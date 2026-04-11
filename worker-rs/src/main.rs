// ACE Worker — single binary, multiple subcommands
//
//  run              All-in-one (simple Docker): public server + signer in one process.
//  signer           Signer only (Helm, replicas=1): DKG/DKR + /partial_key.
//  server           Public server only (Helm, replicas=N): user-facing + proxies to signer.
//  register-node    One-shot: register this worker's public endpoint on-chain.
//                   Run once after deployment; operator provides the public URL.
use anyhow::Result;
use clap::{Parser, Subcommand};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

mod aptos_rpc;
mod bcs;
mod crypto;
mod dkg;
mod public_server;
mod server; // kept for backward-compat; new code uses public_server + signer
mod signer;
mod store;
mod types;
mod verify;
mod vss;

/// Shared in-memory state for the sync-VSS DKG dealing phase.
pub struct DkgShareAccum {
    pub shares: HashMap<u64, ark_bls12_381::Fr>,
    pub posted_dkg_ids: HashSet<u64>,
}
impl DkgShareAccum {
    pub fn new() -> Self { Self { shares: HashMap::new(), posted_dkg_ids: HashSet::new() } }
}

/// Shared in-memory state for the DKR (resharing) phase.
pub struct ReshareAccum {
    pub sub_shares: HashMap<(u64, u64), Vec<(u64, ark_bls12_381::Fr)>>,
    pub posted_epoch_change_ids: HashSet<u64>,
    pub committed_epoch_change_ids: HashSet<u64>,
    pub active_resharing: Option<(u64, Vec<u64>)>,
}
impl ReshareAccum {
    pub fn new() -> Self {
        Self {
            sub_shares: HashMap::new(),
            posted_epoch_change_ids: HashSet::new(),
            committed_epoch_change_ids: HashSet::new(),
            active_resharing: None,
        }
    }
}

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "worker-rs", about = "ACE Worker")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// All-in-one mode for simple Docker deployments.
    /// Runs the public server on --port and an internal signer on --signer-port
    /// (default: --port + 500).  Both share in-process state; no network hop
    /// for /partial_key in this mode because they are on the same host.
    #[command(name = "run")]
    Run(RunArgs),

    /// Signer-only mode (Helm: Deployment replicas=1).
    /// Holds the private key, runs DKG/DKR polling, exposes /partial_key,
    /// /deal_share, /reshare_share on --port.
    #[command(name = "signer")]
    Signer(SignerArgs),

    /// Public-server-only mode (Helm: Deployment replicas=N).
    /// Verifies permissions and proxies /partial_key to the signer.
    #[command(name = "server")]
    Server(ServerArgs),

    /// Register this worker's public endpoint on-chain.
    /// Run once after deployment when the public URL is known.
    #[command(name = "register-node")]
    RegisterNode(RegisterNodeArgs),
}

// ── Shared key arg helper ─────────────────────────────────────────────────────

fn parse_private_key(hex: &str) -> Result<ed25519_dalek::SigningKey> {
    let raw = hex.trim_start_matches("0x");
    let bytes: [u8; 32] = hex::decode(raw)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("private key must be 32 bytes"))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&bytes))
}

fn normalize_addr(s: &str) -> String {
    if s.starts_with("0x") { s.to_string() } else { format!("0x{}", s) }
}

// ── run subcommand ────────────────────────────────────────────────────────────

#[derive(clap::Args)]
struct RunArgs {
    /// Public port (user-facing HTTP server).
    #[arg(long)]
    port: u16,
    /// Internal signer port (defaults to port + 500).
    #[arg(long)]
    signer_port: Option<u16>,
    #[arg(long, name = "rpc-url")]
    rpc_url: String,
    #[arg(long, name = "ace-contract")]
    ace_contract: String,
    #[arg(long, env = "ACE_WORKER_V2_PRIVATE_KEY")]
    private_key: String,
}

async fn cmd_run(args: RunArgs) -> Result<()> {
    let signer_port = args.signer_port.unwrap_or(args.port + 500);
    let signing_key = parse_private_key(&args.private_key)?;
    let verifying_key = signing_key.verifying_key();
    let my_address = compute_address(&verifying_key);
    let contract_addr = normalize_addr(&args.ace_contract);
    let store_path = format!("worker_shares_{}.json", args.port);

    info!("ACE Worker (run mode)");
    info!("  Address:  0x{}", hex::encode(my_address));
    info!("  Public:   http://localhost:{}", args.port);
    info!("  Signer:   http://localhost:{}", signer_port);
    info!("  Contract: {}", contract_addr);
    info!("  Store:    {}", store_path);

    let rpc = aptos_rpc::AptosRpc::new(args.rpc_url.clone());
    let store = Arc::new(Mutex::new(store::ShareStore::load(&store_path)));
    let accum = Arc::new(Mutex::new(DkgShareAccum::new()));
    let reshare_accum = Arc::new(Mutex::new(ReshareAccum::new()));

    // Initial poll then background poller.
    let _ = dkg::poll(
        &rpc, &signing_key, &verifying_key, &contract_addr, &my_address,
        &store_path, Arc::clone(&store), Arc::clone(&accum), Arc::clone(&reshare_accum),
    ).await;
    spawn_dkg_poller(
        rpc.clone(), signing_key, verifying_key, contract_addr.clone(),
        my_address, store_path, Arc::clone(&store), Arc::clone(&accum), Arc::clone(&reshare_accum),
    );

    let signer_state = signer::SignerState {
        contract_addr: contract_addr.clone(),
        rpc: rpc.clone(),
        my_address,
        store,
        accum,
        reshare_accum,
    };
    let signer_url = format!("http://localhost:{}", signer_port);
    let public_state = public_server::PublicServerState {
        contract_addr,
        rpc,
        signer_url,
        http_client: reqwest::Client::new(),
    };

    tokio::try_join!(
        signer::run(signer_port, signer_state),
        public_server::run(args.port, public_state),
    )?;
    Ok(())
}

// ── signer subcommand ─────────────────────────────────────────────────────────

#[derive(clap::Args)]
struct SignerArgs {
    /// Port for signer HTTP (DKG/DKR + /partial_key).
    #[arg(long)]
    port: u16,
    #[arg(long, name = "rpc-url")]
    rpc_url: String,
    #[arg(long, name = "ace-contract")]
    ace_contract: String,
    #[arg(long, env = "ACE_WORKER_V2_PRIVATE_KEY")]
    private_key: String,
}

async fn cmd_signer(args: SignerArgs) -> Result<()> {
    let signing_key = parse_private_key(&args.private_key)?;
    let verifying_key = signing_key.verifying_key();
    let my_address = compute_address(&verifying_key);
    let contract_addr = normalize_addr(&args.ace_contract);
    let store_path = format!("worker_shares_{}.json", args.port);

    info!("ACE Worker (signer mode)");
    info!("  Address:  0x{}", hex::encode(my_address));
    info!("  Port:     {}", args.port);
    info!("  Contract: {}", contract_addr);
    info!("  Store:    {}", store_path);

    let rpc = aptos_rpc::AptosRpc::new(args.rpc_url);
    let store = Arc::new(Mutex::new(store::ShareStore::load(&store_path)));
    let accum = Arc::new(Mutex::new(DkgShareAccum::new()));
    let reshare_accum = Arc::new(Mutex::new(ReshareAccum::new()));

    let _ = dkg::poll(
        &rpc, &signing_key, &verifying_key, &contract_addr, &my_address,
        &store_path, Arc::clone(&store), Arc::clone(&accum), Arc::clone(&reshare_accum),
    ).await;
    spawn_dkg_poller(
        rpc.clone(), signing_key, verifying_key, contract_addr.clone(),
        my_address, store_path, Arc::clone(&store), Arc::clone(&accum), Arc::clone(&reshare_accum),
    );

    let state = signer::SignerState { contract_addr, rpc, my_address, store, accum, reshare_accum };
    signer::run(args.port, state).await
}

// ── server subcommand ─────────────────────────────────────────────────────────

#[derive(clap::Args)]
struct ServerArgs {
    /// Public port.
    #[arg(long)]
    port: u16,
    /// Base URL of the signer, e.g. "http://signer-service:8080".
    #[arg(long, name = "signer-url")]
    signer_url: String,
    #[arg(long, name = "rpc-url")]
    rpc_url: String,
    #[arg(long, name = "ace-contract")]
    ace_contract: String,
}

async fn cmd_server(args: ServerArgs) -> Result<()> {
    info!("ACE Worker (server mode)");
    info!("  Port:       {}", args.port);
    info!("  Signer URL: {}", args.signer_url);

    let state = public_server::PublicServerState {
        contract_addr: normalize_addr(&args.ace_contract),
        rpc: aptos_rpc::AptosRpc::new(args.rpc_url),
        signer_url: args.signer_url,
        http_client: reqwest::Client::new(),
    };
    public_server::run(args.port, state).await
}

// ── register-node subcommand ──────────────────────────────────────────────────

#[derive(clap::Args)]
struct RegisterNodeArgs {
    /// The public URL this worker is reachable at, e.g. "https://worker.acme.com".
    #[arg(long)]
    endpoint: String,
    #[arg(long, name = "rpc-url")]
    rpc_url: String,
    #[arg(long, name = "ace-contract")]
    ace_contract: String,
    #[arg(long, env = "ACE_WORKER_V2_PRIVATE_KEY")]
    private_key: String,
}

async fn cmd_register_node(args: RegisterNodeArgs) -> Result<()> {
    let signing_key = parse_private_key(&args.private_key)?;
    let verifying_key = signing_key.verifying_key();
    let my_address = compute_address(&verifying_key);
    let my_addr_str = format!("0x{}", hex::encode(my_address));
    let contract_addr = normalize_addr(&args.ace_contract);
    let rpc = aptos_rpc::AptosRpc::new(args.rpc_url);

    info!("Registering node: {} → {}", my_addr_str, args.endpoint);
    rpc.submit_txn(
        &signing_key,
        &verifying_key,
        &my_addr_str,
        &format!("{}::ace_network::register_node", contract_addr),
        &[],
        &[serde_json::json!(args.endpoint)],
    )
    .await?;
    info!("Node registered successfully.");
    Ok(())
}

// ── main ──────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Commands::Run(a) => cmd_run(a).await,
        Commands::Signer(a) => cmd_signer(a).await,
        Commands::Server(a) => cmd_server(a).await,
        Commands::RegisterNode(a) => cmd_register_node(a).await,
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn compute_address(vk: &ed25519_dalek::VerifyingKey) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(vk.as_bytes());
    hasher.update([0x00u8]);
    hasher.finalize().into()
}

fn spawn_dkg_poller(
    rpc: aptos_rpc::AptosRpc,
    signing_key: ed25519_dalek::SigningKey,
    verifying_key: ed25519_dalek::VerifyingKey,
    contract_addr: String,
    my_address: [u8; 32],
    store_path: String,
    store: Arc<Mutex<store::ShareStore>>,
    accum: Arc<Mutex<DkgShareAccum>>,
    reshare_accum: Arc<Mutex<ReshareAccum>>,
) {
    let sk_bytes = signing_key.to_bytes();
    let vk_bytes = verifying_key.to_bytes();
    tokio::spawn(async move {
        let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes).unwrap();
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
        loop {
            interval.tick().await;
            let _ = dkg::poll(
                &rpc, &sk, &vk, &contract_addr, &my_address,
                &store_path, Arc::clone(&store), Arc::clone(&accum), Arc::clone(&reshare_accum),
            ).await;
        }
    });
}
