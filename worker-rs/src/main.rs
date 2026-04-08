// Copyright (c) Aptos Labs
// Licensed under Apache-2.0
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
mod server;
mod store;
mod types;
mod verify;
mod vss;

/// Shared in-memory state for the sync-VSS DKG dealing phase.
pub struct DkgShareAccum {
    /// dkg_id → accumulated Fr scalar (sum of all received shares)
    pub shares: HashMap<u64, ark_bls12_381::Fr>,
    /// dkg_ids for which this worker has already posted a partial-MPK contribution
    pub posted_dkg_ids: HashSet<u64>,
}

impl DkgShareAccum {
    pub fn new() -> Self {
        Self {
            shares: HashMap::new(),
            posted_dkg_ids: HashSet::new(),
        }
    }
}

/// Shared in-memory state for the DKR (resharing) phase.
///
/// Old committee members send sub-shares g_i(j) to new committee members via
/// HTTP POST /reshare_share.  New members accumulate them here, then after the
/// epoch advances compute their new share via Lagrange combination.
pub struct ReshareAccum {
    /// (epoch_change_id, secret_id) → list of (dealer_old_index, sub_share_fr)
    pub sub_shares: HashMap<(u64, u64), Vec<(u64, ark_bls12_381::Fr)>>,
    /// epoch_change_ids for which this worker has already dealt (old-member side)
    pub posted_epoch_change_ids: HashSet<u64>,
    /// epoch_change_ids for which the new share has already been stored
    pub committed_epoch_change_ids: HashSet<u64>,
    /// The epoch_change_id + secret_ids of the currently active resharing,
    /// saved when first detected so it's available after the epoch advances.
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

#[derive(Parser)]
#[command(name = "worker-rs", about = "ACE Worker v2 (Rust)")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    #[command(name = "run-worker-v2")]
    RunWorkerV2(RunWorkerV2Args),
}

#[derive(clap::Args)]
struct RunWorkerV2Args {
    #[arg(long)]
    port: u16,

    #[arg(long, name = "rpc-url")]
    rpc_url: String,

    #[arg(long, name = "ace-contract")]
    ace_contract: String,

    #[arg(long, env = "ACE_WORKER_V2_PRIVATE_KEY")]
    private_key: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt::init();
    let cli = Cli::parse();
    match cli.command {
        Commands::RunWorkerV2(args) => run_worker_v2(args).await,
    }
}

async fn run_worker_v2(args: RunWorkerV2Args) -> Result<()> {
    // Parse private key
    let pk_hex = args.private_key.trim_start_matches("0x");
    let pk_bytes: [u8; 32] = hex::decode(pk_hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("private key must be 32 bytes"))?;
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&pk_bytes);
    let verifying_key = signing_key.verifying_key();
    let my_address = compute_address(&verifying_key);

    let contract_addr = if args.ace_contract.starts_with("0x") {
        args.ace_contract.clone()
    } else {
        format!("0x{}", args.ace_contract)
    };

    let endpoint = format!("http://localhost:{}", args.port);
    let store_path = format!("worker_shares_{}.json", args.port);

    info!("ACE Worker v2 (Rust)");
    info!("  Address:  0x{}", hex::encode(my_address));
    info!("  Endpoint: {}", endpoint);
    info!("  Contract: {}", contract_addr);
    info!("  Store:    {}", store_path);

    let rpc = aptos_rpc::AptosRpc::new(args.rpc_url.clone());
    let store = Arc::new(Mutex::new(store::ShareStore::load(&store_path)));
    let accum = Arc::new(Mutex::new(DkgShareAccum::new()));
    let reshare_accum = Arc::new(Mutex::new(ReshareAccum::new()));

    // Register node
    let _ = dkg::ensure_registered(&rpc, &signing_key, &verifying_key, &contract_addr, &endpoint).await;

    // Initial poll
    let _ = dkg::poll(
        &rpc, &signing_key, &verifying_key, &contract_addr, &my_address,
        &store_path, Arc::clone(&store), Arc::clone(&accum), Arc::clone(&reshare_accum),
    ).await;

    // Background poller
    {
        let rpc2 = rpc.clone();
        let contract_addr2 = contract_addr.clone();
        let store_path2 = store_path.clone();
        let store2 = Arc::clone(&store);
        let accum2 = Arc::clone(&accum);
        let reshare_accum2 = Arc::clone(&reshare_accum);
        let sk_bytes = signing_key.to_bytes();
        let vk_bytes = verifying_key.to_bytes();
        let my_address2 = my_address;
        tokio::spawn(async move {
            let sk = ed25519_dalek::SigningKey::from_bytes(&sk_bytes);
            let vk = ed25519_dalek::VerifyingKey::from_bytes(&vk_bytes).unwrap();
            let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
            loop {
                interval.tick().await;
                let _ = dkg::poll(
                    &rpc2, &sk, &vk, &contract_addr2, &my_address2,
                    &store_path2, Arc::clone(&store2), Arc::clone(&accum2),
                    Arc::clone(&reshare_accum2),
                ).await;
            }
        });
    }

    // HTTP server
    server::run(args.port, contract_addr, args.rpc_url, my_address, store, accum, reshare_accum).await
}

pub fn compute_address(vk: &ed25519_dalek::VerifyingKey) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(vk.as_bytes());
    hasher.update([0x00u8]); // Ed25519 scheme byte
    hasher.finalize().into()
}
