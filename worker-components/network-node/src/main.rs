// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! `network-node` binary — thin CLI over [`network_node::run`].
//!
//! Modes:
//! * `monolith` (default): one process maintains secrets and serves user
//!   requests. Same flags as before.
//! * `maintainer`: secret maintenance only. Serves `GET /secrets` on
//!   `--secrets-port`. Skip chain-RPC flags — they are not needed.
//! * `handler`: user request handling only. Pulls from a peer maintainer
//!   given by `--s0-url`. Skip on-chain account / `pke-dk` / `ace-deployment-*`
//!   flags — they are not needed.

use clap::{Parser, Subcommand, ValueEnum};
use std::time::Duration;
use tokio::sync::oneshot;
use vss_common::AptosRpc;

#[derive(Parser)]
#[command(name = "network-node", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the network-node supervisor for one committee member.
    Run(RunArgs),
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum CliMode {
    /// Default — secrets + user requests in one process.
    Monolith,
    /// Secrets only — serves `GET /secrets` for handler peers to pull from.
    Maintainer,
    /// User requests only — pulls secrets from a peer maintainer.
    Handler,
}

#[derive(Parser)]
struct RunArgs {
    /// Deployment mode.
    #[arg(long, value_enum, default_value = "monolith")]
    mode: CliMode,

    // ── Maintainer / monolith params (ignored in handler mode) ───────────────
    /// Aptos fullnode URL for the ACE deployment (DKG/DKR operations).
    #[arg(long, default_value = "http://localhost:8080/v1")]
    ace_deployment_api: String,
    /// Optional API key for the ACE deployment Aptos fullnode.
    #[arg(long)]
    ace_deployment_apikey: Option<String>,
    /// Gas station API key for fee-sponsored transactions.
    #[arg(long)]
    ace_deployment_gaskey: Option<String>,
    /// ACE contract address on Aptos.
    #[arg(long, default_value = "")]
    ace_deployment_addr: String,
    #[arg(long, default_value = "")]
    account_addr: String,
    /// Ed25519 private key hex (0x prefix optional).
    #[arg(long, default_value = "")]
    account_sk: String,
    /// PKE decryption key hex (0x prefix optional).
    #[arg(long, default_value = "")]
    pke_dk: String,

    // ── User-request server params (monolith + handler) ──────────────────────
    /// TCP port for the user-request HTTP server (`POST /`). Required in
    /// monolith + handler modes; ignored in maintainer mode.
    #[arg(long)]
    port: Option<u16>,
    /// Maximum concurrent in-flight HTTP requests.
    #[arg(long)]
    max_concurrent: Option<usize>,

    // ── Maintainer-only ──────────────────────────────────────────────────────
    /// TCP port for the secrets HTTP server (`GET /secrets`). Required in
    /// maintainer mode.
    #[arg(long)]
    secrets_port: Option<u16>,
    /// Optional bearer token guarding `/secrets`.
    #[arg(long)]
    secrets_auth_token: Option<String>,

    // ── Handler-only ─────────────────────────────────────────────────────────
    /// URL of the peer maintainer's `/secrets` endpoint. Required in handler mode.
    #[arg(long)]
    s0_url: Option<String>,
    /// Optional bearer token presented to the peer maintainer.
    #[arg(long)]
    s0_auth_token: Option<String>,

    // ── Per-chain Aptos RPC endpoints (used by user-request verification) ────
    #[arg(long, default_value = "https://api.mainnet.aptoslabs.com/v1")]
    aptos_mainnet_api: String,
    #[arg(long)]
    aptos_mainnet_apikey: Option<String>,
    #[arg(long, default_value = "https://api.testnet.aptoslabs.com/v1")]
    aptos_testnet_api: String,
    #[arg(long)]
    aptos_testnet_apikey: Option<String>,
    #[arg(long, default_value = "http://127.0.0.1:8080/v1")]
    aptos_localnet_api: String,
    #[arg(long)]
    aptos_localnet_apikey: Option<String>,
    #[arg(long, default_value = "https://api.mainnet-beta.solana.com")]
    solana_mainnet_beta_rpc: String,
    #[arg(long, default_value = "https://api.testnet.solana.com")]
    solana_testnet_rpc: String,
    #[arg(long, default_value = "https://api.devnet.solana.com")]
    solana_devnet_rpc: String,
}

fn require<T>(label: &str, v: Option<T>) -> T {
    v.unwrap_or_else(|| {
        eprintln!("network-node: missing required flag --{}", label);
        std::process::exit(2);
    })
}

fn require_str(label: &str, v: &str) -> String {
    if v.is_empty() {
        eprintln!("network-node: missing required flag --{}", label);
        std::process::exit(2);
    }
    v.to_string()
}

fn build_chain_rpc(args: &RunArgs) -> network_node::ChainRpcConfig {
    network_node::ChainRpcConfig {
        aptos_mainnet: AptosRpc::new_with_key(
            args.aptos_mainnet_api.clone(),
            args.aptos_mainnet_apikey.clone(),
        ),
        aptos_testnet: AptosRpc::new_with_key(
            args.aptos_testnet_api.clone(),
            args.aptos_testnet_apikey.clone(),
        ),
        aptos_localnet: AptosRpc::new_with_key(
            args.aptos_localnet_api.clone(),
            args.aptos_localnet_apikey.clone(),
        ),
        solana_mainnet_beta: args.solana_mainnet_beta_rpc.clone(),
        solana_testnet: args.solana_testnet_rpc.clone(),
        solana_devnet: args.solana_devnet_rpc.clone(),
        solana_client: reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("failed to build Solana HTTP client"),
    }
}

fn build_maintainer_config(args: &RunArgs) -> network_node::MaintainerConfig {
    network_node::MaintainerConfig {
        ace_deployment_api: args.ace_deployment_api.clone(),
        ace_deployment_apikey: args.ace_deployment_apikey.clone(),
        ace_deployment_gaskey: args.ace_deployment_gaskey.clone(),
        ace_deployment_addr: require_str("ace-deployment-addr", &args.ace_deployment_addr),
        account_addr: require_str("account-addr", &args.account_addr),
        account_sk_hex: require_str("account-sk", &args.account_sk),
        pke_dk: require_str("pke-dk", &args.pke_dk),
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run(args) => {
            let mode = match args.mode {
                CliMode::Monolith => network_node::Mode::Monolith {
                    maintainer: build_maintainer_config(&args),
                    // No --port → run chain-touching only (matches pre-split behavior).
                    handler: args.port.map(|p| network_node::HandlerLocalConfig {
                        port: p,
                        chain_rpc: build_chain_rpc(&args),
                        max_concurrent: args.max_concurrent,
                    }),
                },
                CliMode::Maintainer => network_node::Mode::Maintainer {
                    maintainer: build_maintainer_config(&args),
                    secrets_port: require("secrets-port", args.secrets_port),
                    secrets_auth_token: args.secrets_auth_token.clone(),
                },
                CliMode::Handler => network_node::Mode::Handler {
                    s0_url: require("s0-url", args.s0_url.clone()),
                    s0_auth_token: args.s0_auth_token.clone(),
                    port: require("port", args.port),
                    chain_rpc: build_chain_rpc(&args),
                    max_concurrent: args.max_concurrent,
                },
            };

            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                let _ = shutdown_tx.send(());
            });

            if let Err(e) = network_node::run(mode, shutdown_rx).await {
                network_node::wlog!("network-node: fatal: {:#}", e);
                std::process::exit(1);
            }
        }
    }
}
