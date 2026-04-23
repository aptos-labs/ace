// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! `network-node` binary — thin CLI over [`network_node::run`].

use clap::{Parser, Subcommand};
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

#[derive(Parser)]
struct RunArgs {
    /// Aptos fullnode URL for the ACE deployment (DKG/DKR operations).
    #[arg(long, default_value = "http://localhost:8080/v1")]
    ace_deployment_api: String,
    /// Optional API key for the ACE deployment Aptos fullnode.
    #[arg(long)]
    ace_deployment_apikey: Option<String>,
    /// Gas station API key for fee-sponsored transactions on the ACE deployment chain.
    #[arg(long)]
    ace_deployment_gaskey: Option<String>,
    /// ACE contract address on Aptos.
    #[arg(long)]
    ace_deployment_addr: String,
    #[arg(long)]
    account_addr: String,
    /// Ed25519 private key hex (0x prefix optional).
    #[arg(long)]
    account_sk: String,
    /// PKE decryption key hex (0x prefix optional).
    #[arg(long)]
    pke_dk: String,
    /// TCP port for the UserRequestHandler HTTP server (optional).
    #[arg(long)]
    port: Option<u16>,
    /// Maximum concurrent in-flight HTTP requests (optional).
    /// Defaults to a value derived from the cgroup memory limit.
    /// Use this to override when running outside a container or to tune manually.
    #[arg(long)]
    max_concurrent: Option<usize>,
    // ── Per-chain Aptos RPC endpoints (for proof-of-permission verification) ──
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
    // ── Per-chain Solana RPC endpoints ───────────────────────────────────────
    #[arg(long, default_value = "https://api.mainnet-beta.solana.com")]
    solana_mainnet_beta_rpc: String,
    #[arg(long, default_value = "https://api.testnet.solana.com")]
    solana_testnet_rpc: String,
    #[arg(long, default_value = "https://api.devnet.solana.com")]
    solana_devnet_rpc: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run(args) => {
            let chain_rpc = network_node::ChainRpcConfig {
                aptos_mainnet: AptosRpc::new_with_key(args.aptos_mainnet_api, args.aptos_mainnet_apikey),
                aptos_testnet: AptosRpc::new_with_key(args.aptos_testnet_api, args.aptos_testnet_apikey),
                aptos_localnet: AptosRpc::new_with_key(args.aptos_localnet_api, args.aptos_localnet_apikey),
                solana_mainnet_beta: args.solana_mainnet_beta_rpc,
                solana_testnet: args.solana_testnet_rpc,
                solana_devnet: args.solana_devnet_rpc,
                solana_client: reqwest::Client::builder()
                    .timeout(Duration::from_secs(10))
                    .build()
                    .expect("failed to build Solana HTTP client"),
            };
            let cfg = network_node::RunConfig {
                ace_deployment_api: args.ace_deployment_api,
                ace_deployment_apikey: args.ace_deployment_apikey,
                ace_deployment_gaskey: args.ace_deployment_gaskey,
                ace_deployment_addr: args.ace_deployment_addr,
                account_addr: args.account_addr,
                account_sk_hex: args.account_sk,
                pke_dk: args.pke_dk,
                port: args.port,
                chain_rpc,
                max_concurrent: args.max_concurrent,
            };


            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                let _ = shutdown_tx.send(());
            });

            if let Err(e) = network_node::run(cfg, shutdown_rx).await {
                eprintln!("network-node: fatal: {:#}", e);
                std::process::exit(1);
            }
        }
    }
}
