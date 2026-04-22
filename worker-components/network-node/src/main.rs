// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! `network-node` binary — thin CLI over [`network_node::run`].

use clap::{Parser, Subcommand};
use tokio::sync::oneshot;

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
    #[arg(long, default_value = "http://localhost:8080/v1")]
    rpc_url: String,
    #[arg(long)]
    ace_contract: String,
    #[arg(long)]
    account_addr: String,
    /// Ed25519 private key hex (0x prefix optional).
    #[arg(long)]
    account_sk: String,
    /// PKE decryption key hex (0x prefix optional).
    #[arg(long)]
    pke_dk_hex: String,
    /// TCP port for the UserRequestHandler HTTP server (optional).
    #[arg(long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run(args) => {
            let cfg = network_node::RunConfig {
                rpc_url: args.rpc_url,
                ace_contract: args.ace_contract,
                account_addr: args.account_addr,
                account_sk_hex: args.account_sk,
                pke_dk_hex: args.pke_dk_hex,
                port: args.port,
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
