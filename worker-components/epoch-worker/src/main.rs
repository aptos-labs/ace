// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Standalone driver for one on-chain `ace::epoch::Session`.
//! Production callers provide an in-process share sink before readiness is acknowledged.

use clap::{Parser, Subcommand};
use tokio::sync::oneshot;

#[derive(Parser)]
#[command(name = "epoch-worker", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Follow one epoch session and drive its inbound/outbound transition role.
    Run(RunArgs),
}

#[derive(Parser)]
struct RunArgs {
    #[arg(long, default_value = "http://localhost:8080/v1")]
    ace_deployment_api: String,
    #[arg(long)]
    ace_deployment_apikey: Option<String>,
    #[arg(long)]
    ace_deployment_gaskey: Option<String>,
    #[arg(long)]
    ace_deployment_addr: String,
    /// Address of `ace::epoch::Session`, not the epoch-change session.
    #[arg(long)]
    epoch_session: String,
    /// Optional assertion against the epoch number stored on chain.
    #[arg(long)]
    expected_epoch: Option<u64>,
    #[arg(long)]
    account_addr: String,
    /// Ed25519 private key hex (0x prefix optional).
    #[arg(long)]
    account_sk: String,
    /// PKE decryption key hex (0x prefix optional).
    #[arg(long)]
    pke_dk: String,
}

#[tokio::main]
async fn main() {
    let Cli { command } = Cli::parse();
    match command {
        Commands::Run(args) => {
            let config = epoch_worker::RunConfig {
                rpc_url: args.ace_deployment_api,
                rpc_api_key: args.ace_deployment_apikey,
                rpc_gas_key: args.ace_deployment_gaskey,
                ace_contract: args.ace_deployment_addr,
                epoch_session: args.epoch_session,
                expected_epoch: args.expected_epoch,
                account_addr: args.account_addr,
                account_sk_hex: args.account_sk,
                pke_dk_hex: args.pke_dk,
                share_sink: None,
            };

            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                let _ = shutdown_tx.send(());
            });

            if let Err(error) = epoch_worker::run(config, shutdown_rx).await {
                eprintln!("epoch-worker: fatal: {error:#}");
                std::process::exit(1);
            }
        }
    }
}
