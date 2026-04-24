// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! `epoch-change-nxt` binary — thin CLI over [`epoch_change_nxt::run`].

use clap::{Parser, Subcommand};
use tokio::sync::oneshot;

#[derive(Parser)]
#[command(name = "epoch-change-nxt", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the next-committee epoch-change client for one `epoch_change::Session` until it reaches `STATE__DONE`.
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
    /// Sticky object address of `ace::epoch_change::Session`.
    #[arg(long)]
    epoch_change_session: String,
    #[arg(long)]
    pke_dk: String,
    #[arg(long)]
    account_addr: String,
    /// Ed25519 private key hex (0x prefix optional).
    #[arg(long)]
    account_sk: String,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run(args) => {
            let cfg = epoch_change_nxt::RunConfig {
                rpc_url: args.ace_deployment_api,
                rpc_api_key: args.ace_deployment_apikey,
                rpc_gas_key: args.ace_deployment_gaskey,
                ace_contract: args.ace_deployment_addr,
                epoch_change_session: args.epoch_change_session,
                pke_dk_hex: args.pke_dk,
                account_addr: args.account_addr,
                account_sk_hex: args.account_sk,
            };

            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                let _ = shutdown_tx.send(());
            });

            if let Err(e) = epoch_change_nxt::run(cfg, shutdown_rx).await {
                eprintln!("epoch-change-nxt: fatal: {:#}", e);
                std::process::exit(1);
            }
        }
    }
}
