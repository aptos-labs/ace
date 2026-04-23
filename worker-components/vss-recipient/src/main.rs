// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! `vss-recipient` binary — thin CLI over [`vss_recipient::run`].

use clap::{Parser, Subcommand};
use tokio::sync::oneshot;

#[derive(Parser)]
#[command(name = "vss-recipient", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Poll until the session completes, submitting ack when in RECIPIENT_ACK state.
    Run(RunArgs),
}

#[derive(Parser)]
struct RunArgs {
    #[arg(long, default_value = "http://localhost:8080/v1")]
    ace_deployment_api: String,
    #[arg(long)]
    ace_deployment_apikey: Option<String>,
    #[arg(long)]
    ace_deployment_addr: String,
    #[arg(long)]
    vss_session: String,
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
            let cfg = vss_recipient::RunConfig {
                rpc_url: args.ace_deployment_api,
                rpc_api_key: args.ace_deployment_apikey,
                rpc_gas_key: None,
                ace_contract: args.ace_deployment_addr,
                vss_session: args.vss_session,
                pke_dk_hex: args.pke_dk,
                account_addr: args.account_addr,
                account_sk_hex: args.account_sk,
            };

            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                let _ = shutdown_tx.send(());
            });

            if let Err(e) = vss_recipient::run(cfg, shutdown_rx).await {
                eprintln!("vss-recipient: fatal: {:#}", e);
                std::process::exit(1);
            }
        }
    }
}
