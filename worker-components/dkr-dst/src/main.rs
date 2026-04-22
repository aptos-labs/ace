// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! `dkr-dst` binary — thin CLI over [`dkr_dst::run`].

use clap::{Parser, Subcommand};
use tokio::sync::oneshot;

#[derive(Parser)]
#[command(name = "dkr-dst", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the DKR new-committee recipient until the DKR session completes.
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
    dkr_session: String,
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
            let cfg = dkr_dst::RunConfig {
                rpc_url: args.ace_deployment_api,
                rpc_api_key: args.ace_deployment_apikey,
                ace_contract: args.ace_deployment_addr,
                dkr_session: args.dkr_session,
                pke_dk_hex: args.pke_dk,
                account_addr: args.account_addr,
                account_sk_hex: args.account_sk,
            };

            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                let _ = shutdown_tx.send(());
            });

            if let Err(e) = dkr_dst::run(cfg, shutdown_rx).await {
                eprintln!("dkr-dst: fatal: {:#}", e);
                std::process::exit(1);
            }
        }
    }
}
