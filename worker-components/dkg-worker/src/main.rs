// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! `dkg-worker` binary — thin CLI over [`dkg_worker::run`].

use clap::{Parser, Subcommand};
use tokio::sync::oneshot;

#[derive(Parser)]
#[command(name = "dkg-worker", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the DKG worker (dealer + all recipients) until the DKG session completes.
    Run(RunArgs),
}

#[derive(Parser)]
struct RunArgs {
    #[arg(long, default_value = "http://localhost:8080/v1")]
    rpc_url: String,
    #[arg(long)]
    ace_contract: String,
    #[arg(long)]
    dkg_session: String,
    #[arg(long)]
    pke_dk_hex: String,
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
            let cfg = dkg_worker::RunConfig {
                rpc_url: args.rpc_url,
                ace_contract: args.ace_contract,
                dkg_session: args.dkg_session,
                pke_dk_hex: args.pke_dk_hex,
                account_addr: args.account_addr,
                account_sk_hex: args.account_sk,
            };

            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                let _ = shutdown_tx.send(());
            });

            if let Err(e) = dkg_worker::run(cfg, shutdown_rx).await {
                eprintln!("dkg-worker: fatal: {:#}", e);
                std::process::exit(1);
            }
        }
    }
}
