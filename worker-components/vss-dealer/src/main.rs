// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! `vss-dealer` binary — thin CLI over [`vss_dealer::run`].

use clap::{Parser, Subcommand};
use tokio::sync::oneshot;

#[derive(Parser)]
#[command(name = "vss-dealer", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run the two-phase dealer until the on-chain session reaches SUCCESS.
    Run(RunArgs),
}

#[derive(Parser)]
struct RunArgs {
    #[arg(long, default_value = "http://localhost:8080/v1")]
    rpc_url: String,
    #[arg(long)]
    ace_contract: String,
    #[arg(long)]
    vss_session: String,
    #[arg(long)]
    pke_dk_hex: String,
    /// Ed25519 private key hex (0x prefix optional).
    /// Falls back to env var `ACE_VSS_DEALER_PRIVATE_KEY` if not provided.
    #[arg(long)]
    account_sk: Option<String>,
    /// Aptos account address. Derived from `account_sk` if omitted.
    #[arg(long)]
    account_addr: Option<String>,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run(args) => {
            let sk_hex = args
                .account_sk
                .or_else(|| std::env::var("ACE_VSS_DEALER_PRIVATE_KEY").ok())
                .expect("--account-sk or ACE_VSS_DEALER_PRIVATE_KEY env var required");

            let sk = vss_common::parse_ed25519_signing_key_hex(&sk_hex)
                .expect("invalid account_sk hex");
            let vk = sk.verifying_key();

            let account_addr = args
                .account_addr
                .unwrap_or_else(|| vss_common::account_address_hex(&vk));

            let cfg = vss_dealer::RunConfig {
                rpc_url: args.rpc_url,
                ace_contract: args.ace_contract,
                vss_session: args.vss_session,
                pke_dk_hex: args.pke_dk_hex,
                account_addr,
                account_sk_hex: sk_hex,
                secret_override: None,
            };

            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                let _ = shutdown_tx.send(());
            });

            if let Err(e) = vss_dealer::run(cfg, shutdown_rx).await {
                eprintln!("vss-dealer: fatal: {:#}", e);
                std::process::exit(1);
            }
        }
    }
}
