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
    ace_deployment_api: String,
    #[arg(long)]
    ace_deployment_apikey: Option<String>,
    #[arg(long)]
    ace_deployment_addr: String,
    #[arg(long)]
    vss_session: String,
    #[arg(long)]
    pke_dk: String,
    /// Optional explicit 32-byte Fr little-endian secret override, hex encoded.
    #[arg(long)]
    secret_override: Option<String>,
    /// Optional explicit 32-byte Fr little-endian old Pedersen blinding, hex encoded.
    #[arg(long)]
    previous_blinding_override: Option<String>,
    /// Ed25519 private key hex (0x prefix optional).
    /// Falls back to env var `ACE_VSS_DEALER_PRIVATE_KEY` if not provided.
    #[arg(long)]
    account_sk: Option<String>,
    /// Aptos account address. Derived from `account_sk` if omitted.
    #[arg(long)]
    account_addr: Option<String>,
    /// Ed25519 node-to-node messaging private key hex (0x prefix optional).
    #[arg(long)]
    sig_sk: Option<String>,
    /// Persistent VSS store URL, e.g. sqlite:///tmp/vss.db or postgres://...
    #[arg(long)]
    vss_store_url: Option<String>,
    /// Address this process listens on for node-to-node VSS messages.
    #[arg(long)]
    node_msg_listen: Option<String>,
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

            let sk =
                vss_common::parse_ed25519_signing_key_hex(&sk_hex).expect("invalid account_sk hex");
            let vk = sk.verifying_key();

            let account_addr = args
                .account_addr
                .unwrap_or_else(|| vss_common::account_address_hex(&vk));

            let cfg = vss_dealer::RunConfig {
                rpc_url: args.ace_deployment_api,
                rpc_api_key: args.ace_deployment_apikey,
                rpc_gas_key: None,
                ace_contract: args.ace_deployment_addr,
                vss_session: args.vss_session,
                pke_dk_hex: args.pke_dk,
                account_addr,
                account_sk_hex: sk_hex,
                secret_override: args
                    .secret_override
                    .as_deref()
                    .map(|value| parse_fr_override_hex("--secret-override", value))
                    .transpose()
                    .expect("invalid --secret-override"),
                previous_blinding_override: args
                    .previous_blinding_override
                    .as_deref()
                    .map(|value| parse_fr_override_hex("--previous-blinding-override", value))
                    .transpose()
                    .expect("invalid --previous-blinding-override"),
                sig_sk_hex: args.sig_sk,
                vss_store_url: args.vss_store_url,
                node_msg_listen: args.node_msg_listen,
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

fn parse_fr_override_hex(name: &str, value: &str) -> Result<[u8; 32], String> {
    let bytes = hex::decode(value.trim_start_matches("0x"))
        .map_err(|e| format!("{} must be hex: {}", name, e))?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| format!("{} must be exactly 32 bytes, got {}", name, bytes.len()))
}
