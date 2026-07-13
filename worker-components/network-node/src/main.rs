// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! `network-node` binary — thin CLI over [`network_node::run`].
//!
//! Modes:
//! * `monolith` (default): one process maintains secrets and serves user
//!   requests. Same flags as before.
//! * `maintainer`: secret maintenance only. No user-request HTTP server.
//! * `handler`: user request handling only. Reads shares from `--vss-store-url`
//!   in a background sync loop.

use clap::{Parser, Subcommand, ValueEnum};
use serde::Deserialize;
use std::env;
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
    /// Secrets only — maintains VSS/DKG/DKR state and writes the shared VSS DB.
    Maintainer,
    /// User requests only — syncs shares from the shared VSS DB.
    Handler,
}

#[derive(Parser)]
struct RunArgs {
    /// Deployment mode.
    #[arg(long, value_enum, default_value = "monolith")]
    mode: CliMode,

    // ── Maintainer / monolith params ─────────────────────────────────────────
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
    /// Ed25519 node-to-node messaging signing key hex (0x prefix optional).
    #[arg(long, default_value = "")]
    sig_sk: String,
    /// Persistent VSS store URL used by embedded VSS clients.
    #[arg(long, default_value = "")]
    vss_store_url: String,
    /// Local listen address for embedded node-to-node VSS share gateway.
    #[arg(long, default_value = "")]
    node_msg_listen: String,

    // ── HTTP-server port ─────────────────────────────────────────────────────
    /// TCP port. In monolith and handler modes serves `POST /` (user requests);
    /// Optional in monolith mode (omitting it runs chain-touching only, useful
    /// for DKG-only test setups).
    #[arg(long)]
    port: Option<u16>,
    /// Maximum concurrent in-flight HTTP requests.
    #[arg(long)]
    max_concurrent: Option<usize>,

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
    #[arg(long)]
    aptos_shelby_private_beta_api: Option<String>,
    #[arg(long)]
    aptos_shelby_private_beta_apikey: Option<String>,
}

#[derive(Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct EnvConfig {
    account_sk: Option<String>,
    pke_dk: Option<String>,
    sig_sk: Option<String>,
    vss_store_url: Option<String>,
    node_msg_listen: Option<String>,
    deployment_api_key: Option<String>,
    deployment_gas_key: Option<String>,
    aptos_mainnet_api_key: Option<String>,
    aptos_testnet_api_key: Option<String>,
    aptos_localnet_api_key: Option<String>,
    aptos_shelby_private_beta_api_key: Option<String>,
}

fn env_nonempty(name: &str) -> Option<String> {
    env::var(name).ok().filter(|v| !v.is_empty())
}

fn config_from_env() -> EnvConfig {
    match env_nonempty("ACE_CONFIG_JSON") {
        Some(raw) => serde_json::from_str(&raw).unwrap_or_else(|e| {
            eprintln!("network-node: invalid ACE_CONFIG_JSON: {}", e);
            std::process::exit(2);
        }),
        None => EnvConfig::default(),
    }
}

fn option_or_env_or_config(
    v: Option<String>,
    env_name: &str,
    config_value: Option<String>,
) -> Option<String> {
    v.or_else(|| env_nonempty(env_name)).or(config_value)
}

fn string_or_env_or_config(v: String, env_name: &str, config_value: Option<String>) -> String {
    if v.is_empty() {
        env_nonempty(env_name).or(config_value).unwrap_or_default()
    } else {
        v
    }
}

impl RunArgs {
    fn apply_env_fallbacks(mut self) -> Self {
        let cfg = config_from_env();
        self.ace_deployment_apikey = option_or_env_or_config(
            self.ace_deployment_apikey,
            "ACE_DEPLOYMENT_APIKEY",
            cfg.deployment_api_key.clone(),
        );
        self.ace_deployment_gaskey = option_or_env_or_config(
            self.ace_deployment_gaskey,
            "ACE_DEPLOYMENT_GASKEY",
            cfg.deployment_gas_key.clone(),
        );
        self.account_sk =
            string_or_env_or_config(self.account_sk, "ACE_ACCOUNT_SK", cfg.account_sk.clone());
        self.pke_dk = string_or_env_or_config(self.pke_dk, "ACE_PKE_DK", cfg.pke_dk.clone());
        self.sig_sk = string_or_env_or_config(self.sig_sk, "ACE_SIG_SK", cfg.sig_sk.clone());
        self.vss_store_url = string_or_env_or_config(
            self.vss_store_url,
            "ACE_VSS_STORE_URL",
            cfg.vss_store_url.clone(),
        );
        self.node_msg_listen = string_or_env_or_config(
            self.node_msg_listen,
            "ACE_NODE_MSG_LISTEN",
            cfg.node_msg_listen.clone(),
        );
        self.aptos_mainnet_apikey = option_or_env_or_config(
            self.aptos_mainnet_apikey,
            "ACE_APTOS_MAINNET_APIKEY",
            cfg.aptos_mainnet_api_key.clone(),
        );
        self.aptos_testnet_apikey = option_or_env_or_config(
            self.aptos_testnet_apikey,
            "ACE_APTOS_TESTNET_APIKEY",
            cfg.aptos_testnet_api_key.clone(),
        );
        self.aptos_localnet_apikey = option_or_env_or_config(
            self.aptos_localnet_apikey,
            "ACE_APTOS_LOCALNET_APIKEY",
            cfg.aptos_localnet_api_key.clone(),
        );
        self.aptos_shelby_private_beta_apikey = option_or_env_or_config(
            self.aptos_shelby_private_beta_apikey,
            "ACE_APTOS_SHELBY_PRIVATE_BETA_APIKEY",
            cfg.aptos_shelby_private_beta_api_key.clone(),
        );
        self
    }
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
        aptos_shelby_private_beta: args.aptos_shelby_private_beta_api.as_ref().map(|api| {
            AptosRpc::new_with_key(api.clone(), args.aptos_shelby_private_beta_apikey.clone())
        }),
    }
}

fn runtime_mode(mode: CliMode) -> network_node::RuntimeMode {
    match mode {
        CliMode::Monolith => network_node::RuntimeMode::Monolith,
        CliMode::Maintainer => network_node::RuntimeMode::Maintainer,
        CliMode::Handler => network_node::RuntimeMode::Handler,
    }
}

fn build_run_config(args: &RunArgs) -> network_node::RunConfig {
    network_node::RunConfig {
        mode: runtime_mode(args.mode),
        ace_deployment_api: args.ace_deployment_api.clone(),
        ace_deployment_apikey: args.ace_deployment_apikey.clone(),
        ace_deployment_gaskey: args.ace_deployment_gaskey.clone(),
        ace_deployment_addr: args.ace_deployment_addr.clone(),
        account_addr: args.account_addr.clone(),
        account_sk_hex: args.account_sk.clone(),
        pke_dk: args.pke_dk.clone(),
        sig_sk_hex: args.sig_sk.clone(),
        vss_store_url: args.vss_store_url.clone(),
        node_msg_listen: args.node_msg_listen.clone(),
        port: args.port,
        chain_rpc: if matches!(args.mode, CliMode::Maintainer) {
            None
        } else {
            Some(build_chain_rpc(args))
        },
        max_concurrent: args.max_concurrent,
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    match cli.command {
        Commands::Run(args) => {
            let args = args.apply_env_fallbacks();
            let config = build_run_config(&args);

            let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
            tokio::spawn(async move {
                let _ = tokio::signal::ctrl_c().await;
                let _ = shutdown_tx.send(());
            });

            if let Err(e) = network_node::run(config, shutdown_rx).await {
                network_node::wlog!("network-node: fatal: {:#}", e);
                std::process::exit(1);
            }
        }
    }
}
