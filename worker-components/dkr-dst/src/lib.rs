// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Programmatic API for the DKR new-committee recipient client.
//! Each new-committee member acts as a VSS recipient in ALL of the DKR VSS sessions
//! (one per old-committee member) and polls the DKR session until it completes.

use anyhow::{anyhow, Result};
use serde_json::Value;
use tokio::sync::oneshot;
use vss_common::{normalize_account_addr, parse_ed25519_signing_key_hex, AptosRpc, TxnArg};

const STATE_DONE: u8 = 1;
const STATE_FAIL: u8 = 2;

#[derive(Debug, Clone)]
struct DkrSession {
    new_nodes: Vec<String>,
    vss_sessions: Vec<String>,
    state_code: u8,
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub rpc_url: String,
    pub rpc_api_key: Option<String>,
    pub rpc_gas_key: Option<String>,
    pub ace_contract: String,
    pub dkr_session: String,
    pub account_addr: String,
    pub account_sk_hex: String,
    pub pke_dk_hex: String,
}

async fn fetch_dkr_session(rpc: &AptosRpc, ace: &str, session_addr: &str) -> Result<DkrSession> {
    let data = rpc
        .get_resource_data(session_addr, &format!("{}::dkr::Session", ace))
        .await?;
    parse_dkr_session_data(&data)
}

fn parse_dkr_session_data(data: &Value) -> Result<DkrSession> {
    let new_nodes = data["new_nodes"]
        .as_array()
        .ok_or_else(|| anyhow!("missing new_nodes in DKR session"))?
        .iter()
        .map(|v| normalize_account_addr(v.as_str().unwrap_or("")))
        .collect();

    let vss_sessions = data["vss_sessions"]
        .as_array()
        .ok_or_else(|| anyhow!("missing vss_sessions in DKR session"))?
        .iter()
        .map(|v| normalize_account_addr(v.as_str().unwrap_or("")))
        .collect();

    let state_code: u8 = match &data["state_code"] {
        Value::Number(n) => n.as_u64().unwrap_or(0) as u8,
        Value::String(s) => s.parse().unwrap_or(0),
        _ => return Err(anyhow!("missing or invalid state_code in DKR session")),
    };

    Ok(DkrSession { new_nodes, vss_sessions, state_code })
}

pub async fn run(config: RunConfig, mut shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
    let rpc = AptosRpc::new_with_gas_key(config.rpc_url.clone(), config.rpc_api_key.clone(), config.rpc_gas_key.clone());
    let sk = parse_ed25519_signing_key_hex(&config.account_sk_hex)?;
    let vk = sk.verifying_key();
    let account_addr = normalize_account_addr(&config.account_addr);
    let dkr_session_addr = normalize_account_addr(&config.dkr_session);
    let ace = normalize_account_addr(&config.ace_contract);

    println!(
        "dkr-dst: starting (account={} dkr_session={} ace={})",
        account_addr, dkr_session_addr, ace
    );

    let session = fetch_dkr_session(&rpc, &ace, &dkr_session_addr).await?;

    // Verify this account is in the new committee.
    if !session.new_nodes.iter().any(|n| *n == account_addr) {
        return Err(anyhow!(
            "account {} not found in DKR new_nodes {:?}",
            account_addr,
            session.new_nodes
        ));
    }

    let num_vss = session.vss_sessions.len();
    println!(
        "dkr-dst: joining {} VSS sessions as recipient",
        num_vss
    );

    // Spawn a VSS recipient for every VSS session (one per old-committee member).
    let mut recipient_shutdown_txs: Vec<oneshot::Sender<()>> = Vec::with_capacity(num_vss);
    for (j, vss_addr) in session.vss_sessions.iter().enumerate() {
        let (tx, rx) = oneshot::channel::<()>();
        recipient_shutdown_txs.push(tx);
        let rcfg = vss_recipient::RunConfig {
            rpc_url: config.rpc_url.clone(),
            rpc_api_key: config.rpc_api_key.clone(),
            rpc_gas_key: config.rpc_gas_key.clone(),
            ace_contract: ace.clone(),
            vss_session: vss_addr.clone(),
            pke_dk_hex: config.pke_dk_hex.clone(),
            account_addr: account_addr.clone(),
            account_sk_hex: config.account_sk_hex.clone(),
        };
        tokio::spawn(async move {
            if let Err(e) = vss_recipient::run(rcfg, rx).await {
                eprintln!("dkr-dst: recipient sub-task (vss={}) error: {:#}", j, e);
            }
        });
    }

    // Poll DKR session until DONE, FAIL, or shutdown.
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                println!("dkr-dst: shutdown signal received.");
                for tx in recipient_shutdown_txs {
                    let _ = tx.send(());
                }
                return Ok(());
            }
            _ = interval.tick() => {}
        }

        // Call touch_entry to trigger DKR state finalization when enough VSS sessions complete.
        if let Err(e) = rpc.submit_txn(
            &sk, &vk, &account_addr,
            &format!("{}::dkr::touch_entry", ace), &[],
            &[TxnArg::Address(&dkr_session_addr)],
        ).await {
            eprintln!("dkr-dst: touch_entry error: {:#}", e);
        }

        match fetch_dkr_session(&rpc, &ace, &dkr_session_addr).await {
            Err(e) => eprintln!("dkr-dst: poll error: {:#}", e),
            Ok(s) if s.state_code == STATE_DONE => {
                println!("dkr-dst: DKR session reached DONE.");
                for tx in recipient_shutdown_txs {
                    let _ = tx.send(());
                }
                return Ok(());
            }
            Ok(s) if s.state_code >= STATE_FAIL => {
                for tx in recipient_shutdown_txs {
                    let _ = tx.send(());
                }
                return Err(anyhow!("dkr-dst: DKR session failed (state_code={})", s.state_code));
            }
            Ok(s) => {
                println!("dkr-dst: DKR in progress (state_code={})", s.state_code);
            }
        }
    }
}
