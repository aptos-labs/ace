// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Programmatic API for the on-chain DKG worker client.
//! Each worker spawns one VSS dealer (for their own VSS session) and n VSS recipients
//! (for all VSS sessions — they are a share holder in every session, including their own).
//!
//! VSS sessions are created lazily on-chain (one per `dkg::touch`), so dealer/recipient
//! sub-tasks are reconciled each tick as new sessions appear in `vss_sessions`.

use anyhow::{anyhow, Result};
use serde_json::Value;
use std::collections::HashMap;
use tokio::sync::oneshot;
use vss_common::{normalize_account_addr, parse_ed25519_signing_key_hex, AptosRpc, TxnArg};

const STATE_DONE: u8 = 3;
const STATE_FAIL: u8 = 4;

#[derive(Debug, Clone)]
struct DkgSession {
    workers: Vec<String>,
    vss_sessions: Vec<String>,
    state: u8,
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub rpc_url: String,
    pub rpc_api_key: Option<String>,
    pub rpc_gas_key: Option<String>,
    pub ace_contract: String,
    pub dkg_session: String,
    pub account_addr: String,
    pub account_sk_hex: String,
    pub pke_dk_hex: String,
}

async fn fetch_dkg_session(rpc: &AptosRpc, ace: &str, session_addr: &str) -> Result<DkgSession> {
    let data = rpc
        .get_resource_data(session_addr, &format!("{}::dkg::Session", ace))
        .await?;
    parse_dkg_session_data(&data)
}

fn parse_dkg_session_data(data: &Value) -> Result<DkgSession> {
    let workers_arr = data["workers"]
        .as_array()
        .ok_or_else(|| anyhow!("missing workers array in DKG session"))?;
    let workers: Vec<String> = workers_arr
        .iter()
        .map(|v| normalize_account_addr(v.as_str().unwrap_or("")))
        .collect();

    let vss_arr = data["vss_sessions"]
        .as_array()
        .ok_or_else(|| anyhow!("missing vss_sessions array in DKG session"))?;
    let vss_sessions: Vec<String> = vss_arr
        .iter()
        .map(|v| normalize_account_addr(v.as_str().unwrap_or("")))
        .collect();

    let state: u8 = match &data["state"] {
        Value::Number(n) => n.as_u64().unwrap_or(0) as u8,
        Value::String(s) => s.parse().unwrap_or(0),
        _ => return Err(anyhow!("missing or invalid state field in DKG session")),
    };

    Ok(DkgSession { workers, vss_sessions, state })
}

pub async fn run(config: RunConfig, mut shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
    let rpc = AptosRpc::new_with_gas_key(config.rpc_url.clone(), config.rpc_api_key.clone(), config.rpc_gas_key.clone());
    let sk = parse_ed25519_signing_key_hex(&config.account_sk_hex)?;
    let vk = sk.verifying_key();
    let account_addr = normalize_account_addr(&config.account_addr);
    let dkg_session_addr = normalize_account_addr(&config.dkg_session);
    let ace = normalize_account_addr(&config.ace_contract);

    println!(
        "dkg-worker: starting (account={} dkg_session={} ace={})",
        account_addr, dkg_session_addr, ace
    );

    // Fetch once to find my_idx — workers list is fixed for the session lifetime.
    let initial = fetch_dkg_session(&rpc, &ace, &dkg_session_addr).await?;
    let my_idx = initial
        .workers
        .iter()
        .position(|w| *w == account_addr)
        .ok_or_else(|| anyhow!("account {} not found in DKG workers list", account_addr))?;
    let n = initial.workers.len();
    println!("dkg-worker: my_idx={} (n={})", my_idx, n);

    // Dealer is spawned once vss_sessions[my_idx] appears on-chain.
    let mut dealer_shutdown_tx: Option<oneshot::Sender<()>> = None;
    // Recipients keyed by VSS session address; spawned as sessions appear.
    let mut recipient_shutdown_txs: HashMap<String, oneshot::Sender<()>> = HashMap::new();

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                println!("dkg-worker: shutdown signal received, stopping sub-tasks.");
                if let Some(tx) = dealer_shutdown_tx { let _ = tx.send(()); }
                for (_, tx) in recipient_shutdown_txs { let _ = tx.send(()); }
                return Ok(());
            }
            _ = interval.tick() => {}
        }

        // touch advances START_VSSS (one VSS per call) and later finalises the DKG.
        if let Err(e) = rpc.submit_txn(
            &sk, &vk, &account_addr,
            &format!("{}::dkg::touch_entry", ace), &[],
            &[TxnArg::Address(&dkg_session_addr)],
        ).await {
            eprintln!("dkg-worker: touch_entry error: {:#}", e);
        }

        let session = match fetch_dkg_session(&rpc, &ace, &dkg_session_addr).await {
            Ok(s) => s,
            Err(e) => { eprintln!("dkg-worker: poll error: {:#}", e); continue; }
        };

        // Spawn dealer for vss_sessions[my_idx] as soon as it appears.
        if dealer_shutdown_tx.is_none() && session.vss_sessions.len() > my_idx {
            let (tx, rx) = oneshot::channel::<()>();
            dealer_shutdown_tx = Some(tx);
            let dealer_cfg = vss_dealer::RunConfig {
                rpc_url: config.rpc_url.clone(),
                rpc_api_key: config.rpc_api_key.clone(),
                rpc_gas_key: config.rpc_gas_key.clone(),
                ace_contract: ace.clone(),
                vss_session: session.vss_sessions[my_idx].clone(),
                pke_dk_hex: config.pke_dk_hex.clone(),
                account_addr: account_addr.clone(),
                account_sk_hex: config.account_sk_hex.clone(),
                secret_override: None,
            };
            println!("dkg-worker: spawning dealer for vss_sessions[{}]={}", my_idx, session.vss_sessions[my_idx]);
            tokio::spawn(async move {
                if let Err(e) = vss_dealer::run(dealer_cfg, rx).await {
                    eprintln!("dkg-worker: dealer sub-task error: {:#}", e);
                }
            });
        }

        // Reconcile recipients: spawn one per VSS session as they appear on-chain.
        for (j, vss_addr) in session.vss_sessions.iter().enumerate() {
            if recipient_shutdown_txs.contains_key(vss_addr) {
                continue;
            }
            let (tx, rx) = oneshot::channel::<()>();
            recipient_shutdown_txs.insert(vss_addr.clone(), tx);
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
            println!("dkg-worker: spawning recipient for vss_sessions[{}]={}", j, vss_addr);
            tokio::spawn(async move {
                if let Err(e) = vss_recipient::run(rcfg, rx).await {
                    eprintln!("dkg-worker: recipient sub-task (vss_idx={}) error: {:#}", j, e);
                }
            });
        }

        if session.state == STATE_DONE {
            println!("dkg-worker: DKG session reached DONE.");
            if let Some(tx) = dealer_shutdown_tx { let _ = tx.send(()); }
            for (_, tx) in recipient_shutdown_txs { let _ = tx.send(()); }
            return Ok(());
        }
        if session.state >= STATE_FAIL {
            if let Some(tx) = dealer_shutdown_tx { let _ = tx.send(()); }
            for (_, tx) in recipient_shutdown_txs { let _ = tx.send(()); }
            return Err(anyhow!("dkg-worker: DKG session failed (state={})", session.state));
        }
        println!("dkg-worker: DKG in progress (state={}, vss_sessions={})", session.state, session.vss_sessions.len());
    }
}
