// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Programmatic API for the on-chain DKG worker client.
//! Each worker spawns one VSS dealer (for their own VSS session) and n VSS recipients
//! (for all VSS sessions — they are a share holder in every session, including their own).

use anyhow::{anyhow, Result};
use serde_json::Value;
use tokio::sync::oneshot;
use vss_common::{normalize_account_addr, parse_ed25519_signing_key_hex, AptosRpc, TxnArg};

fn shutdown_all(dealer: oneshot::Sender<()>, recipients: Vec<oneshot::Sender<()>>) {
    let _ = dealer.send(());
    for tx in recipients {
        let _ = tx.send(());
    }
}

const STATE_DONE: u8 = 1;

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

    // Fetch DKG session once to learn workers list and VSS session addresses.
    let session = fetch_dkg_session(&rpc, &ace, &dkg_session_addr).await?;
    let n = session.workers.len();

    // Find this worker's index in the committee.
    let my_idx = session
        .workers
        .iter()
        .position(|w| *w == account_addr)
        .ok_or_else(|| {
            anyhow!(
                "account {} not found in DKG workers list {:?}",
                account_addr,
                session.workers
            )
        })?;

    println!(
        "dkg-worker: my_idx={} (n={}), dealing vss_sessions[{}]={}",
        my_idx, n, my_idx, session.vss_sessions[my_idx]
    );

    // --- Spawn VSS dealer for my own VSS session ---
    let (dealer_shutdown_tx, dealer_shutdown_rx) = oneshot::channel::<()>();
    let dealer_cfg = vss_dealer::RunConfig {
        rpc_url: config.rpc_url.clone(),
        rpc_api_key: config.rpc_api_key.clone(),
        rpc_gas_key: config.rpc_gas_key.clone(),
        ace_contract: ace.clone(),
        vss_session: session.vss_sessions[my_idx].clone(),
        pke_dk_hex: config.pke_dk_hex.clone(),
        account_addr: account_addr.clone(),
        account_sk_hex: config.account_sk_hex.clone(),
        secret_override: None, // DKG dealers pick their own random secret from the DK.
    };
    tokio::spawn(async move {
        if let Err(e) = vss_dealer::run(dealer_cfg, dealer_shutdown_rx).await {
            eprintln!("dkg-worker: dealer sub-task error: {:#}", e);
        }
    });

    // --- Spawn VSS recipient for ALL VSS sessions ---
    // This worker is a share holder in every session (including their own as dealer).
    // They must ack in all sessions to avoid their share being publicly revealed in DC1.
    let mut recipient_shutdown_txs: Vec<oneshot::Sender<()>> = Vec::with_capacity(n);
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
                eprintln!("dkg-worker: recipient sub-task (vss={}) error: {:#}", j, e);
            }
        });
    }

    // --- Poll DKG session until DONE, FAIL, or shutdown ---
    let mut interval =
        tokio::time::interval(tokio::time::Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                println!("dkg-worker: shutdown signal received, stopping sub-tasks.");
                shutdown_all(dealer_shutdown_tx, recipient_shutdown_txs);
                return Ok(());
            }
            _ = interval.tick() => {}
        }

        // Call touch_entry to trigger DKG state finalization when enough VSS sessions complete.
        if let Err(e) = rpc.submit_txn(
            &sk, &vk, &account_addr,
            &format!("{}::dkg::touch_entry", ace), &[],
            &[TxnArg::Address(&dkg_session_addr)],
        ).await {
            eprintln!("dkg-worker: touch_entry error: {:#}", e);
        }

        match fetch_dkg_session(&rpc, &ace, &dkg_session_addr).await {
            Err(e) => eprintln!("dkg-worker: poll error: {:#}", e),
            Ok(s) if s.state == STATE_DONE => {
                println!("dkg-worker: DKG session reached DONE.");
                shutdown_all(dealer_shutdown_tx, recipient_shutdown_txs);
                return Ok(());
            }
            Ok(s) if s.state > STATE_DONE => {
                shutdown_all(dealer_shutdown_tx, recipient_shutdown_txs);
                return Err(anyhow!("dkg-worker: DKG session failed (state={})", s.state));
            }
            Ok(s) => {
                println!("dkg-worker: DKG in progress (state={})", s.state);
            }
        }
    }
}
