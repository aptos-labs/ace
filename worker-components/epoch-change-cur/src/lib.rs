// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Programmatic API for the epoch-change **current committee** side of a single
//! on-chain `ace::epoch_change::Session`, identified by `epoch_change_session`.
//!
//! 1. Submits `epoch_change::touch(session_addr)` on each tick. This process only reads
//!    `ace::epoch_change::Session` for that address — not `network::State` (orchestrators
//!    decide when to start or stop this client; see `RunConfig::epoch_change_session`).
//! 2. Drives the on-chain state machine (DKR fan-out, then `AWAIT` → `DONE`).
//! 3. If the operator is in the session's `cur_nodes`, starts one [`dkr_src::RunConfig`] per
//!    `dkr` in `dkrs` and reconciles a local map.
//!
//! When the session reaches `STATE__DONE`, this client exits successfully.
//! A separate `network::touch` (e.g. from `network-node`) is still required to
//! apply `epoch_change::results` to global `State`.

use anyhow::{anyhow, Result};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::sync::oneshot;
use vss_common::{normalize_account_addr, parse_ed25519_signing_key_hex, AptosRpc, TxnArg};

/// Must match `ace::epoch_change::Session.state_code` when the session is finished.
const STATE_DONE: u8 = 3;

#[derive(Debug, Clone)]
struct EpochChangeSession {
    cur_nodes: Vec<String>,
    dkrs: Vec<String>,
    state_code: u8,
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub rpc_url: String,
    pub rpc_api_key: Option<String>,
    pub rpc_gas_key: Option<String>,
    pub ace_contract: String,
    /// Sticky object address of `ace::epoch_change::Session`.
    pub epoch_change_session: String,
    pub account_addr: String,
    pub account_sk_hex: String,
    pub pke_dk_hex: String,
}

async fn fetch_epoch_change_session(
    rpc: &AptosRpc,
    ace: &str,
    session_addr: &str,
) -> Result<EpochChangeSession> {
    let data = rpc
        .get_resource_data(session_addr, &format!("{}::epoch_change::Session", ace))
        .await?;
    parse_session(&data)
}

fn parse_session(data: &Value) -> Result<EpochChangeSession> {
    let cur_nodes: Vec<String> = data["cur_nodes"]
        .as_array()
        .ok_or_else(|| anyhow!("missing cur_nodes in epoch_change::Session"))?
        .iter()
        .map(|v| normalize_account_addr(v.as_str().unwrap_or("")))
        .collect();

    let dkrs: Vec<String> = data["dkrs"]
        .as_array()
        .ok_or_else(|| anyhow!("missing dkrs in epoch_change::Session"))?
        .iter()
        .map(|v| normalize_account_addr(v.as_str().unwrap_or("")))
        .collect();

    let state_code: u8 = match &data["state_code"] {
        Value::Number(n) => n.as_u64().unwrap_or(0) as u8,
        Value::String(s) => s.parse().unwrap_or(0),
        _ => return Err(anyhow!("missing or invalid state_code in epoch_change::Session")),
    };

    Ok(EpochChangeSession {
        cur_nodes,
        dkrs,
        state_code,
    })
}

fn stop_dkr_tasks(tasks: &mut HashMap<String, oneshot::Sender<()>>) {
    for (_, tx) in tasks.drain() {
        let _ = tx.send(());
    }
}

/// Run the epoch-change cur protocol until the session is `STATE__DONE` or shutdown.
pub async fn run(config: RunConfig, mut shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
    let rpc = AptosRpc::new_with_gas_key(
        config.rpc_url.clone(),
        config.rpc_api_key.clone(),
        config.rpc_gas_key.clone(),
    );
    let sk = parse_ed25519_signing_key_hex(&config.account_sk_hex)?;
    let vk = sk.verifying_key();
    let account_addr = normalize_account_addr(&config.account_addr);
    let session_addr = normalize_account_addr(&config.epoch_change_session);
    let ace = normalize_account_addr(&config.ace_contract);

    println!(
        "epoch-change-cur: starting (account={} epoch_change_session={} ace={})",
        account_addr, session_addr, ace
    );

    // Verify session exists before the main loop.
    let initial = fetch_epoch_change_session(&rpc, &ace, &session_addr).await?;
    if initial.state_code == STATE_DONE {
        println!("epoch-change-cur: session already STATE__DONE; nothing to do.");
        return Ok(());
    }

    let mut dkr_src_tasks: HashMap<String, oneshot::Sender<()>> = HashMap::new();
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                println!("epoch-change-cur: shutdown signal received.");
                stop_dkr_tasks(&mut dkr_src_tasks);
                return Ok(());
            }
            _ = interval.tick() => {}
        }

        if let Err(e) = rpc
            .submit_txn(
                &sk,
                &vk,
                &account_addr,
                &format!("{}::epoch_change::touch", ace),
                &[],
                &[TxnArg::Address(&session_addr)],
            )
            .await
        {
            eprintln!("epoch-change-cur: touch error: {:#}", e);
        }

        let session = match fetch_epoch_change_session(&rpc, &ace, &session_addr).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("epoch-change-cur: fetch session error: {:#}", e);
                continue;
            }
        };

        if session.state_code == STATE_DONE {
            println!("epoch-change-cur: session reached STATE__DONE; exiting.");
            stop_dkr_tasks(&mut dkr_src_tasks);
            return Ok(());
        }

        let in_cur = session
            .cur_nodes
            .iter()
            .any(|n| n == &account_addr);
        if !in_cur {
            eprintln!(
                "epoch-change-cur: account {} is not in cur_nodes; only submitting touch, no dkr-src.",
                account_addr
            );
            if !dkr_src_tasks.is_empty() {
                println!("epoch-change-cur: stopping dkr-src tasks (not in cur_nodes).");
                stop_dkr_tasks(&mut dkr_src_tasks);
            }
            continue;
        }

        // Reconcile DKR-src: one sub-task per DKR session address in `dkrs`.
        let active: HashSet<String> = session.dkrs.iter().cloned().collect();
        for dkr in &session.dkrs {
            if dkr_src_tasks.contains_key(dkr) {
                continue;
            }
            let (tx, rx) = oneshot::channel::<()>();
            dkr_src_tasks.insert(dkr.clone(), tx);
            let cfg = dkr_src::RunConfig {
                rpc_url: config.rpc_url.clone(),
                rpc_api_key: config.rpc_api_key.clone(),
                rpc_gas_key: config.rpc_gas_key.clone(),
                ace_contract: ace.clone(),
                dkr_session: dkr.clone(),
                account_addr: account_addr.clone(),
                account_sk_hex: config.account_sk_hex.clone(),
                pke_dk_hex: config.pke_dk_hex.clone(),
            };
            let label = dkr.clone();
            tokio::spawn(async move {
                if let Err(e) = dkr_src::run(cfg, rx).await {
                    eprintln!("epoch-change-cur: dkr-src sub-task error for session={} : {:#}", label, e);
                }
            });
            println!("epoch-change-cur: started dkr-src for dkr_session={}", dkr);
        }

        // Drop tasks for DKR addrs that disappeared (abnormal; keeps map consistent).
        let stale: Vec<String> = dkr_src_tasks
            .keys()
            .filter(|k| !active.contains(*k))
            .cloned()
            .collect();
        for k in stale {
            if let Some(tx) = dkr_src_tasks.remove(&k) {
                let _ = tx.send(());
                println!("epoch-change-cur: stopped dkr-src for dkr_session={} (no longer in dkrs)", k);
            }
        }

    }
}
