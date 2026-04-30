// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Programmatic API for the epoch-change **next committee** side of a single
//! on-chain `ace::epoch_change::Session`, identified by `epoch_change_session`.
//!
//! 1. Submits `epoch_change::touch(session_addr)` on each tick. Only reads
//!    `ace::epoch_change::Session` at `RunConfig::epoch_change_session` — not `network::State`.
//! 2. Drives the session (`START_DKRS`, `START_DKGS`, then `AWAIT` → `DONE`), same liveness as
//!    `epoch-change-cur` for the shared `touch` entry.
//! 3. If the operator is in the session's `nxt_nodes`, starts
//!    - one [`dkr_dst::RunConfig`] per address in `dkrs`, and
//!    - one [`dkg_worker::RunConfig`] per address in `dkgs`.
//!
//! When the session reaches `STATE__DONE`, this client exits successfully.
//! A separate `network::touch` is still required to apply `epoch_change::results` to
//! global `State`.

use anyhow::{anyhow, Result};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::time::Duration;
use tokio::sync::oneshot;
use vss_common::{normalize_account_addr, parse_ed25519_signing_key_hex, AptosRpc, TxnArg};

const STATE_DONE: u8 = 3;

#[derive(Debug, Clone)]
struct EpochChangeSession {
    nxt_nodes: Vec<String>,
    dkrs: Vec<String>,
    dkgs: Vec<String>,
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
    let nxt_nodes: Vec<String> = data["nxt_nodes"]
        .as_array()
        .ok_or_else(|| anyhow!("missing nxt_nodes in epoch_change::Session"))?
        .iter()
        .map(|v| normalize_account_addr(v.as_str().unwrap_or("")))
        .collect();

    let dkrs: Vec<String> = data["dkrs"]
        .as_array()
        .ok_or_else(|| anyhow!("missing dkrs in epoch_change::Session"))?
        .iter()
        .map(|v| normalize_account_addr(v.as_str().unwrap_or("")))
        .collect();

    let dkgs: Vec<String> = data["dkgs"]
        .as_array()
        .ok_or_else(|| anyhow!("missing dkgs in epoch_change::Session"))?
        .iter()
        .map(|v| normalize_account_addr(v.as_str().unwrap_or("")))
        .collect();

    let state_code: u8 = match &data["state_code"] {
        Value::Number(n) => n.as_u64().unwrap_or(0) as u8,
        Value::String(s) => s.parse().unwrap_or(0),
        _ => return Err(anyhow!("missing or invalid state_code in epoch_change::Session")),
    };

    Ok(EpochChangeSession {
        nxt_nodes,
        dkrs,
        dkgs,
        state_code,
    })
}

fn stop_tasks(tasks: &mut HashMap<String, oneshot::Sender<()>>) {
    for (_, tx) in tasks.drain() {
        let _ = tx.send(());
    }
}

/// Run the epoch-change nxt protocol until the session is `STATE__DONE` or shutdown.
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
        "epoch-change-nxt: starting (account={} epoch_change_session={} ace={})",
        account_addr, session_addr, ace
    );

    let initial = fetch_epoch_change_session(&rpc, &ace, &session_addr).await?;
    if initial.state_code == STATE_DONE {
        println!("epoch-change-nxt: session already STATE__DONE; nothing to do.");
        return Ok(());
    }

    let mut dkr_dst_tasks: HashMap<String, oneshot::Sender<()>> = HashMap::new();
    let mut dkg_tasks: HashMap<String, oneshot::Sender<()>> = HashMap::new();

    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                println!("epoch-change-nxt: shutdown signal received.");
                stop_tasks(&mut dkr_dst_tasks);
                stop_tasks(&mut dkg_tasks);
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
            eprintln!("epoch-change-nxt: touch error: {:#}", e);
        }

        let session = match fetch_epoch_change_session(&rpc, &ace, &session_addr).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("epoch-change-nxt: fetch session error: {:#}", e);
                continue;
            }
        };

        if session.state_code == STATE_DONE {
            println!("epoch-change-nxt: session reached STATE__DONE; exiting.");
            stop_tasks(&mut dkr_dst_tasks);
            stop_tasks(&mut dkg_tasks);
            return Ok(());
        }

        let in_nxt = session.nxt_nodes.iter().any(|n| n == &account_addr);
        if !in_nxt {
            eprintln!(
                "epoch-change-nxt: account {} is not in nxt_nodes; only submitting touch, no dkr-dst/dkg.",
                account_addr
            );
            if !dkr_dst_tasks.is_empty() {
                println!("epoch-change-nxt: stopping dkr-dst tasks (not in nxt_nodes).");
                stop_tasks(&mut dkr_dst_tasks);
            }
            if !dkg_tasks.is_empty() {
                println!("epoch-change-nxt: stopping dkg-worker tasks (not in nxt_nodes).");
                stop_tasks(&mut dkg_tasks);
            }
            continue;
        }

        // DKR-dst: one sub-task per DKR session in `dkrs`.
        let active_dkrs: HashSet<String> = session.dkrs.iter().cloned().collect();
        for dkr in &session.dkrs {
            if dkr_dst_tasks.contains_key(dkr) {
                continue;
            }
            let (tx, rx) = oneshot::channel::<()>();
            dkr_dst_tasks.insert(dkr.clone(), tx);
            let cfg = dkr_dst::RunConfig {
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
                if let Err(e) = dkr_dst::run(cfg, rx).await {
                    eprintln!(
                        "epoch-change-nxt: dkr-dst sub-task error for session={} : {:#}",
                        label, e
                    );
                }
            });
            println!("epoch-change-nxt: started dkr-dst for dkr_session={}", dkr);
        }
        for k in dkr_dst_tasks
            .keys()
            .filter(|k| !active_dkrs.contains(*k))
            .cloned()
            .collect::<Vec<_>>()
        {
            if let Some(tx) = dkr_dst_tasks.remove(&k) {
                let _ = tx.send(());
                println!(
                    "epoch-change-nxt: stopped dkr-dst for dkr_session={} (no longer in dkrs)",
                    k
                );
            }
        }

        // DKG: one sub-task per DKG session in `dkgs`.
        let active_dkgs: HashSet<String> = session.dkgs.iter().cloned().collect();
        for dkg in &session.dkgs {
            if dkg_tasks.contains_key(dkg) {
                continue;
            }
            let (tx, rx) = oneshot::channel::<()>();
            dkg_tasks.insert(dkg.clone(), tx);
            let cfg = dkg_worker::RunConfig {
                rpc_url: config.rpc_url.clone(),
                rpc_api_key: config.rpc_api_key.clone(),
                rpc_gas_key: config.rpc_gas_key.clone(),
                ace_contract: ace.clone(),
                dkg_session: dkg.clone(),
                account_addr: account_addr.clone(),
                account_sk_hex: config.account_sk_hex.clone(),
                pke_dk_hex: config.pke_dk_hex.clone(),
            };
            let label = dkg.clone();
            tokio::spawn(async move {
                if let Err(e) = dkg_worker::run(cfg, rx).await {
                    eprintln!("epoch-change-nxt: dkg-worker error for dkg={} : {:#}", label, e);
                }
            });
            println!("epoch-change-nxt: started dkg-worker for dkg_session={}", dkg);
        }
        for k in dkg_tasks
            .keys()
            .filter(|k| !active_dkgs.contains(*k))
            .cloned()
            .collect::<Vec<_>>()
        {
            if let Some(tx) = dkg_tasks.remove(&k) {
                let _ = tx.send(());
                println!(
                    "epoch-change-nxt: stopped dkg-worker for dkg_session={} (no longer in dkgs)",
                    k
                );
            }
        }
    }
}
