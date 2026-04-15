// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Supervisor process for one committee member.
//!
//! Polls `network::State` from `@ace` every 5 seconds and manages sub-tasks:
//!
//! * **DKG tasks** (`dkg_worker::run`) — started for every session in
//!   `State.dkgs_in_progress` when this node is in `cur_nodes`.
//! * **DKR-src tasks** (`dkr_src::run`) — started for every session in
//!   `EpochChangeState.dkr_sessions` when this node is in `cur_nodes`.
//! * **DKR-dst tasks** (`dkr_dst::run`) — started for every session in
//!   `EpochChangeState.dkr_sessions` when this node is in `nxt_nodes`.
//!
//! Sub-tasks receive a `oneshot::Receiver<()>` shutdown channel and exit on
//! their own when the protocol session completes.  The supervisor keeps the
//! sender in a `HashMap`; calling `stop_tasks` drains the map and fires each
//! sender (errors are silently ignored because the task may have already exited).

use anyhow::Result;
use serde_json::Value;
use std::collections::HashMap;
use tokio::sync::oneshot;
use vss_common::{normalize_account_addr, parse_ed25519_signing_key_hex, AptosRpc};

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub rpc_url: String,
    pub ace_contract: String,
    pub account_addr: String,
    pub account_sk_hex: String,
    pub pke_dk_hex: String,
}

// ── On-chain state representation ───────────────────────────────────────────

struct EpochChangeState {
    nxt_nodes: Vec<String>,
    dkr_sessions: Vec<String>,
}

struct NetworkState {
    cur_nodes: Vec<String>,
    dkgs_in_progress: Vec<String>,
    epoch_change_state: Option<EpochChangeState>,
}

fn parse_addr_array(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|arr| {
            arr.iter()
                .map(|a| normalize_account_addr(a.as_str().unwrap_or("")))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_network_state(data: &Value) -> NetworkState {
    let cur_nodes = parse_addr_array(&data["cur_nodes"]);
    let dkgs_in_progress = parse_addr_array(&data["dkgs_in_progress"]);

    // Move `Option<T>` encodes as `{"vec": []}` (None) or `{"vec": [<T>]}` (Some).
    let epoch_change_state = data["epoch_change_state"]["vec"]
        .as_array()
        .and_then(|arr| arr.first())
        .map(|ecs| EpochChangeState {
            nxt_nodes: parse_addr_array(&ecs["nxt_nodes"]),
            dkr_sessions: parse_addr_array(&ecs["dkr_sessions"]),
        });

    NetworkState { cur_nodes, dkgs_in_progress, epoch_change_state }
}

async fn fetch_network_state(rpc: &AptosRpc, ace: &str) -> Result<NetworkState> {
    let data = rpc
        .get_resource_data(ace, &format!("{}::network::State", ace))
        .await?;
    Ok(parse_network_state(&data))
}

// ── Task lifecycle helpers ───────────────────────────────────────────────────

/// Drain `tasks`, sending shutdown to each sub-task (ignoring already-closed channels).
fn stop_tasks(tasks: &mut HashMap<String, oneshot::Sender<()>>) {
    for (_, tx) in tasks.drain() {
        let _ = tx.send(());
    }
}

// ── Main loop ────────────────────────────────────────────────────────────────

pub async fn run(config: RunConfig, mut shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
    let rpc = AptosRpc::new(config.rpc_url.clone());
    let sk = parse_ed25519_signing_key_hex(&config.account_sk_hex)?;
    let vk = sk.verifying_key();
    let account_addr = normalize_account_addr(&config.account_addr);
    let ace = normalize_account_addr(&config.ace_contract);

    println!(
        "network-node: starting (account={} ace={})",
        account_addr, ace
    );

    let mut dkg_tasks: HashMap<String, oneshot::Sender<()>> = HashMap::new();
    let mut dkr_src_tasks: HashMap<String, oneshot::Sender<()>> = HashMap::new();
    let mut dkr_dst_tasks: HashMap<String, oneshot::Sender<()>> = HashMap::new();

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                println!("network-node: shutdown signal received.");
                stop_tasks(&mut dkg_tasks);
                stop_tasks(&mut dkr_src_tasks);
                stop_tasks(&mut dkr_dst_tasks);
                return Ok(());
            }
            _ = interval.tick() => {}
        }

        let state = match fetch_network_state(&rpc, &ace).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("network-node: fetch state error: {:#}", e);
                continue;
            }
        };

        // Call network::touch() to advance state (move completed DKGs to secrets,
        // or advance the epoch when all DKR sessions are done).
        let no_args: &[Value] = &[];
        if let Err(e) = rpc.submit_txn(
            &sk, &vk, &account_addr,
            &format!("{}::network::touch", ace), &[],
            no_args,
        ).await {
            eprintln!("network-node: touch error: {:#}", e);
        }

        let in_cur_nodes = state.cur_nodes.iter().any(|n| n == &account_addr);

        // ── DKG sub-tasks ───────────────────────────────────────────────────
        // TODO: also start UserRequestHandler tasks for each session in State.secrets
        //       when in_cur_nodes (serves decryption requests from clients).

        if in_cur_nodes {
            for session_addr in &state.dkgs_in_progress {
                if !dkg_tasks.contains_key(session_addr) {
                    let (tx, rx) = oneshot::channel::<()>();
                    let cfg = dkg_worker::RunConfig {
                        rpc_url: config.rpc_url.clone(),
                        ace_contract: ace.clone(),
                        dkg_session: session_addr.clone(),
                        account_addr: account_addr.clone(),
                        account_sk_hex: config.account_sk_hex.clone(),
                        pke_dk_hex: config.pke_dk_hex.clone(),
                    };
                    tokio::spawn(async move {
                        if let Err(e) = dkg_worker::run(cfg, rx).await {
                            eprintln!("network-node: dkg-worker sub-task error: {:#}", e);
                        }
                    });
                    dkg_tasks.insert(session_addr.clone(), tx);
                    println!("network-node: started dkg-worker for session={}", session_addr);
                }
            }
        } else if !dkg_tasks.is_empty() {
            println!("network-node: stopping all dkg-worker tasks (not in cur_nodes).");
            stop_tasks(&mut dkg_tasks);
        }

        // ── DKR sub-tasks ───────────────────────────────────────────────────

        match state.epoch_change_state {
            Some(ecs) => {
                let in_nxt_nodes = ecs.nxt_nodes.iter().any(|n| n == &account_addr);

                // DKR-src: old-committee members deal their DKG share into a DKR VSS.
                if in_cur_nodes {
                    for session_addr in &ecs.dkr_sessions {
                        if !dkr_src_tasks.contains_key(session_addr) {
                            let (tx, rx) = oneshot::channel::<()>();
                            let cfg = dkr_src::RunConfig {
                                rpc_url: config.rpc_url.clone(),
                                ace_contract: ace.clone(),
                                dkr_session: session_addr.clone(),
                                account_addr: account_addr.clone(),
                                account_sk_hex: config.account_sk_hex.clone(),
                                pke_dk_hex: config.pke_dk_hex.clone(),
                            };
                            tokio::spawn(async move {
                                if let Err(e) = dkr_src::run(cfg, rx).await {
                                    eprintln!("network-node: dkr-src sub-task error: {:#}", e);
                                }
                            });
                            dkr_src_tasks.insert(session_addr.clone(), tx);
                            println!("network-node: started dkr-src for session={}", session_addr);
                        }
                    }
                } else if !dkr_src_tasks.is_empty() {
                    println!("network-node: stopping all dkr-src tasks (not in cur_nodes).");
                    stop_tasks(&mut dkr_src_tasks);
                }

                // DKR-dst: new-committee members receive shares from all DKR VSS sessions.
                if in_nxt_nodes {
                    for session_addr in &ecs.dkr_sessions {
                        if !dkr_dst_tasks.contains_key(session_addr) {
                            let (tx, rx) = oneshot::channel::<()>();
                            let cfg = dkr_dst::RunConfig {
                                rpc_url: config.rpc_url.clone(),
                                ace_contract: ace.clone(),
                                dkr_session: session_addr.clone(),
                                account_addr: account_addr.clone(),
                                account_sk_hex: config.account_sk_hex.clone(),
                                pke_dk_hex: config.pke_dk_hex.clone(),
                            };
                            tokio::spawn(async move {
                                if let Err(e) = dkr_dst::run(cfg, rx).await {
                                    eprintln!("network-node: dkr-dst sub-task error: {:#}", e);
                                }
                            });
                            dkr_dst_tasks.insert(session_addr.clone(), tx);
                            println!("network-node: started dkr-dst for session={}", session_addr);
                        }
                    }
                } else if !dkr_dst_tasks.is_empty() {
                    println!("network-node: stopping all dkr-dst tasks (not in nxt_nodes).");
                    stop_tasks(&mut dkr_dst_tasks);
                }
            }
            None => {
                // No epoch change in progress — stop any lingering DKR tasks.
                if !dkr_src_tasks.is_empty() {
                    println!("network-node: stopping all dkr-src tasks (no epoch change).");
                    stop_tasks(&mut dkr_src_tasks);
                }
                if !dkr_dst_tasks.is_empty() {
                    println!("network-node: stopping all dkr-dst tasks (no epoch change).");
                    stop_tasks(&mut dkr_dst_tasks);
                }
            }
        }
    }
}
