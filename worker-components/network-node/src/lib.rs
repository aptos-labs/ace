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

pub mod crypto;
mod http_server;
pub mod verify;

use anyhow::{anyhow, Result};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, RwLock};
use vss_common::{normalize_account_addr, parse_ed25519_signing_key_hex, AptosRpc};

// ── Per-chain RPC configuration ──────────────────────────────────────────────

/// Pre-built RPC clients for all supported chains.
/// Clients are constructed once at startup and shared across all requests.
pub struct ChainRpcConfig {
    pub aptos_mainnet: AptosRpc,   // chain_id=1
    pub aptos_testnet: AptosRpc,   // chain_id=2
    pub aptos_localnet: AptosRpc,  // chain_id=4
    pub solana_mainnet_beta: String,
    pub solana_testnet: String,
    pub solana_devnet: String,
    pub solana_client: reqwest::Client,
}

impl ChainRpcConfig {
    pub fn aptos_rpc_for_chain_id(&self, chain_id: u8) -> Result<&AptosRpc> {
        Ok(match chain_id {
            1 => &self.aptos_mainnet,
            2 => &self.aptos_testnet,
            4 => &self.aptos_localnet,
            _ => return Err(anyhow!("no Aptos RPC configured for chain_id {}", chain_id)),
        })
    }

    pub fn solana_rpc_for_chain_name(&self, name: &str) -> Result<String> {
        Ok(match name {
            "localnet" | "localhost" => "http://127.0.0.1:8899".to_string(),
            "devnet" => self.solana_devnet.clone(),
            "testnet" => self.solana_testnet.clone(),
            "mainnet-beta" => self.solana_mainnet_beta.clone(),
            other => return Err(anyhow!("verify_solana: unsupported chain name '{}'", other)),
        })
    }
}

// ── Top-level run configuration ───────────────────────────────────────────────

pub struct RunConfig {
    pub ace_deployment_api: String,
    pub ace_deployment_apikey: Option<String>,
    pub ace_deployment_addr: String,
    pub account_addr: String,
    pub account_sk_hex: String,
    pub pke_dk: String,
    pub port: Option<u16>,
    pub chain_rpc: ChainRpcConfig,
}

// ── On-chain state representation ───────────────────────────────────────────

struct EpochChangeState {
    nxt_nodes: Vec<String>,
    dkr_sessions: Vec<String>,
}

struct NetworkState {
    epoch: u64,
    cur_nodes: Vec<String>,
    dkgs_in_progress: Vec<String>,
    epoch_change_state: Option<EpochChangeState>,
    secrets: Vec<String>,
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
    // Aptos REST API serialises u64 as a JSON string.
    let epoch = data["epoch"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0);
    let cur_nodes = parse_addr_array(&data["cur_nodes"]);
    let dkgs_in_progress = parse_addr_array(&data["dkgs_in_progress"]);
    let secrets = parse_addr_array(&data["secrets"]);

    // Move `Option<T>` encodes as `{"vec": []}` (None) or `{"vec": [<T>]}` (Some).
    let epoch_change_state = data["epoch_change_state"]["vec"]
        .as_array()
        .and_then(|arr| arr.first())
        .map(|ecs| EpochChangeState {
            nxt_nodes: parse_addr_array(&ecs["nxt_nodes"]),
            dkr_sessions: parse_addr_array(&ecs["dkr_sessions"]),
        });

    NetworkState { epoch, cur_nodes, dkgs_in_progress, epoch_change_state, secrets }
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
    let rpc = AptosRpc::new_with_key(
        config.ace_deployment_api.clone(),
        config.ace_deployment_apikey.clone(),
    );
    let sk = parse_ed25519_signing_key_hex(&config.account_sk_hex)?;
    let vk = sk.verifying_key();
    let account_addr = normalize_account_addr(&config.account_addr);
    let ace = normalize_account_addr(&config.ace_deployment_addr);

    // Decode PKE decryption key bytes once.
    let pke_dk_bytes: Vec<u8> = {
        let raw = config.pke_dk.trim().trim_start_matches("0x");
        hex::decode(raw).map_err(|e| anyhow::anyhow!("pke_dk decode: {}", e))?
    };

    println!(
        "network-node: starting (account={} ace={})",
        account_addr, ace
    );

    // keypair_shares: keypair_id → epoch → scalar_le32.
    // Multiple epoch entries coexist during the ~30-second post-transition buffer window
    // so that clients who fetched the committee just before an epoch change can still be
    // served by nodes that have since rotated to the new epoch's shares.
    let keypair_shares: Arc<RwLock<HashMap<String, HashMap<u64, [u8; 32]>>>> =
        Arc::new(RwLock::new(HashMap::new()));

    // Scheduled evictions: (deadline, keypair_id, epoch).  URH tasks push here on
    // shutdown instead of removing immediately; the cleanup timer does the actual removal.
    let expiry_queue: Arc<Mutex<Vec<(Instant, String, u64)>>> =
        Arc::new(Mutex::new(Vec::new()));

    let cur_nodes_shared: Arc<RwLock<Vec<String>>> = Arc::new(RwLock::new(Vec::new()));

    // Spawn HTTP server if a port was configured.
    if let Some(port) = config.port {
        let ks = keypair_shares.clone();
        let cn = cur_nodes_shared.clone();
        let my = account_addr.clone();
        let chain_rpc = Arc::new(config.chain_rpc);
        let dk = pke_dk_bytes.clone();
        tokio::spawn(http_server::run(port, ks, cn, my, chain_rpc, dk));
    }

    // Spawn the share cleanup timer.  Wakes every 5 seconds and evicts expired entries.
    {
        let ks = keypair_shares.clone();
        let eq = expiry_queue.clone();
        tokio::spawn(async move {
            let mut ticker =
                tokio::time::interval(tokio::time::Duration::from_secs(5));
            loop {
                ticker.tick().await;
                let now = Instant::now();
                let expired: Vec<(String, u64)> = {
                    let mut q = eq.lock().unwrap();
                    let (done, pending): (Vec<_>, Vec<_>) =
                        q.drain(..).partition(|(t, _, _)| *t <= now);
                    *q = pending;
                    done.into_iter().map(|(_, k, e)| (k, e)).collect()
                };
                if !expired.is_empty() {
                    let mut w = ks.write().await;
                    for (keypair_id, epoch) in expired {
                        if let Some(by_epoch) = w.get_mut(&keypair_id) {
                            by_epoch.remove(&epoch);
                            if by_epoch.is_empty() {
                                w.remove(&keypair_id);
                            }
                            println!(
                                "network-node: [cleanup] evicted keypair_id={} epoch={}",
                                keypair_id, epoch
                            );
                        }
                    }
                }
            }
        });
    }

    let mut dkg_tasks: HashMap<String, oneshot::Sender<()>> = HashMap::new();
    let mut dkr_src_tasks: HashMap<String, oneshot::Sender<()>> = HashMap::new();
    let mut dkr_dst_tasks: HashMap<String, oneshot::Sender<()>> = HashMap::new();
    let mut urh_tasks: HashMap<String, oneshot::Sender<()>> = HashMap::new();

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                println!("network-node: shutdown signal received.");
                stop_tasks(&mut dkg_tasks);
                stop_tasks(&mut dkr_src_tasks);
                stop_tasks(&mut dkr_dst_tasks);
                stop_tasks(&mut urh_tasks);
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

        // Update cur_nodes for the HTTP server's eval-point lookup.
        *cur_nodes_shared.write().await = state.cur_nodes.clone();

        // ── URH (UserRequestHandler) tasks ─────────────────────────────────
        // For each session address in state.secrets, maintain a background task that:
        //   1. Reconstructs this node's Shamir scalar share.
        //   2. Inserts it into keypair_shares so the HTTP server can serve requests.
        //   3. Waits for shutdown, then removes it from keypair_shares.

        let active_secrets: HashSet<String> = if in_cur_nodes {
            state.secrets.iter().cloned().collect()
        } else {
            HashSet::new()
        };

        for secret_addr in &active_secrets {
            if urh_tasks.contains_key(secret_addr) {
                continue;
            }
            let (tx, rx) = oneshot::channel::<()>();
            urh_tasks.insert(secret_addr.clone(), tx);

            let rpc2 = rpc.clone();
            let ace2 = ace.clone();
            let secret = secret_addr.clone();
            let pke_dk = pke_dk_bytes.clone();
            let my = account_addr.clone();
            let shares = keypair_shares.clone();
            let expiry = expiry_queue.clone();
            let epoch = state.epoch;

            tokio::spawn(async move {
                match vss_common::reconstruct_share(&rpc2, &ace2, &secret, &my, &pke_dk).await {
                    Ok((scalar_le32, keypair_id)) => {
                        shares
                            .write()
                            .await
                            .entry(keypair_id.clone())
                            .or_default()
                            .insert(epoch, scalar_le32);
                        println!(
                            "network-node: [urh] registered keypair_id={} epoch={}",
                            keypair_id, epoch
                        );
                        let _ = rx.await;
                        // Defer removal by 30 s so clients who fetched the committee
                        // just before an epoch change can still be served.
                        let deadline = Instant::now() + Duration::from_secs(30);
                        expiry.lock().unwrap().push((deadline, keypair_id.clone(), epoch));
                        println!(
                            "network-node: [urh] scheduled eviction keypair_id={} epoch={} in 30s",
                            keypair_id, epoch
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "network-node: [urh] reconstruct_share failed for {}: {:#}",
                            secret, e
                        );
                    }
                }
            });
            println!("network-node: started URH task for secret={}", secret_addr);
        }

        let stale_secrets: Vec<String> = urh_tasks
            .keys()
            .filter(|k| !active_secrets.contains(*k))
            .cloned()
            .collect();
        for k in stale_secrets {
            if let Some(tx) = urh_tasks.remove(&k) {
                let _ = tx.send(());
                println!("network-node: stopped URH task for secret={}", k);
            }
        }

        // ── DKG sub-tasks ───────────────────────────────────────────────────

        if in_cur_nodes {
            for session_addr in &state.dkgs_in_progress {
                if !dkg_tasks.contains_key(session_addr) {
                    let (tx, rx) = oneshot::channel::<()>();
                    let cfg = dkg_worker::RunConfig {
                        rpc_url: config.ace_deployment_api.clone(),
                        rpc_api_key: config.ace_deployment_apikey.clone(),
                        ace_contract: ace.clone(),
                        dkg_session: session_addr.clone(),
                        account_addr: account_addr.clone(),
                        account_sk_hex: config.account_sk_hex.clone(),
                        pke_dk_hex: config.pke_dk.clone(),
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
                                rpc_url: config.ace_deployment_api.clone(),
                                rpc_api_key: config.ace_deployment_apikey.clone(),
                                ace_contract: ace.clone(),
                                dkr_session: session_addr.clone(),
                                account_addr: account_addr.clone(),
                                account_sk_hex: config.account_sk_hex.clone(),
                                pke_dk_hex: config.pke_dk.clone(),
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
                                rpc_url: config.ace_deployment_api.clone(),
                                rpc_api_key: config.ace_deployment_apikey.clone(),
                                ace_contract: ace.clone(),
                                dkr_session: session_addr.clone(),
                                account_addr: account_addr.clone(),
                                account_sk_hex: config.account_sk_hex.clone(),
                                pke_dk_hex: config.pke_dk.clone(),
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
