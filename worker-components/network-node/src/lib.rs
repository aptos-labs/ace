// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Supervisor for one worker: polls `network::State`, **URH** (share reconstruction for
//! `State.secrets` when in `cur_nodes`), optional **HTTP** server, and
//! **`network::touch`** only while `State.epoch_change_info` is `Some` (so global `State`
//! can apply a finished `epoch_change` session).
//!
//! DKR / DKG / `epoch_change::touch` for the child session are **not** run here; use
//! `epoch-change-cur` and `epoch-change-nxt` (or equivalent processes) for that.
//!
//! URH sub-tasks use a `oneshot::Receiver<()>` shutdown; `stop_tasks` drains the map.

pub mod crypto;
mod http_server;
pub mod verify;

use anyhow::{anyhow, Result};
use serde_json::Value;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, RwLock, Semaphore};
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

// ── Memory-based concurrency limit ───────────────────────────────────────────

/// Reads the container's memory limit from cgroup (v2 then v1 fallback).
/// Returns `None` when running outside a cgroup or when no explicit limit is set.
fn read_cgroup_memory_limit() -> Option<usize> {
    // cgroup v2: a plain integer or the string "max" (= unlimited)
    if let Ok(s) = std::fs::read_to_string("/sys/fs/cgroup/memory.max") {
        let s = s.trim();
        if s != "max" {
            if let Ok(n) = s.parse::<usize>() {
                return Some(n);
            }
        }
        return None; // "max" → no limit
    }
    // cgroup v1: values ≥ 2^62 indicate "no limit"
    if let Ok(s) = std::fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes") {
        if let Ok(n) = s.trim().parse::<usize>() {
            if n < (1usize << 62) {
                return Some(n);
            }
        }
    }
    None
}

/// Derives `max_concurrent_requests` from a cgroup memory limit.
///
/// Constants come from `bench-request-mem` (release build, macOS M-series),
/// scaled up by 1.5× for headroom against real Linux + TLS workloads:
///   measured per-request ≈ 66 KiB  →  100 KiB used
///   measured baseline    ≈ 182 KiB →  256 KiB used
fn derive_max_concurrent(memory_limit: usize) -> usize {
    const BASELINE: usize = 256 * 1024;
    const PER_REQUEST: usize = 100 * 1024;
    const MIN: usize = 10;
    (memory_limit.saturating_sub(BASELINE) / PER_REQUEST).max(MIN)
}

// ── Top-level run configuration ───────────────────────────────────────────────

pub struct RunConfig {
    pub ace_deployment_api: String,
    pub ace_deployment_apikey: Option<String>,
    pub ace_deployment_gaskey: Option<String>,
    pub ace_deployment_addr: String,
    pub account_addr: String,
    pub account_sk_hex: String,
    pub pke_dk: String,
    pub port: Option<u16>,
    pub chain_rpc: ChainRpcConfig,
    /// Maximum concurrent in-flight HTTP requests.
    /// `None` = auto-derive from cgroup memory limit.
    pub max_concurrent: Option<usize>,
}

// ── On-chain state representation ───────────────────────────────────────────

/// Mirrors `ace::network::EpochChangeInfo`.
struct EpochChangeInfo {
    nxt_nodes: Vec<String>,
    session: String,
}

struct NetworkState {
    epoch: u64,
    epoch_start_time_micros: u64,
    epoch_duration_micros: u64,
    cur_nodes: Vec<String>,
    epoch_change_info: Option<EpochChangeInfo>,
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

fn parse_u64_field(data: &Value, key: &str) -> u64 {
    data[key].as_str().and_then(|s| s.parse().ok()).unwrap_or(0)
}

fn parse_network_state(data: &Value) -> NetworkState {
    let epoch = parse_u64_field(data, "epoch");
    let epoch_start_time_micros = parse_u64_field(data, "epoch_start_time_micros");
    let epoch_duration_micros = parse_u64_field(data, "epoch_duration_micros");
    let cur_nodes = parse_addr_array(&data["cur_nodes"]);
    let secrets = parse_addr_array(&data["secrets"]);

    // Move `Option<EpochChangeInfo>` is serialised as `{"vec": []}` or `{"vec": [item]}`.
    let epoch_change_info = data["epoch_change_info"]["vec"]
        .as_array()
        .and_then(|a| a.first())
        .map(|item| EpochChangeInfo {
            nxt_nodes: parse_addr_array(&item["nxt_nodes"]),
            session: normalize_account_addr(item["session"].as_str().unwrap_or("")),
        });

    NetworkState {
        epoch,
        epoch_start_time_micros,
        epoch_duration_micros,
        cur_nodes,
        epoch_change_info,
        secrets,
    }
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
    let rpc = AptosRpc::new_with_gas_key(
        config.ace_deployment_api.clone(),
        config.ace_deployment_apikey.clone(),
        config.ace_deployment_gaskey.clone(),
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

    // Fields forwarded verbatim to epoch-change-cur / epoch-change-nxt RunConfigs.
    let ec_rpc_url = config.ace_deployment_api.clone();
    let ec_rpc_api_key = config.ace_deployment_apikey.clone();
    let ec_rpc_gas_key = config.ace_deployment_gaskey.clone();
    let ec_account_sk_hex = config.account_sk_hex.clone();
    let ec_pke_dk_hex = config.pke_dk.clone();

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
        const DEFAULT_MAX_CONCURRENT: usize = 100;
        let max_concurrent = config.max_concurrent.unwrap_or_else(|| {
            match read_cgroup_memory_limit() {
                Some(limit) => {
                    let mc = derive_max_concurrent(limit);
                    println!(
                        "network-node: cgroup memory limit {:.0} MiB → max_concurrent_requests={}",
                        limit as f64 / (1024.0 * 1024.0),
                        mc,
                    );
                    mc
                }
                None => {
                    println!(
                        "network-node: no cgroup memory limit detected, \
                         max_concurrent_requests={DEFAULT_MAX_CONCURRENT} (default)"
                    );
                    DEFAULT_MAX_CONCURRENT
                }
            }
        });
        let concurrency = Arc::new(Semaphore::new(max_concurrent));

        let ks = keypair_shares.clone();
        let cn = cur_nodes_shared.clone();
        let my = account_addr.clone();
        let chain_rpc = Arc::new(config.chain_rpc);
        let dk = pke_dk_bytes.clone();
        tokio::spawn(http_server::run(port, ks, cn, my, chain_rpc, dk, concurrency));
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

    let mut urh_tasks: HashMap<String, oneshot::Sender<()>> = HashMap::new();
    // Keyed by epoch_change session address so re-entrant ticks are idempotent.
    let mut epoch_change_cur_tasks: HashMap<String, oneshot::Sender<()>> = HashMap::new();
    let mut epoch_change_nxt_tasks: HashMap<String, oneshot::Sender<()>> = HashMap::new();

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                println!("network-node: shutdown signal received.");
                stop_tasks(&mut urh_tasks);
                stop_tasks(&mut epoch_change_cur_tasks);
                stop_tasks(&mut epoch_change_nxt_tasks);
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

        let in_cur_nodes = state.cur_nodes.iter().any(|n| n == &account_addr);

        // Submit network::touch only when useful:
        // - epoch_change_info is Some: apply results once child session reaches STATE__DONE.
        // - epoch_change_info is None and epoch has timed out: trigger auto epoch-change.
        let epoch_timed_out = {
            let now_micros = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros() as u64;
            now_micros >= state.epoch_start_time_micros.saturating_add(state.epoch_duration_micros)
        };
        if state.epoch_change_info.is_some() || epoch_timed_out {
            if let Err(e) = rpc
                .submit_txn(
                    &sk,
                    &vk,
                    &account_addr,
                    &format!("{}::network::touch", ace),
                    &[],
                    &[],
                )
                .await
            {
                eprintln!("network-node: network::touch error: {:#}", e);
            }
        }

        match &state.epoch_change_info {
            Some(info) => {

                // epoch-change-cur: cur_nodes drive DKR-src + touch.
                if in_cur_nodes {
                    if !epoch_change_cur_tasks.contains_key(&info.session) {
                        let (tx, rx) = oneshot::channel::<()>();
                        epoch_change_cur_tasks.insert(info.session.clone(), tx);
                        let cfg = epoch_change_cur::RunConfig {
                            rpc_url: ec_rpc_url.clone(),
                            rpc_api_key: ec_rpc_api_key.clone(),
                            rpc_gas_key: ec_rpc_gas_key.clone(),
                            ace_contract: ace.clone(),
                            epoch_change_session: info.session.clone(),
                            account_addr: account_addr.clone(),
                            account_sk_hex: ec_account_sk_hex.clone(),
                            pke_dk_hex: ec_pke_dk_hex.clone(),
                        };
                        tokio::spawn(async move {
                            if let Err(e) = epoch_change_cur::run(cfg, rx).await {
                                eprintln!("network-node: epoch-change-cur error: {:#}", e);
                            }
                        });
                        println!("network-node: started epoch-change-cur for session={}", info.session);
                    }
                } else {
                    stop_tasks(&mut epoch_change_cur_tasks);
                }

                // epoch-change-nxt: nxt_nodes drive DKR-dst + optional DKG + touch.
                let in_nxt_nodes = info.nxt_nodes.iter().any(|n| n == &account_addr);
                if in_nxt_nodes {
                    if !epoch_change_nxt_tasks.contains_key(&info.session) {
                        let (tx, rx) = oneshot::channel::<()>();
                        epoch_change_nxt_tasks.insert(info.session.clone(), tx);
                        let cfg = epoch_change_nxt::RunConfig {
                            rpc_url: ec_rpc_url.clone(),
                            rpc_api_key: ec_rpc_api_key.clone(),
                            rpc_gas_key: ec_rpc_gas_key.clone(),
                            ace_contract: ace.clone(),
                            epoch_change_session: info.session.clone(),
                            account_addr: account_addr.clone(),
                            account_sk_hex: ec_account_sk_hex.clone(),
                            pke_dk_hex: ec_pke_dk_hex.clone(),
                        };
                        tokio::spawn(async move {
                            if let Err(e) = epoch_change_nxt::run(cfg, rx).await {
                                eprintln!("network-node: epoch-change-nxt error: {:#}", e);
                            }
                        });
                        println!("network-node: started epoch-change-nxt for session={}", info.session);
                    }
                } else {
                    stop_tasks(&mut epoch_change_nxt_tasks);
                }
            }
            None => {
                stop_tasks(&mut epoch_change_cur_tasks);
                stop_tasks(&mut epoch_change_nxt_tasks);
            }
        }

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
    }
}
