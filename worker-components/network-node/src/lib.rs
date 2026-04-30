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

/// ISO 8601 UTC timestamp with millisecond precision, e.g. `2026-04-30T16:53:26.877Z`.
pub fn now_utc_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d   = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let sec = d.as_secs();
    let ms  = d.subsec_millis();
    // civil_from_days: https://howardhinnant.github.io/date_algorithms.html
    let days = sec / 86400;
    let t    = sec % 86400;
    let (h, m, s) = (t / 3600, (t % 3600) / 60, t % 60);
    let z    = days as i64 + 719_468;
    let era  = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe  = (z - era * 146_097) as u64;
    let yoe  = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy  = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp   = (5 * doy + 2) / 153;
    let day  = doy - (153 * mp + 2) / 5 + 1;
    let mon  = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr   = yoe as i64 + era * 400 + if mon <= 2 { 1 } else { 0 };
    format!("{yr:04}-{mon:02}-{day:02}T{h:02}:{m:02}:{s:02}.{ms:03}Z")
}

/// Log a line to stderr with a UTC timestamp prefix.
#[macro_export]
macro_rules! wlog {
    ($($arg:tt)*) => { eprintln!("[{}] {}", $crate::now_utc_iso(), format_args!($($arg)*)) };
}

use anyhow::{anyhow, Result};
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

// ── BCS mirror of ace::network::StateViewV0 ─────────────────────────────────

#[allow(dead_code)]
#[derive(serde::Deserialize)]
struct BcsProposedEpochConfig {
    nodes: Vec<[u8; 32]>,
    threshold: u64,
    epoch_duration_micros: u64,
    secrets_to_retain: Vec<[u8; 32]>,
    new_secrets: Vec<u8>,
    description: String,
    target_epoch: u64,
}

#[allow(dead_code)]
#[derive(serde::Deserialize)]
struct BcsProposalView {
    proposal: BcsProposedEpochConfig,
    voting_session: [u8; 32],
    votes: Vec<bool>,
    voting_passed: bool,
}

#[derive(serde::Deserialize)]
struct BcsEpochChangeView {
    #[allow(dead_code)]
    triggering_proposal_idx: Option<u64>,
    session_addr: [u8; 32],
    nxt_nodes: Vec<[u8; 32]>,
    #[allow(dead_code)]
    nxt_threshold: u64,
}

#[allow(dead_code)]
#[derive(serde::Deserialize)]
struct BcsSecretInfo {
    current_session: [u8; 32],
    keypair_id: [u8; 32],
    scheme: u8,
}

#[derive(serde::Deserialize)]
struct BcsStateViewV0 {
    epoch: u64,
    epoch_start_time_micros: u64,
    epoch_duration_micros: u64,
    cur_nodes: Vec<[u8; 32]>,
    #[allow(dead_code)]
    cur_threshold: u64,
    secrets: Vec<BcsSecretInfo>,
    proposals: Vec<Option<BcsProposalView>>,
    epoch_change_info: Option<BcsEpochChangeView>,
}

fn addr_bytes_to_string(addr: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(addr))
}

async fn fetch_state_view_v0(rpc: &AptosRpc, ace: &str) -> Result<BcsStateViewV0> {
    let result = rpc
        .call_view(&format!("{}::network::state_view_v0_bcs", ace), &[])
        .await?;
    let hex = result
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("expected string in state_view_v0_bcs result"))?;
    let bytes = hex::decode(hex.trim_start_matches("0x"))?;
    bcs::from_bytes(&bytes).map_err(|e| anyhow!("bcs decode StateViewV0: {}", e))
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

    wlog!(
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
                    wlog!(
                        "network-node: cgroup memory limit {:.0} MiB → max_concurrent_requests={}",
                        limit as f64 / (1024.0 * 1024.0),
                        mc,
                    );
                    mc
                }
                None => {
                    wlog!(
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
                            wlog!(
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
                wlog!("network-node: shutdown signal received.");
                stop_tasks(&mut urh_tasks);
                stop_tasks(&mut epoch_change_cur_tasks);
                stop_tasks(&mut epoch_change_nxt_tasks);
                return Ok(());
            }
            _ = interval.tick() => {}
        }

        let state = match fetch_state_view_v0(&rpc, &ace).await {
            Ok(s) => s,
            Err(e) => {
                wlog!("network-node: fetch state view error: {:#}", e);
                continue;
            }
        };

        let in_cur_nodes = state.cur_nodes.iter().any(|n| addr_bytes_to_string(n) == account_addr);

        // Derive touch condition entirely from the view — no extra calls needed.
        let now_micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let epoch_timed_out =
            now_micros >= state.epoch_start_time_micros.saturating_add(state.epoch_duration_micros);
        let has_approved_proposal = state
            .proposals
            .iter()
            .any(|p| p.as_ref().is_some_and(|pv| pv.voting_passed));
        if state.epoch_change_info.is_some() || epoch_timed_out || has_approved_proposal {
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
                wlog!("network-node: network::touch error: {:#}", e);
            }
        }

        match &state.epoch_change_info {
            Some(info) => {
                let session = addr_bytes_to_string(&info.session_addr);

                // epoch-change-cur: cur_nodes drive DKR-src + touch.
                if in_cur_nodes {
                    if !epoch_change_cur_tasks.contains_key(&session) {
                        let (tx, rx) = oneshot::channel::<()>();
                        epoch_change_cur_tasks.insert(session.clone(), tx);
                        let cfg = epoch_change_cur::RunConfig {
                            rpc_url: ec_rpc_url.clone(),
                            rpc_api_key: ec_rpc_api_key.clone(),
                            rpc_gas_key: ec_rpc_gas_key.clone(),
                            ace_contract: ace.clone(),
                            epoch_change_session: session.clone(),
                            account_addr: account_addr.clone(),
                            account_sk_hex: ec_account_sk_hex.clone(),
                            pke_dk_hex: ec_pke_dk_hex.clone(),
                        };
                        tokio::spawn(async move {
                            if let Err(e) = epoch_change_cur::run(cfg, rx).await {
                                wlog!("network-node: epoch-change-cur error: {:#}", e);
                            }
                        });
                        wlog!("network-node: started epoch-change-cur for session={}", session);
                    }
                } else {
                    stop_tasks(&mut epoch_change_cur_tasks);
                }

                // epoch-change-nxt: nxt_nodes from the view — no extra RPC call needed.
                let in_nxt_nodes = info.nxt_nodes.iter().any(|n| addr_bytes_to_string(n) == account_addr);
                if in_nxt_nodes {
                    if !epoch_change_nxt_tasks.contains_key(&session) {
                        let (tx, rx) = oneshot::channel::<()>();
                        epoch_change_nxt_tasks.insert(session.clone(), tx);
                        let cfg = epoch_change_nxt::RunConfig {
                            rpc_url: ec_rpc_url.clone(),
                            rpc_api_key: ec_rpc_api_key.clone(),
                            rpc_gas_key: ec_rpc_gas_key.clone(),
                            ace_contract: ace.clone(),
                            epoch_change_session: session.clone(),
                            account_addr: account_addr.clone(),
                            account_sk_hex: ec_account_sk_hex.clone(),
                            pke_dk_hex: ec_pke_dk_hex.clone(),
                        };
                        tokio::spawn(async move {
                            if let Err(e) = epoch_change_nxt::run(cfg, rx).await {
                                wlog!("network-node: epoch-change-nxt error: {:#}", e);
                            }
                        });
                        wlog!("network-node: started epoch-change-nxt for session={}", session);
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
        *cur_nodes_shared.write().await =
            state.cur_nodes.iter().map(addr_bytes_to_string).collect();

        // ── URH (UserRequestHandler) tasks ─────────────────────────────────
        // For each session address in state.secrets, maintain a background task that:
        //   1. Reconstructs this node's Shamir scalar share.
        //   2. Inserts it into keypair_shares so the HTTP server can serve requests.
        //   3. Waits for shutdown, then removes it from keypair_shares.

        let active_secrets: HashSet<String> = if in_cur_nodes {
            state.secrets.iter().map(|s| addr_bytes_to_string(&s.current_session)).collect()
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
                        wlog!(
                            "network-node: [urh] registered keypair_id={} epoch={}",
                            keypair_id, epoch
                        );
                        let _ = rx.await;
                        // Defer removal by 30 s so clients who fetched the committee
                        // just before an epoch change can still be served.
                        let deadline = Instant::now() + Duration::from_secs(30);
                        expiry.lock().unwrap().push((deadline, keypair_id.clone(), epoch));
                        wlog!(
                            "network-node: [urh] scheduled eviction keypair_id={} epoch={} in 30s",
                            keypair_id, epoch
                        );
                    }
                    Err(e) => {
                        wlog!(
                            "network-node: [urh] reconstruct_share failed for {}: {:#}",
                            secret, e
                        );
                    }
                }
            });
            wlog!("network-node: started URH task for secret={}", secret_addr);
        }

        let stale_secrets: Vec<String> = urh_tasks
            .keys()
            .filter(|k| !active_secrets.contains(*k))
            .cloned()
            .collect();
        for k in stale_secrets {
            if let Some(tx) = urh_tasks.remove(&k) {
                let _ = tx.send(());
                wlog!("network-node: stopped URH task for secret={}", k);
            }
        }
    }
}
