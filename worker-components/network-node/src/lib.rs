// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Supervisor for one worker.
//!
//! Three deployment modes:
//!
//! * `Monolith` (default, backwards-compatible): one process does **both** secret
//!   maintenance (URH share reconstruction, `network::touch`, epoch-change-cur/nxt)
//!   and user request handling (`POST /` on `port`).
//! * `Maintainer`: secret maintenance only. Same URH/touch/epoch-change loop as
//!   monolith, but the HTTP surface is **`GET /secrets`** (current + previous
//!   epoch shares, with `eval_point` baked in) instead of `POST /`. No
//!   user-request verification; no chain-RPC config needed.
//! * `Handler`: user request handling only. No state polling, no URH, no chain
//!   account or PKE key. Fetches the secrets snapshot from a peer maintainer's
//!   `/secrets` on demand with a 1-second singleflight cache.
//!
//! The split lets the maintainer remain a `min/max=1` singleton (it owns the
//! on-chain DKR ordering invariant) while handlers scale out horizontally
//! behind a load balancer.

pub mod crypto;
mod http_server;
mod secret_usage;
pub mod secrets;
pub mod verify;

/// ISO 8601 UTC timestamp with millisecond precision, e.g. `2026-04-30T16:53:26.877Z`.
pub fn now_utc_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d   = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let sec = d.as_secs();
    let ms  = d.subsec_millis();
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
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{oneshot, RwLock, Semaphore};
use vss_common::{
    normalize_account_addr, parse_ed25519_signing_key_hex, should_submit_rotating_touch, AptosRpc,
};

use crate::secrets::{LocalSecrets, RemoteSecrets, SecretsProvider, ShareEntry};

// ── Per-chain RPC configuration ──────────────────────────────────────────────

/// Pre-built RPC clients for all supported chains.
/// Clients are constructed once at startup and shared across all requests.
pub struct ChainRpcConfig {
    pub aptos_mainnet: AptosRpc,                     // chain_id=1
    pub aptos_testnet: AptosRpc,                     // chain_id=2
    pub aptos_localnet: AptosRpc,                    // chain_id=4
    pub aptos_shelby_private_beta: Option<AptosRpc>, // chain_id=125
    pub solana_mainnet_beta: String,
    pub solana_testnet: String,
    pub solana_devnet: String,
    pub solana_client: reqwest::Client,
}

impl ChainRpcConfig {
    pub fn aptos_rpc_for_chain_id(&self, chain_id: u8) -> Result<&AptosRpc> {
        match chain_id {
            1 => Ok(&self.aptos_mainnet),
            2 => Ok(&self.aptos_testnet),
            4 => Ok(&self.aptos_localnet),
            125 => self.aptos_shelby_private_beta.as_ref().ok_or_else(|| {
                anyhow!(
                    "no Aptos RPC configured for chain_id 125 (shelby-private-beta); \
                     set --aptos-shelby-private-beta-api"
                )
            }),
            _ => Err(anyhow!("no Aptos RPC configured for chain_id {}", chain_id)),
        }
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

fn read_cgroup_memory_limit() -> Option<usize> {
    if let Ok(s) = std::fs::read_to_string("/sys/fs/cgroup/memory.max") {
        let s = s.trim();
        if s != "max" {
            if let Ok(n) = s.parse::<usize>() {
                return Some(n);
            }
        }
        return None;
    }
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

fn resolve_max_concurrent(explicit: Option<usize>) -> usize {
    const DEFAULT_MAX_CONCURRENT: usize = 100;
    explicit.unwrap_or_else(|| match read_cgroup_memory_limit() {
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
    })
}

// ── Top-level run configuration ───────────────────────────────────────────────

/// Deployment mode. See module-level docs.
pub enum Mode {
    /// One process does everything (default; backwards-compatible).
    /// `handler` is `None` for chain-touching-only deployments that don't
    /// serve user requests (e.g. test setups exercising DKG only).
    Monolith {
        maintainer: MaintainerConfig,
        handler: Option<HandlerLocalConfig>,
    },
    /// Secret maintenance only; serves `GET /secrets` on `port`.
    Maintainer {
        maintainer: MaintainerConfig,
        port: u16,
    },
    /// Request handling only; pulls secrets from a peer maintainer.
    /// `pke_dk` is loaded directly from CLI — it never crosses the wire.
    Handler {
        maintainer_url: String,
        pke_dk: String,
        port: u16,
        chain_rpc: ChainRpcConfig,
        max_concurrent: Option<usize>,
    },
}

/// Fields needed for secret maintenance (URH + on-chain DKR/touch).
pub struct MaintainerConfig {
    pub ace_deployment_api: String,
    pub ace_deployment_apikey: Option<String>,
    pub ace_deployment_gaskey: Option<String>,
    pub ace_deployment_addr: String,
    pub account_addr: String,
    pub account_sk_hex: String,
    /// PKE decryption key (hex). Held here by maintainer (needed for VSS
    /// share decryption during DKR/URH); also passed to monolith/handler
    /// for user-request decryption. Never crosses the `/secrets` wire.
    pub pke_dk: String,
}

/// Fields needed for the user-request HTTP server when running in the same
/// process as the maintainer (monolith only).
pub struct HandlerLocalConfig {
    pub port: u16,
    pub chain_rpc: ChainRpcConfig,
    pub max_concurrent: Option<usize>,
}

// ── BCS mirror of ace::network::StateViewV0 ─────────────────────────────────

#[allow(dead_code)]
#[derive(serde::Deserialize)]
struct BcsSecretRequest {
    expected_usage: u64,
    note: String,
}

#[allow(dead_code)]
#[derive(serde::Deserialize)]
struct BcsProposedEpochConfig {
    nodes: Vec<[u8; 32]>,
    threshold: u64,
    epoch_duration_micros: u64,
    secrets_to_retain: Vec<[u8; 32]>,
    new_secrets: Vec<BcsSecretRequest>,
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
    expected_usage: u64,
    note: String,
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

fn stop_tasks(tasks: &mut HashMap<String, oneshot::Sender<()>>) {
    for (_, tx) in tasks.drain() {
        let _ = tx.send(());
    }
}

// ── Dispatch ─────────────────────────────────────────────────────────────────

pub async fn run(mode: Mode, shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
    match mode {
        Mode::Monolith { maintainer, handler } => {
            run_with_maintainer(maintainer, handler, None, shutdown_rx).await
        }
        Mode::Maintainer { maintainer, port } => {
            run_with_maintainer(maintainer, None, Some(port), shutdown_rx).await
        }
        Mode::Handler {
            maintainer_url,
            pke_dk,
            port,
            chain_rpc,
            max_concurrent,
        } => run_handler(maintainer_url, pke_dk, port, chain_rpc, max_concurrent, shutdown_rx).await,
    }
}

// ── Maintainer / monolith ─────────────────────────────────────────────────────

async fn run_with_maintainer(
    config: MaintainerConfig,
    handler_local: Option<HandlerLocalConfig>,
    secrets_server_port: Option<u16>,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> Result<()> {
    let rpc = AptosRpc::new_with_gas_key(
        config.ace_deployment_api.clone(),
        config.ace_deployment_apikey.clone(),
        config.ace_deployment_gaskey.clone(),
    );
    let sk = parse_ed25519_signing_key_hex(&config.account_sk_hex)?;
    let vk = sk.verifying_key();
    let account_addr = normalize_account_addr(&config.account_addr);
    let ace = normalize_account_addr(&config.ace_deployment_addr);

    let pke_dk_bytes: Arc<Vec<u8>> = {
        let raw = config.pke_dk.trim().trim_start_matches("0x");
        Arc::new(hex::decode(raw).map_err(|e| anyhow::anyhow!("pke_dk decode: {}", e))?)
    };

    let ec_rpc_url = config.ace_deployment_api.clone();
    let ec_rpc_api_key = config.ace_deployment_apikey.clone();
    let ec_rpc_gas_key = config.ace_deployment_gaskey.clone();
    let ec_account_sk_hex = config.account_sk_hex.clone();
    let ec_pke_dk_hex = config.pke_dk.clone();

    wlog!(
        "network-node: starting (account={} ace={})",
        account_addr, ace
    );

    // `(keypair_id, epoch) → ShareEntry` — flat map, one lookup per request.
    // `eval_point`, `group_scheme`, and `expected_usage` are captured per-entry at URH
    // registration time so stale buffer-window entries from a previous epoch
    // use the right values even after committee membership changes.
    //
    // No separate "am I in the committee" flag: an empty map already means
    // "nothing to serve" (whether because the node is genuinely not in
    // `cur_nodes` or because URH hasn't completed yet). The handler returns
    // NotFound on lookup miss either way.
    let shares: Arc<RwLock<HashMap<(String, u64), ShareEntry>>> =
        Arc::new(RwLock::new(HashMap::new()));

    let expiry_queue: Arc<Mutex<Vec<(Instant, String, u64)>>> =
        Arc::new(Mutex::new(Vec::new()));

    let local = LocalSecrets { shares: shares.clone() };

    // Optional user-request server (monolith only).
    if let Some(h) = handler_local {
        let max_concurrent = resolve_max_concurrent(h.max_concurrent);
        let state = http_server::AppState {
            provider: Arc::new(SecretsProvider::Local(local.clone())),
            chain_rpc: Arc::new(h.chain_rpc),
            concurrency: Arc::new(Semaphore::new(max_concurrent)),
            pke_dk_bytes: pke_dk_bytes.clone(),
        };
        tokio::spawn(http_server::run_user_server(h.port, state));
    }

    // Optional secrets server (maintainer mode).
    if let Some(port) = secrets_server_port {
        let state = http_server::SecretsServerState { local: local.clone() };
        tokio::spawn(http_server::run_secrets_server(port, state));
    }

    // Share cleanup timer.
    {
        let s = shares.clone();
        let eq = expiry_queue.clone();
        tokio::spawn(async move {
            let mut ticker = tokio::time::interval(tokio::time::Duration::from_secs(5));
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
                    let mut w = s.write().await;
                    for (keypair_id, epoch) in expired {
                        if w.remove(&(keypair_id.clone(), epoch)).is_some() {
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

        let cur_node_idx = state
            .cur_nodes
            .iter()
            .position(|n| addr_bytes_to_string(n) == account_addr);
        let in_cur_nodes = cur_node_idx.is_some();

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
        if (state.epoch_change_info.is_some() || epoch_timed_out || has_approved_proposal)
            && cur_node_idx
                .map(|idx| should_submit_rotating_touch(idx, state.cur_nodes.len()))
                .unwrap_or(false)
        {
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

        // This node's eval_point (1-based position) at the current epoch.
        // URH stores it alongside each share so the handler doesn't have to
        // re-derive committee state.
        let my_eval_point: Option<u64> = state
            .cur_nodes
            .iter()
            .position(|n| addr_bytes_to_string(n) == account_addr)
            .map(|i| (i + 1) as u64);

        let active_secrets: HashMap<String, (u64, String)> = if in_cur_nodes {
            state
                .secrets
                .iter()
                .map(|s| {
                    (
                        addr_bytes_to_string(&s.current_session),
                        (s.expected_usage, s.note.clone()),
                    )
                })
                .collect()
        } else {
            HashMap::new()
        };

        for (secret_addr, (expected_usage, note)) in &active_secrets {
            if urh_tasks.contains_key(secret_addr) {
                continue;
            }
            let (tx, rx) = oneshot::channel::<()>();
            urh_tasks.insert(secret_addr.clone(), tx);

            let rpc2 = rpc.clone();
            let ace2 = ace.clone();
            let secret = secret_addr.clone();
            let pke_dk = (*pke_dk_bytes).clone();
            let my = account_addr.clone();
            let shares2 = shares.clone();
            let expiry = expiry_queue.clone();
            let epoch = state.epoch;
            let expected_usage = *expected_usage;
            let note = note.clone();
            // eval_point at the time this share is being registered — sourced from
            // the just-observed `cur_nodes`. Stored with the share so future
            // requests (including stale-buffer-window ones after a committee
            // change) use the correct value.
            let eval_point = match my_eval_point {
                Some(e) => e,
                None => {
                    // Should not happen — we only enter this block when
                    // `in_cur_nodes` is true. Belt-and-suspenders.
                    wlog!(
                        "network-node: [urh] {} unexpected: in_cur_nodes but no eval_point",
                        secret_addr
                    );
                    continue;
                }
            };

            tokio::spawn(async move {
                match vss_common::reconstruct_share(&rpc2, &ace2, &secret, &my, &pke_dk).await {
                    Ok((scalar_le32, keypair_id, group_scheme)) => {
                        // Maintainer stays out of the t-IBE business — store the
                        // raw group_scheme plus on-chain usage policy; handler
                        // validates the request's primitive before deriving.
                        shares2.write().await.insert(
                            (keypair_id.clone(), epoch),
                            ShareEntry {
                                scalar_le32,
                                group_scheme,
                                expected_usage,
                                eval_point,
                                note,
                            },
                        );
                        wlog!(
                            "network-node: [urh] registered keypair_id={} epoch={} group_scheme={} expected_usage={} eval_point={}",
                            keypair_id, epoch, group_scheme, expected_usage, eval_point
                        );
                        let _ = rx.await;
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
            .filter(|k| !active_secrets.contains_key(*k))
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

// ── Handler-only ─────────────────────────────────────────────────────────────

async fn run_handler(
    maintainer_url: String,
    pke_dk: String,
    port: u16,
    chain_rpc: ChainRpcConfig,
    max_concurrent: Option<usize>,
    shutdown_rx: oneshot::Receiver<()>,
) -> Result<()> {
    wlog!(
        "network-node: starting handler-only (maintainer_url={})",
        maintainer_url
    );
    let pke_dk_bytes: Arc<Vec<u8>> = {
        let raw = pke_dk.trim().trim_start_matches("0x");
        Arc::new(hex::decode(raw).map_err(|e| anyhow::anyhow!("pke_dk decode: {}", e))?)
    };
    let remote = Arc::new(RemoteSecrets::new(maintainer_url));
    let state = http_server::AppState {
        provider: Arc::new(SecretsProvider::Remote(remote)),
        chain_rpc: Arc::new(chain_rpc),
        concurrency: Arc::new(Semaphore::new(resolve_max_concurrent(max_concurrent))),
        pke_dk_bytes,
    };
    tokio::spawn(http_server::run_user_server(port, state));
    let _ = shutdown_rx.await;
    wlog!("network-node: handler shutdown signal received.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rpc(label: &str) -> AptosRpc {
        AptosRpc::new(format!("https://{}.example/v1", label))
    }

    fn chain_rpc_config() -> ChainRpcConfig {
        ChainRpcConfig {
            aptos_mainnet: rpc("mainnet"),
            aptos_testnet: rpc("testnet"),
            aptos_localnet: rpc("localnet"),
            aptos_shelby_private_beta: Some(rpc("shelby")),
            solana_mainnet_beta: "https://solana-mainnet.example".to_string(),
            solana_testnet: "https://solana-testnet.example".to_string(),
            solana_devnet: "https://solana-devnet.example".to_string(),
            solana_client: reqwest::Client::new(),
        }
    }

    #[test]
    fn shelby_private_beta_uses_chain_id_125() {
        let cfg = chain_rpc_config();
        assert_eq!(
            cfg.aptos_rpc_for_chain_id(125).unwrap().base_url,
            "https://shelby.example/v1"
        );
        assert!(cfg.aptos_rpc_for_chain_id(139).is_err());
    }
}
