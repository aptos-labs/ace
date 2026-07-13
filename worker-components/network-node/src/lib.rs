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
//!   monolith, but without the user request server. No user-request
//!   verification; no per-chain RPC config needed.
//! * `Handler`: user request handling only. No state polling, no URH, no chain
//!   account key. It reads reconstructed shares from the shared VSS DB using a
//!   background sync loop and serves `POST /`.
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
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let sec = d.as_secs();
    let ms = d.subsec_millis();
    let days = sec / 86400;
    let t = sec % 86400;
    let (h, m, s) = (t / 3600, (t % 3600) / 60, t % 60);
    let z = days as i64 + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let mon = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr = yoe as i64 + era * 400 + if mon <= 2 { 1 } else { 0 };
    format!("{yr:04}-{mon:02}-{day:02}T{h:02}:{m:02}:{s:02}.{ms:03}Z")
}

/// Log a line to stderr with a UTC timestamp prefix.
#[macro_export]
macro_rules! wlog {
    ($($arg:tt)*) => { eprintln!("[{}] {}", $crate::now_utc_iso(), format_args!($($arg)*)) };
}

use anyhow::{anyhow, Result};
use ark_bls12_381::Fr;
use ark_ff::{Field, Zero};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{oneshot, Semaphore};
use vss_common::crypto::fr_to_le_bytes;
use vss_common::group::{BcsElement, BcsScalar};
use vss_common::session::BcsPcsPublicParams;
use vss_common::vss_types::{opening_eval_value_p_fr, opening_eval_value_r_fr};
use vss_common::{
    normalize_account_addr, parse_ed25519_signing_key_hex, should_submit_rotating_touch, AptosRpc,
};
use vss_store::{connect_vss_store, read_verified_holder_opening, VssStore};

use crate::secrets::{LocalSecrets, SecretsProvider, ShareEntry, ShareEvictionQueue, ShareMap};

// ── Per-chain RPC configuration ──────────────────────────────────────────────

/// Pre-built RPC clients for all supported chains.
/// Clients are constructed once at startup and shared across all requests.
pub struct ChainRpcConfig {
    pub aptos_mainnet: AptosRpc,                     // chain_id=1
    pub aptos_testnet: AptosRpc,                     // chain_id=2
    pub aptos_localnet: AptosRpc,                    // chain_id=4
    pub aptos_shelby_private_beta: Option<AptosRpc>, // chain_id=139
}

impl ChainRpcConfig {
    pub fn aptos_rpc_for_chain_id(&self, chain_id: u8) -> Result<&AptosRpc> {
        match chain_id {
            1 => Ok(&self.aptos_mainnet),
            2 => Ok(&self.aptos_testnet),
            4 => Ok(&self.aptos_localnet),
            139 => self.aptos_shelby_private_beta.as_ref().ok_or_else(|| {
                anyhow!(
                    "no Aptos RPC configured for chain_id 139 (shelby-private-beta); \
                     set --aptos-shelby-private-beta-api"
                )
            }),
            _ => Err(anyhow!("no Aptos RPC configured for chain_id {}", chain_id)),
        }
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
    /// Secret maintenance only; no user-request HTTP server.
    Maintainer { maintainer: MaintainerConfig },
    /// Request handling only; syncs shares from the shared VSS DB.
    /// `pke_dk` is loaded directly from CLI.
    Handler {
        ace_deployment_api: String,
        ace_deployment_apikey: Option<String>,
        ace_deployment_addr: String,
        account_addr: String,
        vss_store_url: String,
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
    /// PKE decryption key (hex). Passed to monolith/handler for user-request
    /// decryption and kept with maintainer config for embedded protocol clients.
    pub pke_dk: String,
    /// Ed25519 node-to-node messaging signing key hex used by embedded VSS clients.
    pub sig_sk_hex: String,
    /// Persistent VSS store URL used by embedded VSS clients.
    pub vss_store_url: String,
    /// Local listen address for embedded node-to-node VSS share gateway.
    pub node_msg_listen: String,
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

#[allow(dead_code)]
#[derive(serde::Deserialize)]
struct BcsDkgSession {
    caller: [u8; 32],
    workers: Vec<[u8; 32]>,
    threshold: u64,
    scheme: u8,
    pcs_context: BcsPcsPublicParams,
    expected_usage: u64,
    note: String,
    state: u8,
    vss_sessions: Vec<[u8; 32]>,
    done_flags: Vec<bool>,
    commitment_points: Vec<BcsElement>,
    public_keys: Vec<BcsElement>,
}

#[allow(dead_code)]
#[derive(serde::Deserialize)]
struct BcsDkrSession {
    caller: [u8; 32],
    original_session: [u8; 32],
    previous_session: [u8; 32],
    expected_usage: u64,
    note: String,
    current_nodes: Vec<[u8; 32]>,
    current_threshold: u64,
    new_nodes: Vec<[u8; 32]>,
    new_threshold: u64,
    pcs_context: BcsPcsPublicParams,
    src_pcs_context: BcsPcsPublicParams,
    src_commitment_points: Vec<BcsElement>,
    src_public_keys: Vec<BcsElement>,
    state_code: u8,
    vss_sessions: Vec<[u8; 32]>,
    vss_contribution_flags: Vec<bool>,
    lagrange_coeffs_at_zero: Vec<BcsScalar>,
    commitment_points: Vec<BcsElement>,
    public_keys: Vec<BcsElement>,
}

struct ReconstructedShare {
    scalar_le32: [u8; 32],
    blinding_le32: [u8; 32],
    keypair_id: String,
    group_scheme: u8,
    pcs_context: BcsPcsPublicParams,
    share_commitment: BcsElement,
}

fn addr_bytes_to_string(addr: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(addr))
}

fn addr_string_to_bytes(addr: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(addr.trim_start_matches("0x"))?;
    raw.try_into()
        .map_err(|b: Vec<u8>| anyhow!("address has length {} (want 32)", b.len()))
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

async fn reconstruct_share_from_store(
    rpc: &AptosRpc,
    ace: &str,
    session_addr: &str,
    my_addr: &str,
    store: &dyn VssStore,
) -> Result<ReconstructedShare> {
    let session_addr = normalize_account_addr(session_addr);
    let my_addr = normalize_account_addr(my_addr);

    match fetch_dkr_session_bcs(rpc, ace, &session_addr).await {
        Ok(dkr_session) => reconstruct_from_dkr_store(rpc, ace, &dkr_session, &my_addr, store).await,
        Err(dkr_err) => match fetch_dkg_session_bcs(rpc, ace, &session_addr).await {
            Ok(dkg_session) => {
                reconstruct_from_dkg_store(rpc, ace, &session_addr, &dkg_session, &my_addr, store)
                    .await
            }
            Err(dkg_err) => Err(anyhow!(
                "not DKR and not DKG at {}: DKR get_session_bcs failed: {}; DKG get_session_bcs failed: {}",
                session_addr,
                dkr_err,
                dkg_err
            )),
        },
    }
}

async fn fetch_dkg_session_bcs(
    rpc: &AptosRpc,
    ace: &str,
    session_addr: &str,
) -> Result<BcsDkgSession> {
    let result = rpc
        .call_view(
            &format!("{}::dkg::get_session_bcs", ace),
            &[serde_json::json!(session_addr)],
        )
        .await?;
    let hex = result
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("expected string in dkg::get_session_bcs result"))?;
    let bytes = hex::decode(hex.trim_start_matches("0x"))?;
    bcs::from_bytes(&bytes).map_err(|e| anyhow!("bcs decode DKG Session: {}", e))
}

async fn fetch_dkr_session_bcs(
    rpc: &AptosRpc,
    ace: &str,
    session_addr: &str,
) -> Result<BcsDkrSession> {
    let result = rpc
        .call_view(
            &format!("{}::dkr::get_session_bcs", ace),
            &[serde_json::json!(session_addr)],
        )
        .await?;
    let hex = result
        .first()
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow!("expected string in dkr::get_session_bcs result"))?;
    let bytes = hex::decode(hex.trim_start_matches("0x"))?;
    bcs::from_bytes(&bytes).map_err(|e| anyhow!("bcs decode DKR Session: {}", e))
}

async fn reconstruct_from_dkg_store(
    rpc: &AptosRpc,
    ace: &str,
    session_addr: &str,
    dkg_session: &BcsDkgSession,
    my_addr: &str,
    store: &dyn VssStore,
) -> Result<ReconstructedShare> {
    let my_addr_bytes = addr_string_to_bytes(my_addr)?;
    let workers = &dkg_session.workers;
    let my_idx = workers
        .iter()
        .position(|n| n == &my_addr_bytes)
        .ok_or_else(|| anyhow!("my_addr {} not found in DKG workers", my_addr))?;

    let vss_sessions = dkg_session
        .vss_sessions
        .iter()
        .map(addr_bytes_to_string)
        .collect::<Vec<_>>();
    let done_flags = &dkg_session.done_flags;
    if vss_sessions.len() != done_flags.len() {
        return Err(anyhow!(
            "DKG vss_sessions.len()={} != done_flags.len()={}",
            vss_sessions.len(),
            done_flags.len()
        ));
    }

    let mut secret = Fr::zero();
    let mut blinding = Fr::zero();
    let mut group_scheme: Option<u8> = None;
    let mut num_contributions = 0usize;
    for (idx, vss_addr) in vss_sessions.iter().enumerate() {
        if !done_flags[idx] {
            continue;
        }
        let opening =
            read_verified_holder_opening(rpc, ace, store, vss_addr, my_idx as u64).await?;
        let expected_position = my_idx as u64 + 1;
        if opening.eval_position != expected_position {
            return Err(anyhow!(
                "holder opening position {} != expected {} for DKG {}",
                opening.eval_position,
                expected_position,
                session_addr
            ));
        }
        let scheme = opening.eval_value_p.scheme();
        if group_scheme
            .replace(scheme)
            .is_some_and(|existing| existing != scheme)
        {
            return Err(anyhow!("mixed VSS scalar schemes in DKG {}", session_addr));
        }
        secret += opening_eval_value_p_fr(&opening)?;
        blinding += opening_eval_value_r_fr(&opening)?;
        num_contributions += 1;
    }
    if num_contributions == 0 {
        return Err(anyhow!("no done VSS sessions in DKG {}", session_addr));
    }
    let scheme =
        group_scheme.ok_or_else(|| anyhow!("missing group scheme in DKG {}", session_addr))?;
    let share_commitment = dkg_session
        .commitment_points
        .get(my_idx + 1)
        .cloned()
        .ok_or_else(|| {
            anyhow!(
                "DKG commitment_points missing share commitment at index {} for {}",
                my_idx + 1,
                session_addr
            )
        })?;
    if share_commitment.scheme() != scheme {
        return Err(anyhow!(
            "DKG share commitment scheme {} != reconstructed share scheme {} for {}",
            share_commitment.scheme(),
            scheme,
            session_addr
        ));
    }
    Ok(ReconstructedShare {
        scalar_le32: fr_to_le_bytes(secret),
        blinding_le32: fr_to_le_bytes(blinding),
        keypair_id: session_addr.to_string(),
        group_scheme: scheme,
        pcs_context: dkg_session.pcs_context.clone(),
        share_commitment,
    })
}

async fn reconstruct_from_dkr_store(
    rpc: &AptosRpc,
    ace: &str,
    dkr_session: &BcsDkrSession,
    my_addr: &str,
    store: &dyn VssStore,
) -> Result<ReconstructedShare> {
    let original_session = addr_bytes_to_string(&dkr_session.original_session);
    let my_addr_bytes = addr_string_to_bytes(my_addr)?;
    let new_nodes = &dkr_session.new_nodes;
    let my_idx = new_nodes
        .iter()
        .position(|n| n == &my_addr_bytes)
        .ok_or_else(|| anyhow!("my_addr {} not found in DKR new_nodes", my_addr))?;

    let vss_sessions = dkr_session
        .vss_sessions
        .iter()
        .map(addr_bytes_to_string)
        .collect::<Vec<_>>();
    let vss_contribution_flags = &dkr_session.vss_contribution_flags;
    if vss_sessions.len() != vss_contribution_flags.len() {
        return Err(anyhow!(
            "DKR vss_sessions.len()={} != vss_contribution_flags.len()={}",
            vss_sessions.len(),
            vss_contribution_flags.len()
        ));
    }

    let mut secret_points = Vec::new();
    let mut blinding_points = Vec::new();
    let mut group_scheme: Option<u8> = None;
    for (idx, vss_addr) in vss_sessions.iter().enumerate() {
        if !vss_contribution_flags[idx] {
            continue;
        }
        let opening =
            read_verified_holder_opening(rpc, ace, store, vss_addr, my_idx as u64).await?;
        let expected_position = my_idx as u64 + 1;
        if opening.eval_position != expected_position {
            return Err(anyhow!(
                "holder opening position {} != expected {} for DKR VSS {}",
                opening.eval_position,
                expected_position,
                vss_addr
            ));
        }
        let scheme = opening.eval_value_p.scheme();
        if group_scheme
            .replace(scheme)
            .is_some_and(|existing| existing != scheme)
        {
            return Err(anyhow!(
                "mixed VSS scalar schemes in DKR original_session={}",
                original_session
            ));
        }
        let old_eval_position = idx as u64 + 1;
        secret_points.push((old_eval_position, opening_eval_value_p_fr(&opening)?));
        blinding_points.push((old_eval_position, opening_eval_value_r_fr(&opening)?));
    }
    if secret_points.is_empty() {
        return Err(anyhow!(
            "no contributing VSS sessions in DKR {}",
            original_session
        ));
    }
    let scheme =
        group_scheme.ok_or_else(|| anyhow!("missing group scheme in DKR {}", original_session))?;
    let share_commitment = dkr_session
        .commitment_points
        .get(my_idx + 1)
        .cloned()
        .ok_or_else(|| {
            anyhow!(
                "DKR commitment_points missing share commitment at index {} for original_session={}",
                my_idx + 1,
                original_session
            )
        })?;
    if share_commitment.scheme() != scheme {
        return Err(anyhow!(
            "DKR share commitment scheme {} != reconstructed share scheme {} for original_session={}",
            share_commitment.scheme(),
            scheme,
            original_session
        ));
    }
    Ok(ReconstructedShare {
        scalar_le32: fr_to_le_bytes(lagrange_at_zero(&secret_points)?),
        blinding_le32: fr_to_le_bytes(lagrange_at_zero(&blinding_points)?),
        keypair_id: original_session,
        group_scheme: scheme,
        pcs_context: dkr_session.pcs_context.clone(),
        share_commitment,
    })
}

fn lagrange_at_zero(points: &[(u64, Fr)]) -> Result<Fr> {
    if points.is_empty() {
        return Err(anyhow!("lagrange_at_zero: no points"));
    }
    let mut acc = Fr::zero();
    for (i, (x_i_raw, y_i)) in points.iter().enumerate() {
        let x_i = Fr::from(*x_i_raw);
        let mut numerator = Fr::from(1u64);
        let mut denominator = Fr::from(1u64);
        for (j, (x_j_raw, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            let x_j = Fr::from(*x_j_raw);
            numerator *= -x_j;
            denominator *= x_i - x_j;
        }
        let denominator_inv = denominator
            .inverse()
            .ok_or_else(|| anyhow!("duplicate interpolation point {}", x_i_raw))?;
        acc += *y_i * numerator * denominator_inv;
    }
    Ok(acc)
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
        Mode::Monolith {
            maintainer,
            handler,
        } => run_with_maintainer(maintainer, handler, shutdown_rx).await,
        Mode::Maintainer { maintainer } => run_with_maintainer(maintainer, None, shutdown_rx).await,
        Mode::Handler {
            ace_deployment_api,
            ace_deployment_apikey,
            ace_deployment_addr,
            account_addr,
            vss_store_url,
            pke_dk,
            port,
            chain_rpc,
            max_concurrent,
        } => {
            run_handler(
                ace_deployment_api,
                ace_deployment_apikey,
                ace_deployment_addr,
                account_addr,
                vss_store_url,
                pke_dk,
                port,
                chain_rpc,
                max_concurrent,
                shutdown_rx,
            )
            .await
        }
    }
}

// ── Maintainer / monolith ─────────────────────────────────────────────────────

async fn run_with_maintainer(
    config: MaintainerConfig,
    handler_local: Option<HandlerLocalConfig>,
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
    let ec_sig_sk_hex = config.sig_sk_hex.clone();
    let ec_vss_store_url = config.vss_store_url.clone();
    let ec_node_msg_listen = config.node_msg_listen.clone();
    let vss_store = connect_vss_store(&config.vss_store_url)?;

    wlog!(
        "network-node: starting (account={} ace={})",
        account_addr,
        ace
    );

    let local = LocalSecrets::empty();
    let expiry_queue = ShareEvictionQueue::new(local.clone());

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

    expiry_queue.spawn_cleanup_task(Duration::from_secs(5));

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
        let epoch_timed_out = now_micros
            >= state
                .epoch_start_time_micros
                .saturating_add(state.epoch_duration_micros);
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
                            sig_sk_hex: ec_sig_sk_hex.clone(),
                            vss_store_url: ec_vss_store_url.clone(),
                            node_msg_listen: ec_node_msg_listen.clone(),
                        };
                        tokio::spawn(async move {
                            if let Err(e) = epoch_change_cur::run(cfg, rx).await {
                                wlog!("network-node: epoch-change-cur error: {:#}", e);
                            }
                        });
                        wlog!(
                            "network-node: started epoch-change-cur for session={}",
                            session
                        );
                    }
                } else {
                    stop_tasks(&mut epoch_change_cur_tasks);
                }

                let in_nxt_nodes = info
                    .nxt_nodes
                    .iter()
                    .any(|n| addr_bytes_to_string(n) == account_addr);
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
                            sig_sk_hex: ec_sig_sk_hex.clone(),
                            vss_store_url: ec_vss_store_url.clone(),
                            node_msg_listen: ec_node_msg_listen.clone(),
                        };
                        tokio::spawn(async move {
                            if let Err(e) = epoch_change_nxt::run(cfg, rx).await {
                                wlog!("network-node: epoch-change-nxt error: {:#}", e);
                            }
                        });
                        wlog!(
                            "network-node: started epoch-change-nxt for session={}",
                            session
                        );
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
            let my = account_addr.clone();
            let local2 = local.clone();
            let expiry = expiry_queue.clone();
            let store = vss_store.clone();
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
                match reconstruct_share_from_store(&rpc2, &ace2, &secret, &my, store.as_ref()).await
                {
                    Ok(reconstructed) => {
                        // Maintainer stores the raw share material plus
                        // on-chain usage policy; handler derives
                        // application-layer shares from the snapshot.
                        let keypair_id = reconstructed.keypair_id.clone();
                        let group_scheme = reconstructed.group_scheme;
                        local2
                            .insert_share(
                                keypair_id.clone(),
                                epoch,
                                ShareEntry {
                                    scalar_le32: reconstructed.scalar_le32,
                                    blinding_le32: reconstructed.blinding_le32,
                                    group_scheme,
                                    pcs_context: reconstructed.pcs_context,
                                    share_commitment: reconstructed.share_commitment,
                                    expected_usage,
                                    eval_point,
                                    note,
                                },
                            )
                            .await;
                        wlog!(
                            "network-node: [urh] registered keypair_id={} epoch={} group_scheme={} expected_usage={} eval_point={}",
                            keypair_id, epoch, group_scheme, expected_usage, eval_point
                        );
                        let _ = rx.await;
                        expiry.schedule_after(keypair_id.clone(), epoch, Duration::from_secs(30));
                        wlog!(
                            "network-node: [urh] scheduled eviction keypair_id={} epoch={} in 30s",
                            keypair_id,
                            epoch
                        );
                    }
                    Err(e) => {
                        wlog!(
                            "network-node: [urh] reconstruct_share failed for {}: {:#}",
                            secret,
                            e
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
    ace_deployment_api: String,
    ace_deployment_apikey: Option<String>,
    ace_deployment_addr: String,
    account_addr: String,
    vss_store_url: String,
    pke_dk: String,
    port: u16,
    chain_rpc: ChainRpcConfig,
    max_concurrent: Option<usize>,
    shutdown_rx: oneshot::Receiver<()>,
) -> Result<()> {
    wlog!(
        "network-node: starting handler-only (account={} ace={} store={})",
        normalize_account_addr(&account_addr),
        normalize_account_addr(&ace_deployment_addr),
        vss_store_url
    );
    let pke_dk_bytes: Arc<Vec<u8>> = {
        let raw = pke_dk.trim().trim_start_matches("0x");
        Arc::new(hex::decode(raw).map_err(|e| anyhow::anyhow!("pke_dk decode: {}", e))?)
    };
    let rpc = AptosRpc::new_with_key(ace_deployment_api, ace_deployment_apikey);
    let ace = normalize_account_addr(&ace_deployment_addr);
    let account_addr = normalize_account_addr(&account_addr);
    let store = connect_vss_store(&vss_store_url)?;
    let local = LocalSecrets::empty();

    tokio::spawn(handler_store_sync_loop(
        rpc,
        ace,
        account_addr,
        store,
        local.clone(),
    ));

    let state = http_server::AppState {
        provider: Arc::new(SecretsProvider::Local(local)),
        chain_rpc: Arc::new(chain_rpc),
        concurrency: Arc::new(Semaphore::new(resolve_max_concurrent(max_concurrent))),
        pke_dk_bytes,
    };
    tokio::spawn(http_server::run_user_server(port, state));
    let _ = shutdown_rx.await;
    wlog!("network-node: handler shutdown signal received.");
    Ok(())
}

async fn handler_store_sync_loop(
    rpc: AptosRpc,
    ace: String,
    account_addr: String,
    store: Arc<dyn VssStore>,
    local: LocalSecrets,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        interval.tick().await;
        if let Err(e) =
            handler_store_sync_once(&rpc, &ace, &account_addr, store.as_ref(), &local).await
        {
            wlog!("network-node: handler DB share sync error: {:#}", e);
        }
    }
}

async fn handler_store_sync_once(
    rpc: &AptosRpc,
    ace: &str,
    account_addr: &str,
    store: &dyn VssStore,
    local: &LocalSecrets,
) -> Result<()> {
    let state = fetch_state_view_v0(rpc, ace).await?;
    let my_eval_point = match state
        .cur_nodes
        .iter()
        .position(|n| addr_bytes_to_string(n) == account_addr)
    {
        Some(idx) => (idx + 1) as u64,
        None => {
            local.clear().await;
            return Ok(());
        }
    };

    let mut refreshed = ShareMap::new();
    for secret in &state.secrets {
        let session_addr = addr_bytes_to_string(&secret.current_session);
        let reconstructed =
            reconstruct_share_from_store(rpc, ace, &session_addr, account_addr, store).await?;
        let keypair_id = reconstructed.keypair_id.clone();
        refreshed.insert(
            (keypair_id, state.epoch),
            ShareEntry {
                scalar_le32: reconstructed.scalar_le32,
                blinding_le32: reconstructed.blinding_le32,
                group_scheme: reconstructed.group_scheme,
                pcs_context: reconstructed.pcs_context,
                share_commitment: reconstructed.share_commitment,
                expected_usage: secret.expected_usage,
                eval_point: my_eval_point,
                note: secret.note.clone(),
            },
        );
    }

    let min_epoch_to_keep = state.epoch.saturating_sub(1);
    local.replace_since(min_epoch_to_keep, refreshed).await;
    Ok(())
}
