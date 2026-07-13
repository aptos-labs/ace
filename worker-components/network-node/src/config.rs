// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use vss_common::AptosRpc;

use crate::wlog;

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

pub(crate) fn resolve_max_concurrent(explicit: Option<usize>) -> usize {
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
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeMode {
    /// One process drives protocol progress and optionally serves user requests.
    Monolith,
    /// Secret maintenance only; no user-request HTTP server.
    Maintainer,
    /// Request handling only; syncs shares from the shared VSS DB.
    Handler,
}

/// Single runtime config. Some fields are mode-specific and intentionally unused
/// by other modes, so CLI/env/config-file plumbing can stay uniform.
pub struct RunConfig {
    pub mode: RuntimeMode,
    pub ace_deployment_api: String,
    pub ace_deployment_apikey: Option<String>,
    pub ace_deployment_gaskey: Option<String>,
    pub ace_deployment_addr: String,
    pub account_addr: String,
    pub account_sk_hex: String,
    pub pke_dk: String,
    pub sig_sk_hex: String,
    pub vss_store_url: String,
    pub port: Option<u16>,
    pub chain_rpc: Option<ChainRpcConfig>,
    pub max_concurrent: Option<usize>,
}
