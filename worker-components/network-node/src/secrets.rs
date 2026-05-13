// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Secrets provider abstraction for the three deployment modes.
//!
//! * `Monolith`/`Maintainer` use [`SecretsProvider::Local`], which reads directly
//!   from the in-process keypair-share map and `cur_nodes` list that the URH /
//!   state-polling loop populates.
//! * `Handler` uses [`SecretsProvider::Remote`], which polls a maintainer's
//!   `/secrets` endpoint and caches the snapshot for 1 second (singleflight via
//!   an async mutex). Concurrent stale requests collapse onto a single fetch.
//!
//! The on-the-wire payload is JSON: see [`SecretsSnapshotWire`].

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

/// JSON wire format returned by the maintainer's `GET /secrets` endpoint.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecretsSnapshotWire {
    pub schema_version: u32,
    pub my_addr: String,
    /// `0x`-prefixed hex of the PKE decryption key bytes.
    pub pke_dk_hex: String,
    /// 1-based position of `my_addr` in the current committee, or `None`
    /// when this node is not in `cur_nodes`. Carried in the snapshot so
    /// the handler doesn't need its own view of the committee.
    pub eval_point: Option<u64>,
    pub epochs: Vec<EpochSecretsWire>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct EpochSecretsWire {
    pub epoch: u64,
    pub shares: Vec<ShareWire>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShareWire {
    pub keypair_id: String,
    /// 32-byte BLS scalar (little-endian), `0x`-prefixed hex.
    pub scalar_le32_hex: String,
    pub tibe_scheme: u8,
}

pub const SCHEMA_VERSION: u32 = 1;

/// Parsed, in-memory form of a snapshot. Both providers return references to
/// this same shape so the HTTP handler doesn't care where it came from.
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub pke_dk_bytes: Arc<Vec<u8>>,
    pub eval_point: Option<u64>,
    /// keypair_id → epoch → (scalar_le32, tibe_scheme).
    pub by_keypair_epoch: Arc<HashMap<String, HashMap<u64, ([u8; 32], u8)>>>,
}

impl Snapshot {
    pub fn lookup(&self, keypair_id: &str, epoch: u64) -> Option<([u8; 32], u8)> {
        self.by_keypair_epoch
            .get(keypair_id)
            .and_then(|by_epoch| by_epoch.get(&epoch))
            .copied()
    }
}

// ── Local provider (monolith + maintainer) ───────────────────────────────────

#[derive(Clone)]
pub struct LocalSecrets {
    pub keypair_shares:
        Arc<RwLock<HashMap<String, HashMap<u64, ([u8; 32], u8)>>>>,
    pub cur_nodes: Arc<RwLock<Vec<String>>>,
    pub my_addr: String,
    pub pke_dk_bytes: Arc<Vec<u8>>,
}

impl LocalSecrets {
    /// Build a fresh snapshot from the live in-process state. Cheap — the
    /// share map is typically <10 entries.
    pub async fn snapshot(&self) -> Snapshot {
        let eval_point = {
            let nodes = self.cur_nodes.read().await;
            nodes
                .iter()
                .position(|n| n == &self.my_addr)
                .map(|i| (i + 1) as u64)
        };
        let by_keypair_epoch = {
            let shares = self.keypair_shares.read().await;
            Arc::new(shares.clone())
        };
        Snapshot {
            pke_dk_bytes: self.pke_dk_bytes.clone(),
            eval_point,
            by_keypair_epoch,
        }
    }

    /// JSON wire snapshot for serving `/secrets`.
    pub async fn snapshot_wire(&self) -> SecretsSnapshotWire {
        let s = self.snapshot().await;
        let epochs_acc: HashMap<u64, Vec<ShareWire>> =
            s.by_keypair_epoch
                .iter()
                .flat_map(|(kp_id, by_epoch)| {
                    by_epoch.iter().map(move |(epoch, (scalar, scheme))| {
                        (
                            *epoch,
                            ShareWire {
                                keypair_id: kp_id.clone(),
                                scalar_le32_hex: format!("0x{}", hex::encode(scalar)),
                                tibe_scheme: *scheme,
                            },
                        )
                    })
                })
                .fold(HashMap::new(), |mut acc, (e, w)| {
                    acc.entry(e).or_default().push(w);
                    acc
                });
        let mut epochs: Vec<EpochSecretsWire> = epochs_acc
            .into_iter()
            .map(|(epoch, shares)| EpochSecretsWire { epoch, shares })
            .collect();
        epochs.sort_by_key(|e| e.epoch);
        SecretsSnapshotWire {
            schema_version: SCHEMA_VERSION,
            my_addr: self.my_addr.clone(),
            pke_dk_hex: format!("0x{}", hex::encode(s.pke_dk_bytes.as_ref())),
            eval_point: s.eval_point,
            epochs,
        }
    }
}

// ── Remote provider (handler) ────────────────────────────────────────────────

/// Singleflight 1-second TTL cache over `GET {s0_url}`.
pub struct RemoteSecrets {
    s0_url: String,
    s0_auth: Option<String>,
    client: reqwest::Client,
    state: RwLock<Option<(Arc<Snapshot>, Instant)>>,
    refresh: Mutex<()>,
    ttl: Duration,
}

impl RemoteSecrets {
    pub fn new(s0_url: String, s0_auth: Option<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build reqwest client for RemoteSecrets");
        Self {
            s0_url,
            s0_auth,
            client,
            state: RwLock::new(None),
            refresh: Mutex::new(()),
            ttl: Duration::from_secs(1),
        }
    }

    /// Test-only constructor with a custom TTL.
    #[cfg(test)]
    pub fn with_ttl(s0_url: String, ttl: Duration) -> Self {
        let client = reqwest::Client::builder().build().unwrap();
        Self {
            s0_url,
            s0_auth: None,
            client,
            state: RwLock::new(None),
            refresh: Mutex::new(()),
            ttl,
        }
    }

    pub async fn snapshot(&self) -> Result<Arc<Snapshot>> {
        // Fast path: return cached if still fresh.
        if let Some((snap, at)) = self.state.read().await.as_ref() {
            if at.elapsed() < self.ttl {
                return Ok(snap.clone());
            }
        }
        // Slow path: acquire refresh mutex, re-check, fetch.
        let _g = self.refresh.lock().await;
        if let Some((snap, at)) = self.state.read().await.as_ref() {
            if at.elapsed() < self.ttl {
                return Ok(snap.clone());
            }
        }
        let fresh = Arc::new(self.fetch().await?);
        *self.state.write().await = Some((fresh.clone(), Instant::now()));
        Ok(fresh)
    }

    async fn fetch(&self) -> Result<Snapshot> {
        let mut req = self.client.get(&self.s0_url);
        if let Some(token) = &self.s0_auth {
            req = req.bearer_auth(token);
        }
        let resp = req
            .send()
            .await
            .with_context(|| format!("GET {} failed", self.s0_url))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!("GET {} returned {}: {}", self.s0_url, status, body));
        }
        let wire: SecretsSnapshotWire = resp.json().await.context("decode SecretsSnapshotWire")?;
        if wire.schema_version != SCHEMA_VERSION {
            return Err(anyhow!(
                "unexpected schema_version {} (want {})",
                wire.schema_version,
                SCHEMA_VERSION
            ));
        }
        let pke_dk_bytes = {
            let raw = wire.pke_dk_hex.trim().trim_start_matches("0x");
            Arc::new(hex::decode(raw).context("decode pke_dk_hex")?)
        };
        let mut by_keypair_epoch: HashMap<String, HashMap<u64, ([u8; 32], u8)>> = HashMap::new();
        for ep in wire.epochs {
            for sh in ep.shares {
                let scalar_bytes = hex::decode(sh.scalar_le32_hex.trim_start_matches("0x"))
                    .with_context(|| format!("decode scalar for keypair_id={}", sh.keypair_id))?;
                if scalar_bytes.len() != 32 {
                    return Err(anyhow!(
                        "scalar for keypair_id={} has length {} (want 32)",
                        sh.keypair_id,
                        scalar_bytes.len()
                    ));
                }
                let mut scalar = [0u8; 32];
                scalar.copy_from_slice(&scalar_bytes);
                by_keypair_epoch
                    .entry(sh.keypair_id)
                    .or_default()
                    .insert(ep.epoch, (scalar, sh.tibe_scheme));
            }
        }
        Ok(Snapshot {
            pke_dk_bytes,
            eval_point: wire.eval_point,
            by_keypair_epoch: Arc::new(by_keypair_epoch),
        })
    }
}

// ── Enum facade used by http_server ──────────────────────────────────────────

pub enum SecretsProvider {
    Local(LocalSecrets),
    Remote(Arc<RemoteSecrets>),
}

impl SecretsProvider {
    pub async fn snapshot(&self) -> Result<Arc<Snapshot>> {
        match self {
            SecretsProvider::Local(l) => Ok(Arc::new(l.snapshot().await)),
            SecretsProvider::Remote(r) => r.snapshot().await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn snapshot_wire_roundtrip() {
        let mut shares: HashMap<String, HashMap<u64, ([u8; 32], u8)>> = HashMap::new();
        shares
            .entry("0xkp".to_string())
            .or_default()
            .insert(5, ([0xab; 32], 0));
        shares
            .entry("0xkp".to_string())
            .or_default()
            .insert(6, ([0xcd; 32], 1));

        let local = LocalSecrets {
            keypair_shares: Arc::new(RwLock::new(shares)),
            cur_nodes: Arc::new(RwLock::new(vec!["0xa".into(), "0xme".into(), "0xb".into()])),
            my_addr: "0xme".into(),
            pke_dk_bytes: Arc::new(vec![1, 2, 3, 4]),
        };

        let wire = local.snapshot_wire().await;
        assert_eq!(wire.schema_version, SCHEMA_VERSION);
        assert_eq!(wire.eval_point, Some(2));
        assert_eq!(wire.epochs.len(), 2);
        // sorted by epoch
        assert_eq!(wire.epochs[0].epoch, 5);
        assert_eq!(wire.epochs[1].epoch, 6);
        assert_eq!(wire.pke_dk_hex, "0x01020304");

        let json = serde_json::to_string(&wire).unwrap();
        let parsed: SecretsSnapshotWire = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.schema_version, SCHEMA_VERSION);
        assert_eq!(parsed.eval_point, Some(2));
    }
}
