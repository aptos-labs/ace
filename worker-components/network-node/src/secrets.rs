// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Secrets provider abstraction for the three deployment modes.
//!
//! * `Monolith` / `Maintainer` use [`SecretsProvider::Local`], reading directly
//!   from the in-process share map that the URH / state-polling loop populates.
//! * `Handler` uses [`SecretsProvider::Remote`], which polls a peer
//!   maintainer's `/secrets` endpoint and caches the snapshot for 1 second
//!   (singleflight via an async mutex). Concurrent stale requests collapse
//!   onto a single fetch.
//!
//! The PKE decryption key is **not** carried in the snapshot — both maintainer
//! and handler receive it via CLI flag. That avoids transmitting a long-lived
//! identity secret across processes; the snapshot only carries per-epoch
//! material.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

/// JSON wire format returned by the maintainer's `GET /secrets`. Versioned via
/// the `schema` tag so future shapes can coexist.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "schema")]
pub enum SecretsSnapshotWire {
    /// This node is currently part of the committee. `shares` covers the
    /// current epoch plus any retained-buffer entries from the previous epoch.
    #[serde(rename = "v1-in-committee")]
    V1InCommittee { shares: Vec<ShareWire> },
    /// This node is not in the committee right now — there are no shares to
    /// serve. Handler will reject user requests with 503.
    #[serde(rename = "v1-not-in-committee")]
    V1NotInCommittee,
}

/// Per-(keypair, epoch) share with its evaluation point baked in.
///
/// `eval_point` is captured **at the time the URH task registered the share**,
/// i.e. it reflects the committee membership of the relevant epoch. That makes
/// stale-buffer-window entries (previous-epoch shares served during the ~30s
/// post-rotation grace period) self-contained — the handler doesn't need to
/// reconstruct what the committee looked like back then.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShareWire {
    pub keypair_id: String,
    pub epoch: u64,
    pub eval_point: u64,
    /// 32-byte BLS scalar (little-endian), `0x`-prefixed hex.
    pub scalar_le32_hex: String,
    pub tibe_scheme: u8,
}

/// Parsed, in-memory form of a snapshot.
#[derive(Clone, Debug)]
pub enum Snapshot {
    NotInCommittee,
    InCommittee {
        /// `(keypair_id, epoch)` → share entry.
        entries: Arc<HashMap<(String, u64), ShareEntry>>,
    },
}

#[derive(Clone, Copy, Debug)]
pub struct ShareEntry {
    pub scalar_le32: [u8; 32],
    pub tibe_scheme: u8,
    pub eval_point: u64,
}

impl Snapshot {
    pub fn lookup(&self, keypair_id: &str, epoch: u64) -> Option<ShareEntry> {
        match self {
            Snapshot::NotInCommittee => None,
            // `HashMap<(String, u64), _>::get` needs an owned key here because
            // there's no good Borrow impl for `(String, u64)` from `(&str, u64)`.
            Snapshot::InCommittee { entries } => {
                entries.get(&(keypair_id.to_string(), epoch)).copied()
            }
        }
    }
}

// ── Local provider (monolith + maintainer) ───────────────────────────────────

/// Live view of the maintainer's in-process state. The HTTP handler clones a
/// snapshot per request; the map is small (typically <10 entries) so the
/// clone is cheap.
#[derive(Clone)]
pub struct LocalSecrets {
    pub shares: Arc<RwLock<HashMap<(String, u64), ShareEntry>>>,
    /// Whether this node is currently in `cur_nodes`. Maintained by the
    /// state-polling loop; observed by the snapshot to decide which wire
    /// variant to emit.
    pub in_committee: Arc<RwLock<bool>>,
}

impl LocalSecrets {
    pub async fn snapshot(&self) -> Snapshot {
        if !*self.in_committee.read().await {
            return Snapshot::NotInCommittee;
        }
        let entries = Arc::new(self.shares.read().await.clone());
        Snapshot::InCommittee { entries }
    }

    pub async fn snapshot_wire(&self) -> SecretsSnapshotWire {
        match self.snapshot().await {
            Snapshot::NotInCommittee => SecretsSnapshotWire::V1NotInCommittee,
            Snapshot::InCommittee { entries } => {
                let mut shares: Vec<ShareWire> = entries
                    .iter()
                    .map(|((kp, epoch), e)| ShareWire {
                        keypair_id: kp.clone(),
                        epoch: *epoch,
                        eval_point: e.eval_point,
                        scalar_le32_hex: format!("0x{}", hex::encode(e.scalar_le32)),
                        tibe_scheme: e.tibe_scheme,
                    })
                    .collect();
                shares.sort_by_key(|s| (s.epoch, s.keypair_id.clone()));
                SecretsSnapshotWire::V1InCommittee { shares }
            }
        }
    }
}

// ── Remote provider (handler) ────────────────────────────────────────────────

/// Singleflight 1-second TTL cache over `GET {maintainer_url}`.
pub struct RemoteSecrets {
    maintainer_url: String,
    client: reqwest::Client,
    state: RwLock<Option<(Arc<Snapshot>, Instant)>>,
    refresh: Mutex<()>,
    ttl: Duration,
}

impl RemoteSecrets {
    pub fn new(maintainer_url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()
            .expect("build reqwest client for RemoteSecrets");
        Self {
            maintainer_url,
            client,
            state: RwLock::new(None),
            refresh: Mutex::new(()),
            ttl: Duration::from_secs(1),
        }
    }

    pub async fn snapshot(&self) -> Result<Arc<Snapshot>> {
        if let Some((snap, at)) = self.state.read().await.as_ref() {
            if at.elapsed() < self.ttl {
                return Ok(snap.clone());
            }
        }
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
        let resp = self
            .client
            .get(&self.maintainer_url)
            .send()
            .await
            .with_context(|| format!("GET {} failed", self.maintainer_url))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let body = resp.text().await.unwrap_or_default();
            return Err(anyhow!(
                "GET {} returned {}: {}",
                self.maintainer_url, status, body
            ));
        }
        let wire: SecretsSnapshotWire = resp.json().await.context("decode SecretsSnapshotWire")?;
        match wire {
            SecretsSnapshotWire::V1NotInCommittee => Ok(Snapshot::NotInCommittee),
            SecretsSnapshotWire::V1InCommittee { shares } => {
                let mut entries: HashMap<(String, u64), ShareEntry> = HashMap::new();
                for sh in shares {
                    let scalar_bytes = hex::decode(sh.scalar_le32_hex.trim_start_matches("0x"))
                        .with_context(|| format!("decode scalar for keypair_id={}", sh.keypair_id))?;
                    if scalar_bytes.len() != 32 {
                        return Err(anyhow!(
                            "scalar for keypair_id={} has length {} (want 32)",
                            sh.keypair_id, scalar_bytes.len()
                        ));
                    }
                    let mut scalar = [0u8; 32];
                    scalar.copy_from_slice(&scalar_bytes);
                    entries.insert(
                        (sh.keypair_id, sh.epoch),
                        ShareEntry {
                            scalar_le32: scalar,
                            tibe_scheme: sh.tibe_scheme,
                            eval_point: sh.eval_point,
                        },
                    );
                }
                Ok(Snapshot::InCommittee {
                    entries: Arc::new(entries),
                })
            }
        }
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
    async fn snapshot_wire_in_committee_roundtrip() {
        let mut shares: HashMap<(String, u64), ShareEntry> = HashMap::new();
        shares.insert(
            ("0xkp".to_string(), 5),
            ShareEntry {
                scalar_le32: [0xab; 32],
                tibe_scheme: 0,
                eval_point: 2,
            },
        );
        shares.insert(
            ("0xkp".to_string(), 6),
            ShareEntry {
                scalar_le32: [0xcd; 32],
                tibe_scheme: 1,
                eval_point: 2,
            },
        );

        let local = LocalSecrets {
            shares: Arc::new(RwLock::new(shares)),
            in_committee: Arc::new(RwLock::new(true)),
        };

        let wire = local.snapshot_wire().await;
        let json = serde_json::to_string(&wire).unwrap();
        assert!(json.contains("v1-in-committee"));
        let parsed: SecretsSnapshotWire = serde_json::from_str(&json).unwrap();
        match parsed {
            SecretsSnapshotWire::V1InCommittee { shares } => {
                assert_eq!(shares.len(), 2);
                assert_eq!(shares[0].epoch, 5);
                assert_eq!(shares[0].eval_point, 2);
                assert_eq!(shares[1].epoch, 6);
            }
            _ => panic!("expected V1InCommittee"),
        }
    }

    #[tokio::test]
    async fn snapshot_wire_not_in_committee_roundtrip() {
        let local = LocalSecrets {
            shares: Arc::new(RwLock::new(HashMap::new())),
            in_committee: Arc::new(RwLock::new(false)),
        };
        let wire = local.snapshot_wire().await;
        let json = serde_json::to_string(&wire).unwrap();
        assert!(json.contains("v1-not-in-committee"));
        let parsed: SecretsSnapshotWire = serde_json::from_str(&json).unwrap();
        assert!(matches!(parsed, SecretsSnapshotWire::V1NotInCommittee));
    }
}
