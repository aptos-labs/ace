// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Secrets provider abstraction for the three deployment modes.
//!
//! * `Monolith` / `Maintainer` use [`SecretsProvider::Local`], reading directly
//!   from the in-process share map that the URH / state-polling loop populates.
//! * `Handler` uses [`SecretsProvider::Remote`], which polls a peer
//!   maintainer's `/secrets` endpoint and caches the snapshot for 1 second
//!   (singleflight via the RwLock's write lock — stale callers serialize on
//!   it and re-check after acquiring).
//!
//! The PKE decryption key is **not** carried in the snapshot — both maintainer
//! and handler receive it via CLI flag. That avoids transmitting a long-lived
//! identity secret across processes; the snapshot only carries per-epoch
//! material.
//!
//! No "in committee" flag: an empty `shares` map means "can't serve" whether
//! that's because the node is genuinely not in the committee or because URH
//! reconstruction hasn't completed yet. The handler's lookup-miss path returns
//! NotFound in both cases, which is the right answer for both.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

/// JSON wire format returned by the maintainer's `GET /secrets`.
///
/// Modeled as a tagged enum even though there's only one variant today —
/// it lets us evolve the shape (add fields, change structure, retire old
/// variants) without breaking handlers on a different release. Cheap
/// forward-compat insurance, mirrors the `WorkerRequest` pattern
/// on the request side.
#[derive(Serialize, Deserialize, Clone, Debug)]
#[serde(tag = "schema")]
pub enum SecretsSnapshotWire {
    #[serde(rename = "v1")]
    V1 { shares: Vec<ShareWire> },
}

/// Per-(keypair, epoch) share with its evaluation point and originating group
/// scheme baked in.
///
/// `eval_point` is captured **at the time the URH task registered the share**,
/// so stale-buffer-window entries served after a committee change use the
/// right value for the epoch they belong to.
///
/// `group_scheme` is the underlying VSS group (e.g. BLS12381G1). The handler
/// validates it against the requested primitive's implementation group.
///
/// `expected_usage` is the on-chain ACE primitive usage mask. Handlers must
/// check it before deriving either IBE or VRF shares.
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct ShareWire {
    pub keypair_id: String,
    pub epoch: u64,
    pub eval_point: u64,
    /// 32-byte BLS scalar (little-endian), `0x`-prefixed hex.
    pub scalar_le32_hex: String,
    pub group_scheme: u8,
    pub expected_usage: u64,
    pub note: String,
}

/// Parsed, in-memory form of a snapshot.
#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub entries: Arc<HashMap<(String, u64), ShareEntry>>,
}

#[derive(Clone, Debug)]
pub struct ShareEntry {
    pub scalar_le32: [u8; 32],
    pub group_scheme: u8,
    pub expected_usage: u64,
    pub eval_point: u64,
    pub note: String,
}

impl Snapshot {
    pub fn lookup(&self, keypair_id: &str, epoch: u64) -> Option<ShareEntry> {
        // `HashMap<(String, u64), _>::get` needs an owned key here — there's
        // no `Borrow<(String, u64)>` impl for `(&str, u64)`.
        self.entries.get(&(keypair_id.to_string(), epoch)).cloned()
    }
}

// ── Local provider (monolith + maintainer) ───────────────────────────────────

/// Live view of the maintainer's in-process state. Cheap clone per request;
/// the map is small (typically <10 entries).
#[derive(Clone)]
pub struct LocalSecrets {
    pub shares: Arc<RwLock<HashMap<(String, u64), ShareEntry>>>,
    /// V6 stages reconstructed INIT shares before they can be served. A value
    /// of None means SERVING/HANDOFF; Some(deadline) means GRACE. Absent epochs
    /// are hidden. Legacy V5 deployments leave the inner value unset.
    pub visible_epochs: Arc<RwLock<Option<HashMap<u64, Option<u64>>>>>,
}

impl LocalSecrets {
    async fn visible_epochs(&self) -> Option<HashMap<u64, Option<u64>>> {
        self.visible_epochs.read().await.clone()
    }

    fn epoch_is_visible(visibility: &Option<HashMap<u64, Option<u64>>>, epoch: u64, now_micros: u64) -> bool {
        match visibility {
            None => true,
            Some(epochs) => match epochs.get(&epoch) {
                Some(None) => true,
                Some(Some(deadline)) => now_micros < *deadline,
                None => false,
            },
        }
    }

    pub async fn snapshot(&self) -> Snapshot {
        let visibility = self.visible_epochs().await;
        let now_micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        Snapshot {
            entries: Arc::new(self.shares.read().await.iter()
                .filter(|((_, epoch), _)| Self::epoch_is_visible(&visibility, *epoch, now_micros))
                .map(|(key, share)| (key.clone(), share.clone()))
                .collect()),
        }
    }

    pub async fn snapshot_wire(&self) -> SecretsSnapshotWire {
        let visibility = self.visible_epochs().await;
        let now_micros = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let entries = self.shares.read().await;
        let mut shares: Vec<ShareWire> = entries
            .iter()
            .filter(|((_, epoch), _)| Self::epoch_is_visible(&visibility, *epoch, now_micros))
            .map(|((kp, epoch), e)| ShareWire {
                keypair_id: kp.clone(),
                epoch: *epoch,
                eval_point: e.eval_point,
                scalar_le32_hex: format!("0x{}", hex::encode(e.scalar_le32)),
                group_scheme: e.group_scheme,
                expected_usage: e.expected_usage,
                note: e.note.clone(),
            })
            .collect();
        shares.sort_by_key(|s| (s.epoch, s.keypair_id.clone()));
        SecretsSnapshotWire::V1 { shares }
    }
}

// ── Remote provider (handler) ────────────────────────────────────────────────

/// Singleflight 1-second TTL cache over `GET {maintainer_url}`.
///
/// Single `RwLock` covers both fast-path reads (cache fresh ⇒ `read()` and
/// return) and the singleflight gate (cache stale ⇒ acquire `write()`,
/// re-check, fetch). The "re-check after acquiring write" is necessary
/// because while we waited for the write lock, another task may have already
/// done the fetch — re-checking the timestamp short-circuits the redundant
/// fetch.
pub struct RemoteSecrets {
    maintainer_url: String,
    client: reqwest::Client,
    state: RwLock<Option<(Arc<Snapshot>, Instant)>>,
    ttl: Duration,
}

const MISSING_SHARE_REFRESH_INTERVAL: Duration = Duration::from_millis(100);

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
            ttl: Duration::from_secs(1),
        }
    }

    pub async fn snapshot(&self) -> Result<Arc<Snapshot>> {
        // Fast path: cache fresh ⇒ return immediately under a read lock.
        if let Some((snap, at)) = self.state.read().await.as_ref() {
            if at.elapsed() < self.ttl {
                return Ok(snap.clone());
            }
        }
        // Slow path: take write lock (also acts as the singleflight gate).
        // Re-check after acquiring: another stale caller may have already
        // refreshed.
        let mut guard = self.state.write().await;
        if let Some((snap, at)) = guard.as_ref() {
            if at.elapsed() < self.ttl {
                return Ok(snap.clone());
            }
        }
        let fresh = Arc::new(self.fetch().await?);
        *guard = Some((fresh.clone(), Instant::now()));
        Ok(fresh)
    }

    /// A newly activated epoch may be absent from the handler's 1-second
    /// cache even though the maintainer staged its shares before activation.
    /// Refresh a missing key once per 100 ms, with the cache write lock acting
    /// as a singleflight gate for concurrent misses.
    pub async fn snapshot_for(&self, keypair_id: &str, epoch: u64) -> Result<Arc<Snapshot>> {
        let snapshot = self.snapshot().await?;
        if snapshot.lookup(keypair_id, epoch).is_some() {
            return Ok(snapshot);
        }
        let mut guard = self.state.write().await;
        if let Some((cached, at)) = guard.as_ref() {
            if cached.lookup(keypair_id, epoch).is_some()
                || at.elapsed() < MISSING_SHARE_REFRESH_INTERVAL {
                return Ok(cached.clone());
            }
        }
        let fresh = Arc::new(self.fetch().await?);
        *guard = Some((fresh.clone(), Instant::now()));
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
        let SecretsSnapshotWire::V1 { shares } = wire;
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
                    group_scheme: sh.group_scheme,
                    expected_usage: sh.expected_usage,
                    eval_point: sh.eval_point,
                    note: sh.note,
                },
            );
        }
        Ok(Snapshot {
            entries: Arc::new(entries),
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

    pub async fn snapshot_for(&self, keypair_id: &str, epoch: u64) -> Result<Arc<Snapshot>> {
        match self {
            SecretsProvider::Local(local) => Ok(Arc::new(local.snapshot().await)),
            SecretsProvider::Remote(remote) => remote.snapshot_for(keypair_id, epoch).await,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn snapshot_wire_roundtrip() {
        let mut shares: HashMap<(String, u64), ShareEntry> = HashMap::new();
        shares.insert(
            ("0xkp".to_string(), 5),
            ShareEntry {
                scalar_le32: [0xab; 32],
                group_scheme: 0,
                expected_usage: crate::secret_usage::USAGE_BFIBE_BLS12381_SHORTPK_OTP_HMAC,
                eval_point: 2,
                note: "legacy ibe".to_string(),
            },
        );
        shares.insert(
            ("0xkp".to_string(), 6),
            ShareEntry {
                scalar_le32: [0xcd; 32],
                group_scheme: 1,
                expected_usage: crate::secret_usage::USAGE_BFIBE_BLS12381_SHORTSIG_AEAD,
                eval_point: 2,
                note: "default ibe".to_string(),
            },
        );

        let local = LocalSecrets {
            shares: Arc::new(RwLock::new(shares)),
            visible_epochs: Arc::new(RwLock::new(None)),
        };

        let wire = local.snapshot_wire().await;
        let json = serde_json::to_string(&wire).unwrap();
        // Ensure the version tag is on the wire — that's the whole point of
        // the tagged-enum shape.
        assert!(json.contains("\"schema\":\"v1\""), "json missing schema tag: {json}");
        let parsed: SecretsSnapshotWire = serde_json::from_str(&json).unwrap();
        let SecretsSnapshotWire::V1 { shares } = parsed;
        assert_eq!(shares.len(), 2);
        assert_eq!(shares[0].epoch, 5);
        assert_eq!(shares[0].group_scheme, 0);
        assert_eq!(
            shares[0].expected_usage,
            crate::secret_usage::USAGE_BFIBE_BLS12381_SHORTPK_OTP_HMAC
        );
        assert_eq!(shares[0].note, "legacy ibe");
        assert_eq!(shares[1].epoch, 6);
        assert_eq!(shares[1].group_scheme, 1);
        assert_eq!(
            shares[1].expected_usage,
            crate::secret_usage::USAGE_BFIBE_BLS12381_SHORTSIG_AEAD
        );
        assert_eq!(shares[1].note, "default ibe");
    }

    #[tokio::test]
    async fn snapshot_wire_empty_when_no_shares() {
        let local = LocalSecrets {
            shares: Arc::new(RwLock::new(HashMap::new())),
            visible_epochs: Arc::new(RwLock::new(None)),
        };
        let SecretsSnapshotWire::V1 { shares } = local.snapshot_wire().await;
        assert!(shares.is_empty());
    }

    #[tokio::test]
    async fn remote_cache_refreshes_new_epoch_share_on_lookup_miss() {
        use axum::{routing::get, Json, Router};

        let local = LocalSecrets {
            shares: Arc::new(RwLock::new(HashMap::new())),
            visible_epochs: Arc::new(RwLock::new(None)),
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let serving = local.clone();
        let router = Router::new().route("/", get(move || {
            let local = serving.clone();
            async move { Json(local.snapshot_wire().await) }
        }));
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });

        let remote = RemoteSecrets::new(url);
        let keypair_id = format!("0x{}", "ab".repeat(32));
        assert!(remote.snapshot().await.unwrap().lookup(&keypair_id, 6).is_none());
        local.shares.write().await.insert((keypair_id.clone(), 6), ShareEntry {
            scalar_le32: [7; 32],
            group_scheme: 1,
            expected_usage: 2,
            eval_point: 1,
            note: String::new(),
        });
        assert!(remote.snapshot().await.unwrap().lookup(&keypair_id, 6).is_none());
        tokio::time::sleep(Duration::from_millis(120)).await;
        assert!(remote.snapshot_for(&keypair_id, 6).await.unwrap().lookup(&keypair_id, 6).is_some());
        server.abort();
    }
}
