// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! In-memory secret shares used by request handlers.
//!
//! Monolith processes fill this map from the maintainer loop. Handler-only
//! processes fill the same map from the shared VSS DB in a background sync loop;
//! handlers never fetch shares from a maintainer process.

use std::collections::HashMap;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::RwLock;
use vss_common::group::BcsElement;
use vss_common::session::BcsPcsPublicParams;

/// Per-(keypair, epoch) share with its evaluation point and originating group
/// scheme baked in.
///
/// `eval_point` is captured at registration time, so stale-buffer-window entries
/// served after a committee change use the right value for the epoch they belong
/// to.
#[derive(Clone, Debug)]
pub struct ShareEntry {
    pub scalar_le32: [u8; 32],
    pub blinding_le32: [u8; 32],
    pub group_scheme: u8,
    pub pcs_context: BcsPcsPublicParams,
    pub share_commitment: BcsElement,
    pub expected_usage: u64,
    pub eval_point: u64,
    pub note: String,
}

pub(crate) type ShareKey = (String, u64);
pub(crate) type ShareMap = HashMap<ShareKey, ShareEntry>;
type SharedShareMap = Arc<RwLock<ShareMap>>;

#[derive(Clone)]
pub struct LocalSecrets {
    shares: SharedShareMap,
}

impl LocalSecrets {
    pub(crate) fn empty() -> Self {
        Self {
            shares: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[cfg(test)]
    fn from_map(shares: ShareMap) -> Self {
        Self {
            shares: Arc::new(RwLock::new(shares)),
        }
    }

    pub async fn get_share(&self, keypair_id: &str, epoch: u64) -> Option<ShareEntry> {
        self.shares
            .read()
            .await
            .get(&(keypair_id.to_string(), epoch))
            .cloned()
    }

    #[cfg(test)]
    async fn insert_share(&self, keypair_id: String, epoch: u64, entry: ShareEntry) {
        self.shares.write().await.insert((keypair_id, epoch), entry);
    }

    pub(crate) async fn replace_all(&self, refreshed: ShareMap) {
        *self.shares.write().await = refreshed;
    }
}

pub enum SecretsProvider {
    Local(LocalSecrets),
}

impl SecretsProvider {
    pub async fn get_share(&self, keypair_id: &str, epoch: u64) -> Result<Option<ShareEntry>> {
        match self {
            SecretsProvider::Local(l) => Ok(l.get_share(keypair_id, epoch).await),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vss_common::group::{BcsPublicPoint, SCHEME_BLS12381G2};

    fn dummy_pcs_context() -> BcsPcsPublicParams {
        BcsPcsPublicParams {
            generator_g: BcsElement::Bls12381G2(BcsPublicPoint {
                point: vec![1u8; 96],
            }),
            generator_h: BcsElement::Bls12381G2(BcsPublicPoint {
                point: vec![2u8; 96],
            }),
        }
    }

    fn dummy_commitment() -> BcsElement {
        BcsElement::Bls12381G2(BcsPublicPoint {
            point: vec![3u8; 96],
        })
    }

    #[tokio::test]
    async fn local_get_share_only_clones_requested_share() {
        let mut shares: HashMap<(String, u64), ShareEntry> = HashMap::new();
        shares.insert(
            ("0xkp".to_string(), 5),
            ShareEntry {
                scalar_le32: [0xab; 32],
                blinding_le32: [0xba; 32],
                group_scheme: 0,
                pcs_context: dummy_pcs_context(),
                share_commitment: dummy_commitment(),
                expected_usage: 0,
                eval_point: 2,
                note: "test-only g1".to_string(),
            },
        );
        shares.insert(
            ("0xkp".to_string(), 6),
            ShareEntry {
                scalar_le32: [0xcd; 32],
                blinding_le32: [0xdc; 32],
                group_scheme: SCHEME_BLS12381G2,
                pcs_context: dummy_pcs_context(),
                share_commitment: dummy_commitment(),
                expected_usage: crate::secret_usage::USAGE_BLS12381_THRESHOLD_VRF,
                eval_point: 2,
                note: "threshold vrf".to_string(),
            },
        );

        let local = LocalSecrets::from_map(shares);

        let first = local.get_share("0xkp", 5).await.expect("epoch 5 share");
        assert_eq!(first.group_scheme, 0);
        assert_eq!(first.expected_usage, 0);
        assert_eq!(first.note, "test-only g1");
        local
            .insert_share(
                "0xkp".to_string(),
                5,
                ShareEntry {
                    scalar_le32: [0xee; 32],
                    blinding_le32: [0xdd; 32],
                    group_scheme: 0,
                    pcs_context: dummy_pcs_context(),
                    share_commitment: dummy_commitment(),
                    expected_usage: 0,
                    eval_point: 2,
                    note: "updated live share".to_string(),
                },
            )
            .await;
        assert_eq!(first.note, "test-only g1");

        let second = local.get_share("0xkp", 6).await.expect("epoch 6 share");
        assert_eq!(second.group_scheme, 1);
        assert_eq!(
            second.expected_usage,
            crate::secret_usage::USAGE_BLS12381_THRESHOLD_VRF
        );
        assert_eq!(second.note, "threshold vrf");
    }

    #[tokio::test]
    async fn local_get_share_returns_none_when_missing() {
        let local = LocalSecrets::empty();
        assert!(local.get_share("0xmissing", 7).await.is_none());
    }

    #[tokio::test]
    async fn replace_all_drops_stale_entries_and_keeps_refreshed_entries() {
        let local = LocalSecrets::empty();
        local
            .insert_share("0xold".to_string(), 3, dummy_share("old"))
            .await;
        local
            .insert_share("0xrecent".to_string(), 4, dummy_share("recent"))
            .await;

        let mut refreshed = ShareMap::new();
        refreshed.insert(("0xnew".to_string(), 5), dummy_share("new"));
        local.replace_all(refreshed).await;

        assert!(local.get_share("0xold", 3).await.is_none());
        assert!(local.get_share("0xrecent", 4).await.is_none());
        assert_eq!(local.get_share("0xnew", 5).await.unwrap().note, "new");
    }

    fn dummy_share(note: &str) -> ShareEntry {
        ShareEntry {
            scalar_le32: [0xab; 32],
            blinding_le32: [0xba; 32],
            group_scheme: SCHEME_BLS12381G2,
            pcs_context: dummy_pcs_context(),
            share_commitment: dummy_commitment(),
            expected_usage: crate::secret_usage::USAGE_BLS12381_THRESHOLD_VRF,
            eval_point: 2,
            note: note.to_string(),
        }
    }
}
