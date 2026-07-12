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

#[derive(Clone)]
pub struct LocalSecrets {
    pub shares: Arc<RwLock<HashMap<(String, u64), ShareEntry>>>,
}

impl LocalSecrets {
    pub async fn get_share(&self, keypair_id: &str, epoch: u64) -> Option<ShareEntry> {
        self.shares
            .read()
            .await
            .get(&(keypair_id.to_string(), epoch))
            .cloned()
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

        let local = LocalSecrets {
            shares: Arc::new(RwLock::new(shares)),
        };

        let first = local.get_share("0xkp", 5).await.expect("epoch 5 share");
        assert_eq!(first.group_scheme, 0);
        assert_eq!(
            first.expected_usage,
            0
        );
        assert_eq!(first.note, "test-only g1");
        local
            .shares
            .write()
            .await
            .get_mut(&("0xkp".to_string(), 5))
            .unwrap()
            .note = "updated live share".to_string();
        assert_eq!(
            first.note,
            "test-only g1"
        );

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
        let local = LocalSecrets {
            shares: Arc::new(RwLock::new(HashMap::new())),
        };
        assert!(local.get_share("0xmissing", 7).await.is_none());
    }
}
