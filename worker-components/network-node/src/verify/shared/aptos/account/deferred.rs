// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

use super::{federated_keyless, keyless};
use crate::ChainRpcConfig;

#[derive(Copy, Clone)]
pub(super) enum AnySignatureCheck<'a> {
    VerifiedLocally,
    DeferredKeyless {
        pk: &'a aptos_keyless_common::KeylessPublicKey,
        sig: &'a aptos_keyless_common::KeylessSignature,
    },
    DeferredFederatedKeyless {
        fpk: &'a aptos_keyless_common::FederatedKeylessPublicKey,
        sig: &'a aptos_keyless_common::KeylessSignature,
    },
}

impl AnySignatureCheck<'_> {
    pub(super) fn signed_message_context(&self) -> &'static str {
        match self {
            AnySignatureCheck::VerifiedLocally => "verify_any_signature_only",
            AnySignatureCheck::DeferredKeyless { .. } => "verify_keyless_signature",
            AnySignatureCheck::DeferredFederatedKeyless { .. } => {
                "verify_federated_keyless_signature"
            }
        }
    }
}

pub(super) async fn verify_deferred_keyless_signature_for_message(
    chain_id: u8,
    deferred: AnySignatureCheck<'_>,
    msg_bytes: &[u8],
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    match deferred {
        AnySignatureCheck::DeferredKeyless { pk, sig } => {
            keyless::verify_signature_for_message(chain_id, pk, sig, msg_bytes, chain_rpc).await
        }
        AnySignatureCheck::DeferredFederatedKeyless { fpk, sig } => {
            federated_keyless::verify_signature_for_message(
                chain_id, fpk, sig, msg_bytes, chain_rpc,
            )
            .await
        }
        AnySignatureCheck::VerifiedLocally => Ok(()),
    }
}
