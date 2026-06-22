// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};

mod any;
mod deferred;
mod federated_keyless;
mod keyless;
mod multi_ed25519;
mod multi_key;
mod single;
mod webauthn;

use super::{
    AptosPayloadBinding, AptosProofOfPermission, AptosPublicKeyMaterial, AptosSignatureMaterial,
};
use crate::ChainRpcConfig;

pub(crate) async fn verify_account_proof<P: AptosPayloadBinding + Sync>(
    payload: &P,
    chain_id: u8,
    proof: &AptosProofOfPermission,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    match (&proof.public_key_payload, &proof.signature_payload) {
        (AptosPublicKeyMaterial::Ed25519(pk), AptosSignatureMaterial::Ed25519(sig)) => {
            single::verify_ed25519_account_proof(payload, chain_id, proof, pk, sig, chain_rpc).await
        }
        (AptosPublicKeyMaterial::Any(pk), AptosSignatureMaterial::Any(sig)) => {
            any::verify_account_proof(payload, chain_id, proof, pk, sig, chain_rpc).await
        }
        (AptosPublicKeyMaterial::MultiEd25519(pk), AptosSignatureMaterial::MultiEd25519(sig)) => {
            multi_ed25519::verify_account_proof(payload, chain_id, proof, pk, sig, chain_rpc).await
        }
        (AptosPublicKeyMaterial::MultiKey(pk), AptosSignatureMaterial::MultiKey(sig)) => {
            multi_key::verify_account_proof(payload, chain_id, proof, pk, sig, chain_rpc).await
        }
        (AptosPublicKeyMaterial::Keyless(pk), AptosSignatureMaterial::Keyless(sig)) => {
            keyless::verify_account_proof(payload, chain_id, proof, pk, sig, chain_rpc).await
        }
        (AptosPublicKeyMaterial::FederatedKeyless(pk), AptosSignatureMaterial::Keyless(sig)) => {
            federated_keyless::verify_account_proof(payload, chain_id, proof, pk, sig, chain_rpc)
                .await
        }
        (pk, sig) => Err(anyhow!(
            "verify_account_proof: pk/sig scheme mismatch ({} pk vs {} sig)",
            pk.tag_name(),
            sig.tag_name(),
        )),
    }
}
