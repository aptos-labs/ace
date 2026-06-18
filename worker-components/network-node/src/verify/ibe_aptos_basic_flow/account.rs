// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};

use super::{
    account_any as any, account_federated_keyless as federated_keyless, account_keyless as keyless,
    account_multi_ed25519 as multi_ed25519, account_multi_key as multi_key,
    account_single as single, AptosPayloadBinding, AptosProofOfPermission, AptosPublicKeyMaterial,
    AptosSignatureMaterial,
};
use crate::ChainRpcConfig;

pub(in crate::verify) async fn verify_account_proof<P: AptosPayloadBinding + Sync>(
    payload: &P,
    chain_id: u8,
    proof: &AptosProofOfPermission,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    match (&proof.public_key, &proof.signature) {
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
