// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};

use super::super::hooks::check_auth_key_bytes;
use super::super::{AptosPayloadBinding, AptosProofOfPermission};
use super::single::verify_ed25519_signature;
use crate::verify::aptos::multi_ed25519 as aptos_multi_ed25519;
use crate::ChainRpcConfig;

pub(super) async fn verify_account_proof<P: AptosPayloadBinding + Sync>(
    payload: &P,
    chain_id: u8,
    proof: &AptosProofOfPermission,
    pk: &aptos_multi_ed25519::MultiEd25519PublicKeyInner,
    sig: &aptos_multi_ed25519::MultiEd25519SignatureInner,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    aptos_multi_ed25519::validate(pk, sig)?;
    let positions = aptos_multi_ed25519::bitmap_iter_ones(&sig.bitmap).zip(sig.signatures.iter());
    let position_futs = positions.map(|(pos, sig_bytes)| {
        let pk_bytes = &pk.public_keys[pos];
        async move {
            let vk = ed25519_dalek::VerifyingKey::from_bytes(pk_bytes).map_err(|e| {
                anyhow!(
                    "multi_ed25519 account proof: invalid Ed25519 pubkey at position {}: {}",
                    pos,
                    e
                )
            })?;
            let ed_sig = ed25519_dalek::Signature::from_bytes(sig_bytes);
            verify_ed25519_signature(payload, proof, &vk, &ed_sig, "multi_ed25519 account proof")
        }
    });
    futures::future::try_join_all(position_futs).await?;

    let computed = aptos_multi_ed25519::authentication_key(pk);
    let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
    check_auth_key_bytes(proof, &computed, "multi_ed25519", rpc).await
}
