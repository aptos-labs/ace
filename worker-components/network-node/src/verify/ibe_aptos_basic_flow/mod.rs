// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;

mod account;
mod account_any;
mod account_any_account;
mod account_any_local;
mod account_any_local_secp256k1;
mod account_deferred;
mod account_federated_keyless;
mod account_keyless;
mod account_multi_ed25519;
mod account_multi_key;
mod account_multi_key_deferred;
mod account_single;
mod account_webauthn;
mod account_webauthn_challenge;
mod account_webauthn_prehash;
pub mod any;
mod binding;
mod cache;
pub(in crate::verify) mod constants;
mod federated_keyless;
pub(in crate::verify) mod hooks;
mod jwks;
mod keyless;
pub(in crate::verify) mod message;
pub mod multi_ed25519;
pub mod multi_key;
mod proof;
mod proof_serde;

pub(in crate::verify) use account::verify_account_proof;
pub(in crate::verify) use binding::AptosPayloadBinding;
pub use proof::{
    AptosContractId, AptosProofOfPermission, AptosPublicKeyMaterial, AptosSignatureMaterial,
};

use super::BasicFlowRequest;
use crate::ChainRpcConfig;
use constants::APTOS_DECRYPTION_HOOK;
use hooks::check_ace_request_hook;
use message::extract_request_origin;

pub(in crate::verify) async fn verify_aptos(
    req: &BasicFlowRequest,
    contract: &AptosContractId,
    proof: &AptosProofOfPermission,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    verify_account_proof(&req.payload, contract.chain_id, proof, chain_rpc).await?;
    let origin = extract_request_origin(proof)?;
    check_ace_request_hook(
        contract,
        APTOS_DECRYPTION_HOOK,
        &req.payload.domain,
        &proof.user_addr,
        &origin,
        chain_rpc,
    )
    .await
}
