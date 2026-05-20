// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! `AnyPublicKey::Keyless` / `AnySignature::Keyless` proof-of-permission path.
//!
//! Cosmetic delta from the bare-keyless path ([`super::super::keyless`],
//! `pk_scheme=4`): the wire framing carries an outer `AnyPublicKey`/
//! `AnySignature` enum (`pk_scheme=1`, inner variant tag = `3`) instead of
//! the bare `KeylessPublicKey`/`KeylessSignature` structs. The cryptographic
//! checks are identical — the SingleKey-wrapped auth-key derivation that the
//! bare path already uses (`SHA3-256(0x03 || BCS(KeylessPublicKey) || 0x02)`)
//! is the *same* auth-key the on-chain account has, regardless of which wire
//! shape the wallet picked, so we just unwrap the inner pk/sig and delegate.
//!
//! In TS-SDK terms: a wallet that constructs `KeylessAccount` and uses its
//! `publicKey` / `sign()` directly emits the bare wire; one that calls
//! `getAnyPublicKey()` + wraps `sign()` in `new AnySignature(...)` emits the
//! AnyPublicKey wire. Same account, same auth-key.

use anyhow::Result;

use super::super::super::BasicFlowRequest;
use super::super::{AptosContractId, AptosProofOfPermission};
use crate::ChainRpcConfig;

pub(super) async fn verify(
    req: &BasicFlowRequest,
    contract: &AptosContractId,
    proof: &AptosProofOfPermission,
    pk: &aptos_keyless_common::KeylessPublicKey,
    sig: &aptos_keyless_common::KeylessSignature,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    super::super::keyless::verify(req, contract, proof, pk, sig, chain_rpc).await
}
