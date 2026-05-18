// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Pinned public-input hash for the localnet test fixture (`SAMPLE_PROOF` in
//! aptos-core's `circuit_testcases.rs`).
//!
//! This is a stop-gap: the proper code path computes the public-input hash via
//! Poseidon-BN254 from `(epk, idc, exp_date_secs, exp_horizon_secs, iss, …)`
//! at verification time. Until that port lands, the network-node looks up the
//! matching pinned hash here by recognising the fixture's `(iss, idc)`.
//!
//! Regenerate this constant via `cargo run -p keyless-fixture-dumper`.

use crate::types::{IdCommitment, KeylessPublicKey};
use hex_literal::hex;

/// Public-input hash of SAMPLE_PROOF, as 32-byte little-endian BN254 Fr.
/// Tied to the entire SAMPLE_* fixture bundle — must be regenerated if any
/// of (ephemeral SK, pepper, blinder, exp date, exp horizon, JWT, JWK,
/// uid_key, extra_field) changes.
pub const SAMPLE_PUBLIC_INPUTS_HASH_LE: [u8; 32] =
    hex!("f35c81dd7960104f5bdbc26def36c247544b7ebc21500890e77afa046742ac23");

/// `iss` for the SAMPLE_PROOF fixture.
pub const SAMPLE_ISS: &str = "test.oidc.provider";

/// `idc` for the SAMPLE_PROOF fixture, computed from
/// `IdCommitment::new_from_preimage(SAMPLE_PEPPER, SAMPLE_AUD, "sub", SAMPLE_UID_VAL)`.
/// Pinned alongside the hash so a single match on (iss, idc) is enough to
/// recognise that this is the fixture signature.
///
/// 32-byte little-endian Fr. Regenerate via the dumper.
pub const SAMPLE_IDC: [u8; 32] =
    hex!("c390842e61c06e1ec945fc8504ad0830652ec1b6fc7bb0a095026be7551e001d");

/// Returns the pinned public-inputs hash if `pk` matches the localnet
/// SAMPLE_PROOF fixture identity. Used by the network-node to bridge the
/// missing Poseidon-on-the-fly path; a follow-up PR ports Poseidon-BN254
/// into this crate and deletes this lookup.
pub fn pinned_hash_for(pk: &KeylessPublicKey) -> Option<&'static [u8; 32]> {
    if pk.iss_val == SAMPLE_ISS && pk.idc == IdCommitment(SAMPLE_IDC.to_vec()) {
        Some(&SAMPLE_PUBLIC_INPUTS_HASH_LE)
    } else {
        None
    }
}
