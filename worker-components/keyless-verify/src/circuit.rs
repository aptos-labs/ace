// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Constants pinned by the Aptos keyless Circom circuit
//! (`aptos-core/types/src/keyless/circuit_constants.rs`).
//!
//! These bound the maximum byte length of each variable-length input the
//! circuit can absorb. Changing any of them on chain would require
//! regenerating SAMPLE_PROOF and every existing Groth16 VK, so they are
//! effectively constants of the protocol.

/// Max bytes for the `aud` JWT claim.
pub const MAX_AUD_VAL_BYTES: usize = 120;
/// Max bytes for the `uid_key` (e.g. `"sub"`, `"email"`).
pub const MAX_UID_KEY_BYTES: usize = 30;
/// Max bytes for the `uid_val` (the actual user identifier).
pub const MAX_UID_VAL_BYTES: usize = 330;
