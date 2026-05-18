// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! **Compile-time** constants of the Aptos keyless Circom circuit.
//!
//! These bound the maximum byte length of each variable-length input the
//! circuit absorbs. They are **not** on-chain `0x1::keyless_account::
//! Configuration` fields — the Circom proving/verifying keys hardcode
//! these widths into the R1CS constraint system, so changing one would
//! invalidate every existing proof and the on-chain Groth16 VK in one go.
//!
//! That's why we mirror them as `pub const` here (just like aptos-core's
//! `types/src/keyless/circuit_constants.rs`) rather than reading them
//! from chain via `Configuration`.
//!
//! Source (aptos-core @ rev 8ec3fb76):
//! <https://github.com/aptos-labs/aptos-core/blob/8ec3fb76716abf2e1ee8cb85fa41d0eb212200cb/types/src/keyless/circuit_constants.rs#L16-L21>
//!
//! Note: the **other** byte caps used by the public-input hash
//! (`max_iss_val_bytes`, `max_extra_field_bytes`, `max_jwt_header_b64_bytes`,
//! `max_commited_epk_bytes`) are also circuit-baked at the same scale, but
//! aptos-core exposes them via `Configuration` so they can in principle
//! be lifted later without a circuit change (e.g. by adding padding scalars).
//! We read those from chain in [`public_inputs_hash`](crate::public_inputs_hash).

/// Max bytes for the `aud` JWT claim.
pub const MAX_AUD_VAL_BYTES: usize = 120;
/// Max bytes for the `uid_key` (e.g. `"sub"`, `"email"`).
pub const MAX_UID_KEY_BYTES: usize = 30;
/// Max bytes for the `uid_val` (the actual user identifier).
pub const MAX_UID_VAL_BYTES: usize = 330;
