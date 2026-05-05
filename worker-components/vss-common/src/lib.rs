// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Shared types and utilities for VSS dealer / recipient binaries.

pub mod aptos;
pub mod crypto;
pub mod pke;
pub mod pke_hpke_x25519_chacha20poly1305;
pub mod session;
pub mod share_reconstruction;
pub mod vss_types;

pub use aptos::{AptosRpc, TxnArg};
pub use session::Session;
pub use share_reconstruction::reconstruct_share;

/// Aptos account address from Ed25519 verifying key (same as `worker-rs` / TS-sdk single-key accounts).
pub fn compute_account_address(vk: &ed25519_dalek::VerifyingKey) -> [u8; 32] {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::new();
    hasher.update(vk.as_bytes());
    hasher.update([0x00u8]);
    hasher.finalize().into()
}

/// `0x` + lowercase hex, 32-byte Aptos address.
pub fn account_address_hex(vk: &ed25519_dalek::VerifyingKey) -> String {
    format!("0x{}", hex::encode(compute_account_address(vk))).to_lowercase()
}

pub fn parse_ed25519_signing_key_hex(hex_str: &str) -> anyhow::Result<ed25519_dalek::SigningKey> {
    let raw = hex_str.trim().trim_start_matches("0x");
    let bytes: [u8; 32] = hex::decode(raw)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("private key must be exactly 32 bytes"))?;
    Ok(ed25519_dalek::SigningKey::from_bytes(&bytes))
}

/// Normalize an Aptos address to canonical `0x` + 64 lowercase hex chars.
/// Pads short addresses (e.g. `0x16f8...` with 63 hex digits) to full length.
pub fn normalize_account_addr(s: &str) -> String {
    let t = s.trim().to_lowercase();
    let hex = t.strip_prefix("0x").unwrap_or(&t);
    format!("0x{:0>64}", hex)
}
