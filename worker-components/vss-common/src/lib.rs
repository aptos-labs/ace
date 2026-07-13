// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Shared types and utilities for VSS dealer / recipient binaries.

pub mod aptos;
pub mod crypto;
pub mod group;
pub mod node_wire;
pub mod offchain;
pub mod pke;
pub mod pke_hpke_x25519_chacha20poly1305;
pub mod session;
pub mod share_reconstruction;
pub mod sig;
pub mod sigma_dlog_linear;
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

/// Returns true for one rotating committee slot per wall-clock second.
///
/// Maintenance clients use this to avoid every worker submitting the same no-op
/// touch transaction while an on-chain session is waiting on sub-sessions.
pub fn should_submit_rotating_touch(my_idx: usize, n: usize) -> bool {
    let now_secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    rotating_touch_slot_for_second(my_idx, n, now_secs)
}

pub fn rotating_touch_slot_for_second(my_idx: usize, n: usize, unix_secs: u64) -> bool {
    n == 0 || (my_idx < n && (n == 1 || unix_secs % (n as u64) == my_idx as u64))
}

#[cfg(test)]
mod tests {
    use super::rotating_touch_slot_for_second;

    #[test]
    fn rotating_touch_slot_selects_one_committee_member() {
        let n = 5;
        for second in 0..20 {
            let selected = (0..n)
                .filter(|idx| rotating_touch_slot_for_second(*idx, n, second))
                .count();
            assert_eq!(selected, 1);
        }
    }

    #[test]
    fn rotating_touch_slot_handles_empty_or_singleton_committees() {
        assert!(rotating_touch_slot_for_second(0, 0, 42));
        assert!(rotating_touch_slot_for_second(0, 1, 42));
        assert!(!rotating_touch_slot_for_second(1, 1, 42));
    }
}
