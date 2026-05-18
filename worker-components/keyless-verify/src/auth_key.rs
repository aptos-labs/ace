// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Derivation of the on-chain `authentication_key` for a keyless account.
//!
//! Identical hash chain to `AuthenticationKey::any_key(AnyPublicKey::Keyless { pk })`
//! in `aptos-types`:
//!
//!   `auth_key = SHA3-256( BCS(AnyPublicKey::Keyless(pk)) || 0x02 )`
//!
//! where the inner BCS encoding is `uleb128(3) ++ BCS(KeylessPublicKey)` — `3`
//! is the BCS variant tag of `AnyPublicKey::Keyless`, `0x02` is `Scheme::SingleKey`.

use crate::types::KeylessPublicKey;
use sha3::{Digest, Sha3_256};

/// BCS variant tag of `AnyPublicKey::Keyless` in `aptos_types::transaction::authenticator`.
/// Order is `Ed25519=0, Secp256k1Ecdsa=1, Secp256r1Ecdsa=2, Keyless=3, ...`.
const ANY_PUBLIC_KEY_VARIANT_KEYLESS: u8 = 3;

/// `Scheme::SingleKey` byte; used as the final suffix in single-key auth-key derivation.
const SCHEME_SINGLE_KEY: u8 = 2;

/// Computes the 32-byte authentication key on chain for an account whose
/// public key is `AnyPublicKey::Keyless(pk)` wrapped as a `SingleKey`
/// authenticator.
pub fn keyless_account_authentication_key(pk: &KeylessPublicKey) -> [u8; 32] {
    // `bcs::to_bytes` on a `&KeylessPublicKey` does NOT emit a variant tag.
    // We need the tag for the enclosing AnyPublicKey enum, so prepend it
    // ourselves rather than allocating an AnyPublicKey wrapper struct here.
    let pk_bytes = bcs::to_bytes(pk).expect("BCS encode KeylessPublicKey");

    let mut hasher = Sha3_256::new();
    hasher.update([ANY_PUBLIC_KEY_VARIANT_KEYLESS]);
    hasher.update(&pk_bytes);
    hasher.update([SCHEME_SINGLE_KEY]);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::IdCommitment;

    #[test]
    fn auth_key_shape() {
        let pk = KeylessPublicKey {
            iss_val: "test.oidc.provider".to_string(),
            idc: IdCommitment(vec![0u8; IdCommitment::NUM_BYTES]),
        };
        let ak = keyless_account_authentication_key(&pk);
        assert_eq!(ak.len(), 32);
        // Determinism: same input, same output.
        assert_eq!(ak, keyless_account_authentication_key(&pk));
    }
}
