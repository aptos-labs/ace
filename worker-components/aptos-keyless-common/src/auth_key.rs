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
//!
//! Reference (aptos-core @ rev 8ec3fb76):
//!   - [`AuthenticationKey::any_key`](https://github.com/aptos-labs/aptos-core/blob/8ec3fb76716abf2e1ee8cb85fa41d0eb212200cb/types/src/transaction/authenticator.rs#L1010-L1013)
//!   - [`AuthenticationKey::from_preimage`](https://github.com/aptos-labs/aptos-core/blob/8ec3fb76716abf2e1ee8cb85fa41d0eb212200cb/types/src/transaction/authenticator.rs#L971-L974)
//!   - [`Scheme::SingleKey = 2`](https://github.com/aptos-labs/aptos-core/blob/8ec3fb76716abf2e1ee8cb85fa41d0eb212200cb/types/src/transaction/authenticator.rs#L522-L526)
//!   - [`AnyPublicKey::Keyless` variant order](https://github.com/aptos-labs/aptos-core/blob/8ec3fb76716abf2e1ee8cb85fa41d0eb212200cb/types/src/transaction/authenticator.rs#L1454-L1473)

use crate::types::{FederatedKeylessPublicKey, KeylessPublicKey};
use sha3::{Digest, Sha3_256};

/// BCS variant tag of `AnyPublicKey::Keyless` in `aptos_types::transaction::authenticator`.
/// Order: `Ed25519=0, Secp256k1Ecdsa=1, Secp256r1Ecdsa=2, Keyless=3, FederatedKeyless=4, …`
/// — see [the enum definition][permalink] in aptos-core.
///
/// [permalink]: https://github.com/aptos-labs/aptos-core/blob/8ec3fb76716abf2e1ee8cb85fa41d0eb212200cb/types/src/transaction/authenticator.rs#L1454-L1473
const ANY_PUBLIC_KEY_VARIANT_KEYLESS: u8 = 3;
const ANY_PUBLIC_KEY_VARIANT_FEDERATED_KEYLESS: u8 = 4;

/// `Scheme::SingleKey`; final suffix byte in single-key auth-key derivation.
/// [permalink](https://github.com/aptos-labs/aptos-core/blob/8ec3fb76716abf2e1ee8cb85fa41d0eb212200cb/types/src/transaction/authenticator.rs#L522-L526).
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

/// Computes the 32-byte authentication key on chain for an account whose
/// public key is `AnyPublicKey::FederatedKeyless(fpk)` wrapped as a `SingleKey`
/// authenticator.
///
///   `auth_key = SHA3-256( 0x04 || BCS(FederatedKeylessPublicKey) || 0x02 )`
pub fn federated_keyless_account_authentication_key(fpk: &FederatedKeylessPublicKey) -> [u8; 32] {
    let fpk_bytes = bcs::to_bytes(fpk).expect("BCS encode FederatedKeylessPublicKey");

    let mut hasher = Sha3_256::new();
    hasher.update([ANY_PUBLIC_KEY_VARIANT_FEDERATED_KEYLESS]);
    hasher.update(&fpk_bytes);
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

    // Correctness of `federated_keyless_account_authentication_key` is
    // exercised end-to-end by `test-access-failures-federated-keyless.ts`
    // Step D: the worker recomputes the auth-key from the wire
    // `FederatedKeylessPublicKey` and matches it against the on-chain
    // `authentication_key`. Any drift in the variant byte, scheme byte, or
    // BCS field order fails Step D.
}
