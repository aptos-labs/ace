// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Verification for the modern `AnyPublicKey` / `AnySignature` (SingleKey)
//! account type — Aptos `pk_scheme = 1` / `sig_scheme = 1`.
//!
//! `AnyPublicKey` and `AnySignature` are tagged enums (5 / 4 variants
//! respectively, see the constants below) that aptos-core wraps under a single
//! `Scheme::SingleKey` (0x02) auth-key derivation:
//!
//!   `auth_key = SHA3-256( BCS(AnyPublicKey) || 0x02 )`
//!
//! The on-wire BCS of `AnyPublicKey` is `ULEB128(variant) || BCS(inner)` —
//! [`AnyPublicKeyInner`] mirrors that layout exactly, so the variant tag we
//! get from `bcs::to_bytes` matches aptos-core's enum order
//! (`Ed25519=0, Secp256k1Ecdsa=1, Secp256r1Ecdsa=2, Keyless=3,
//! FederatedKeyless=4`) — see [the aptos-core enum][permalink].
//!
//! Variants ship one at a time; this PR lands `Ed25519` only. The other four
//! variants are present in the enum (so wire-format parsing covers all the
//! tags aptos-core emits) but the dispatch returns a "not yet supported"
//! error until their PRs land.
//!
//! [permalink]: https://github.com/aptos-labs/aptos-core/blob/f8ad6eab698cfb638e56fa8afd92a48642efad12/types/src/transaction/authenticator.rs#L1452-L1473

pub mod ed25519;

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use super::{AptosContractId, AptosProofOfPermission};
use super::super::BasicFlowRequest;
use crate::ChainRpcConfig;

/// Inner BCS-tagged payload of `AnyPublicKey` (pk_scheme=1). Variant order
/// matches `aptos_types::transaction::authenticator::AnyPublicKey` so BCS
/// variant tags line up with what the TS SDK and aptos-core both produce.
///
/// The `#[serde(with = "serde_bytes")]` annotation on the raw-byte variants
/// reproduces aptos-core's `SerializeKey` macro behaviour, which emits
/// `ULEB128(len) || bytes` (serde `serialize_bytes`) for each inner key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AnyPublicKeyInner {
    /// tag 0. 32-byte raw Ed25519 public key.
    Ed25519(#[serde(with = "serde_bytes")] Vec<u8>),
    /// tag 1. 65-byte uncompressed SEC1 secp256k1 public key (`0x04 || X || Y`).
    Secp256k1Ecdsa(#[serde(with = "serde_bytes")] Vec<u8>),
    /// tag 2. 65-byte uncompressed SEC1 P-256 public key (`0x04 || X || Y`).
    Secp256r1Ecdsa(#[serde(with = "serde_bytes")] Vec<u8>),
    /// tag 3. Same on-chain auth-key as the bare keyless path (pk_scheme=4) —
    /// only the wire framing differs.
    Keyless(aptos_keyless_common::KeylessPublicKey),
    /// tag 4. Same on-chain auth-key as the bare federated-keyless path
    /// (pk_scheme=5) — only the wire framing differs.
    FederatedKeyless(aptos_keyless_common::FederatedKeylessPublicKey),
}

/// Inner BCS-tagged payload of `AnySignature` (sig_scheme=1). Variant order
/// matches `aptos_types::transaction::authenticator::AnySignature` (note:
/// only 4 variants — `Secp256r1Ecdsa` shares the WebAuthn variant for sigs).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AnySignatureInner {
    /// tag 0. 64-byte Ed25519 signature.
    Ed25519(#[serde(with = "serde_bytes")] Vec<u8>),
    /// tag 1. 64-byte raw r‖s secp256k1 ECDSA signature, low-s normalized.
    Secp256k1Ecdsa(#[serde(with = "serde_bytes")] Vec<u8>),
    /// tag 2. WebAuthn assertion (paired with `AnyPublicKey::Secp256r1Ecdsa`).
    WebAuthn(WebAuthnAssertion),
    /// tag 3. Keyless signature (paired with `AnyPublicKey::Keyless` or
    /// `AnyPublicKey::FederatedKeyless`).
    Keyless(aptos_keyless_common::KeylessSignature),
}

/// `PartialAuthenticatorAssertionResponse` per aptos-core `webauthn.rs`.
///
/// On the wire (BCS): `signature || authenticator_data || client_data_json`,
/// where each `Vec<u8>` is length-prefixed via `serde_bytes`. Carried in the
/// enum so the deserializer can parse `AnySignature::WebAuthn` even on PRs
/// that haven't wired up the verifier yet.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebAuthnAssertion {
    pub signature: AssertionSignature,
    #[serde(with = "serde_bytes")]
    pub authenticator_data: Vec<u8>,
    #[serde(with = "serde_bytes")]
    pub client_data_json: Vec<u8>,
}

/// `AssertionSignature` enum from aptos-core `webauthn.rs`. Only one variant
/// exists today (`Secp256r1Ecdsa`); the enum framing is here so the BCS layout
/// matches even if more variants are added upstream.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum AssertionSignature {
    /// tag 0. 64-byte raw r‖s P-256 ECDSA signature, low-s normalized.
    Secp256r1Ecdsa(#[serde(with = "serde_bytes")] Vec<u8>),
}

impl AnyPublicKeyInner {
    pub(super) fn tag_name(&self) -> &'static str {
        match self {
            AnyPublicKeyInner::Ed25519(_) => "any/ed25519",
            AnyPublicKeyInner::Secp256k1Ecdsa(_) => "any/secp256k1",
            AnyPublicKeyInner::Secp256r1Ecdsa(_) => "any/secp256r1",
            AnyPublicKeyInner::Keyless(_) => "any/keyless",
            AnyPublicKeyInner::FederatedKeyless(_) => "any/federated_keyless",
        }
    }
}

impl AnySignatureInner {
    pub(super) fn tag_name(&self) -> &'static str {
        match self {
            AnySignatureInner::Ed25519(_) => "any/ed25519",
            AnySignatureInner::Secp256k1Ecdsa(_) => "any/secp256k1",
            AnySignatureInner::WebAuthn(_) => "any/webauthn",
            AnySignatureInner::Keyless(_) => "any/keyless",
        }
    }
}

// `Scheme::SingleKey = 2` — final suffix byte in the SingleKey auth-key
// preimage. See `aptos-types::transaction::authenticator::Scheme`.
const SCHEME_SINGLE_KEY: u8 = 2;

/// Computes the on-chain authentication key for a SingleKey account:
///
///   `auth_key = SHA3-256( BCS(AnyPublicKey) || 0x02 )`
///
/// `bcs::to_bytes(pk)` produces `ULEB128(variant_tag) || BCS(inner)` —
/// identical to what `aptos_types::AnyPublicKey::to_bytes` emits, because
/// [`AnyPublicKeyInner`]'s variant order matches aptos-core's enum.
pub(crate) fn authentication_key(pk: &AnyPublicKeyInner) -> [u8; 32] {
    let pk_bytes = bcs::to_bytes(pk).expect("BCS encode AnyPublicKeyInner is infallible");
    let mut hasher = Sha3_256::new();
    hasher.update(&pk_bytes);
    hasher.update([SCHEME_SINGLE_KEY]);
    hasher.finalize().into()
}

/// Inner dispatch for `pk_scheme = sig_scheme = 1`. Matches on the
/// `(AnyPublicKey, AnySignature)` variant pair and delegates. Variants whose
/// verifier has not been wired up yet return an "unsupported" error so the
/// worker fails closed rather than silently accepting an unverified proof.
pub(super) async fn verify(
    req: &BasicFlowRequest,
    contract: &AptosContractId,
    proof: &AptosProofOfPermission,
    any_pk: &AnyPublicKeyInner,
    any_sig: &AnySignatureInner,
    ephemeral_ek_bytes: &[u8],
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    match (any_pk, any_sig) {
        (AnyPublicKeyInner::Ed25519(pk_bytes), AnySignatureInner::Ed25519(sig_bytes)) => {
            ed25519::verify(
                req,
                contract,
                proof,
                any_pk,
                pk_bytes,
                sig_bytes,
                ephemeral_ek_bytes,
                chain_rpc,
            )
            .await
        }
        (AnyPublicKeyInner::Secp256k1Ecdsa(_), AnySignatureInner::Secp256k1Ecdsa(_))
        | (AnyPublicKeyInner::Secp256r1Ecdsa(_), AnySignatureInner::WebAuthn(_))
        | (AnyPublicKeyInner::Keyless(_), AnySignatureInner::Keyless(_))
        | (AnyPublicKeyInner::FederatedKeyless(_), AnySignatureInner::Keyless(_)) => Err(anyhow!(
            "verify_aptos_any: {} pk / {} sig is a valid pairing but not yet supported in this build",
            any_pk.tag_name(),
            any_sig.tag_name(),
        )),
        (pk, sig) => Err(anyhow!(
            "verify_aptos_any: invalid pk/sig pairing ({} pk vs {} sig)",
            pk.tag_name(),
            sig.tag_name(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aptos_keyless_common::types::IdCommitment;

    /// `AnyPublicKey::Keyless(pk)` must produce the same on-chain auth-key as
    /// the bare-keyless path. The bare path's
    /// [`aptos_keyless_common::keyless_account_authentication_key`] is already
    /// proven against aptos-core fixtures, so equality with it is a strong
    /// signal that our [`AnyPublicKeyInner`] variant tag (3) and BCS framing
    /// for the `Keyless` arm match aptos-core's `AnyPublicKey` enum exactly.
    #[test]
    fn any_keyless_auth_key_matches_bare_keyless() {
        let pk = aptos_keyless_common::KeylessPublicKey {
            iss_val: "test.oidc.provider".to_string(),
            idc: IdCommitment(vec![0u8; IdCommitment::NUM_BYTES]),
        };
        let any = AnyPublicKeyInner::Keyless(pk.clone());
        let from_any = authentication_key(&any);
        let from_bare = aptos_keyless_common::keyless_account_authentication_key(&pk);
        assert_eq!(from_any, from_bare);
    }

    /// `AnyPublicKey::FederatedKeyless(fpk)` should likewise match the bare
    /// federated-keyless auth-key — variant tag 4 + the same SingleKey suffix.
    #[test]
    fn any_federated_keyless_auth_key_matches_bare_federated_keyless() {
        let fpk = aptos_keyless_common::FederatedKeylessPublicKey {
            jwk_addr: [7u8; 32],
            pk: aptos_keyless_common::KeylessPublicKey {
                iss_val: "test.oidc.provider".to_string(),
                idc: IdCommitment(vec![0u8; IdCommitment::NUM_BYTES]),
            },
        };
        let any = AnyPublicKeyInner::FederatedKeyless(fpk.clone());
        let from_any = authentication_key(&any);
        let from_bare = aptos_keyless_common::federated_keyless_account_authentication_key(&fpk);
        assert_eq!(from_any, from_bare);
    }

    /// Sanity: `AnyPublicKey::Ed25519` should hash a known 34-byte preimage
    /// (variant tag 0x00 || ULEB128(32)=0x20 || 32 raw bytes) || 0x02.
    /// Different from the legacy `pk_scheme=0` auth-key, which omits the
    /// variant tag and uses suffix 0x00.
    #[test]
    fn any_ed25519_auth_key_differs_from_legacy_ed25519() {
        use sha3::{Digest, Sha3_256};

        let pk_raw = [0u8; 32];
        let from_any = authentication_key(&AnyPublicKeyInner::Ed25519(pk_raw.to_vec()));

        // Legacy: SHA3-256(pk || 0x00).
        let mut legacy = Sha3_256::new();
        legacy.update(pk_raw);
        legacy.update([0u8]);
        let legacy_out: [u8; 32] = legacy.finalize().into();

        assert_ne!(
            from_any, legacy_out,
            "SingleKey<Ed25519> must derive a distinct auth key from legacy Ed25519"
        );

        // Spot-check the preimage shape: variant 0x00, ULEB128(32)=0x20, 32
        // bytes of zero, suffix 0x02.
        let mut expect = Sha3_256::new();
        expect.update([0u8, 0x20u8]);
        expect.update([0u8; 32]);
        expect.update([2u8]);
        let expect_out: [u8; 32] = expect.finalize().into();
        assert_eq!(from_any, expect_out);
    }
}
