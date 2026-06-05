// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Verification for the K-of-N `MultiKey` (`MultiKeyAuthenticator`) account
//! type — Aptos `pk_scheme = 3` / `sig_scheme = 3`.
//!
//! A `MultiKey` account holds a list of [`AnyPublicKeyInner`]s (each of the
//! same five variants as `pk_scheme = 1`) plus a threshold:
//!
//!   `auth_key = SHA3-256( BCS(MultiKey) || Scheme::MultiKey = 0x03 )`
//!
//! The `MultiKeySignature` carries a `Vec<AnySignatureInner>` plus a bitmap
//! that pinpoints which N of the M public-key positions actually signed.
//! Bits are MSB-first within each byte — bit i ⇔ `bitmap[i/8] & (0x80 >> (i%8))`
//! — and traversed in ascending position order. Signatures pair with set
//! positions positionally: the i-th set bit's position picks
//! `public_keys[pos]`, paired with `signatures[i]`.
//!
//! Verification (one request):
//!   1. Structural validation (cheap, fail-fast before any RPC).
//!   2. `tokio::join!` over (per-position signature verification via
//!      [`any::verify_position`], MultiKey-level on-chain auth-key match,
//!      and one dapp ACL view call against `proof.user_addr`).
//!
//! Per-position verification reuses each variant's
//! `verify_signature_only` — the auth-key check happens once at the
//! MultiKey level (because the on-chain auth-key for a MultiKey account
//! is the MultiKey-level `SHA3-256(BCS(MultiKey) || 0x03)`, not the
//! per-position SingleKey one), and the dapp `check_permission` view
//! likewise runs once over `proof.user_addr` rather than per position.
//!
//! All five `AnyPublicKey`/`AnySignature` pairings — Ed25519, Secp256k1Ecdsa,
//! Keyless, FederatedKeyless, and Secp256r1Ecdsa+WebAuthn — are accepted as
//! MultiKey positions. The WebAuthn path binds to the request payload via
//! `clientDataJSON.challenge` rather than `proof.full_message`, so it
//! composes with positions that need the pretty-message bytes (Ed25519,
//! Secp256k1, Keyless, FederatedKeyless) under a single shared
//! `proof.full_message`.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use super::any::{AnyPublicKeyInner, AnySignatureInner};
use super::super::BasicFlowRequest;
use super::{check_permission, AptosContractId, AptosProofOfPermission};
use crate::ChainRpcConfig;

// Mirrors aptos-core's `MAX_NUM_OF_SIGS: usize = 32` for MultiKey signers.
const MAX_NUM_OF_SIGS: usize = 32;

// Maximum byte-length of the bitmap. aptos-core's `BitVec` trims to
// `highest_set_bit / 8 + 1`; the TS-SDK always emits the full 4 bytes
// (`MultiKeySignature.BITMAP_LEN`). Both shapes round-trip into the
// `Vec<u8>` here.
const MAX_BITMAP_BYTES: usize = (MAX_NUM_OF_SIGS + 7) / 8;

// `Scheme::MultiKey = 3` — final suffix byte in the MultiKey auth-key
// preimage. See `aptos_types::transaction::authenticator::Scheme`.
const SCHEME_MULTI_KEY: u8 = 3;

// ── Wire types ────────────────────────────────────────────────────────────────

/// BCS-compatible mirror of aptos-core's `MultiKey` public-key struct.
/// On the wire: `length-prefixed Vec<AnyPublicKey>` (each as
/// `ULEB128(any_variant) || BCS(inner)`), then `u8(signatures_required)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiKeyInner {
    pub public_keys: Vec<AnyPublicKeyInner>,
    pub signatures_required: u8,
}

/// BCS-compatible mirror of aptos-core's `MultiKeyAuthenticator` signature
/// struct (minus the embedded `MultiKey` — that lives in
/// [`MultiKeyInner`] inside `AptosPublicKeyMaterial`). On the wire:
/// `length-prefixed Vec<AnySignature>` (each as
/// `ULEB128(any_variant) || BCS(inner)`), then `serialize_bytes(bitmap)`.
///
/// `bitmap` is MSB-first within each byte; bit i is set iff
/// `bitmap[i/8] & (0x80 >> (i%8)) != 0`. See [`bitmap_iter_ones`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MultiKeySigInner {
    pub signatures: Vec<AnySignatureInner>,
    #[serde(with = "serde_bytes")]
    pub bitmap: Vec<u8>,
}

// ── Authentication-key derivation ────────────────────────────────────────────

/// Computes the on-chain authentication key for a MultiKey account:
///
///   `auth_key = SHA3-256( BCS(MultiKey) || 0x03 )`
///
/// `bcs::to_bytes(mk)` produces the same bytes aptos-core's
/// `MultiKey::to_bytes` emits (length-prefixed `Vec<AnyPublicKey>` +
/// `u8(signatures_required)`), so the resulting digest matches the
/// on-chain `authentication_key` field at `userAddr` for a MultiKey
/// account derived from this `MultiKey`.
pub(crate) fn authentication_key(mk: &MultiKeyInner) -> [u8; 32] {
    let mk_bytes = bcs::to_bytes(mk).expect("BCS encode MultiKeyInner is infallible");
    let mut hasher = Sha3_256::new();
    hasher.update(&mk_bytes);
    hasher.update([SCHEME_MULTI_KEY]);
    hasher.finalize().into()
}

// ── Bitmap iteration ─────────────────────────────────────────────────────────

/// Iterates set-bit positions in MSB-first order across `bitmap`. Matches
/// aptos-core's `BitVec::iter_ones`: position p maps to
/// `bitmap[p/8] & (0x80 >> (p%8))`.
pub(crate) fn bitmap_iter_ones(bitmap: &[u8]) -> impl Iterator<Item = usize> + '_ {
    bitmap.iter().enumerate().flat_map(|(byte_idx, &byte)| {
        (0..8u32).filter_map(move |bit| {
            if byte & (0x80 >> bit) != 0 {
                Some(byte_idx * 8 + bit as usize)
            } else {
                None
            }
        })
    })
}

// ── Structural validation ────────────────────────────────────────────────────

/// Cheap synchronous checks that reject malformed MultiKey wire payloads
/// before any RPC. Mirrors aptos-core's `MultiKeyAuthenticator::new` /
/// `verify` invariants (`types/src/transaction/authenticator.rs`):
///
///   1. `signatures_required >= 1`                       — MultiKey::new
///   2. `1 <= public_keys.len() <= MAX_NUM_OF_SIGS (32)` — MultiKey::new
///   3. `public_keys.len() >= signatures_required`       — MultiKey::new
///   4. `bitmap.len() <= 4` (max bytes for 32 bits)
///   5. `popcount(bitmap) == signatures.len()`           — verify
///   6. `signatures.len() >= signatures_required`        — verify
///   7. Every set bit position is `< public_keys.len()`  — verify
///
/// Note rule 6 is `>=`, not `==`. aptos-core accepts over-signing (more
/// signatures than the threshold) as long as every supplied signature
/// verifies; this matches that policy. Earlier versions of this file
/// enforced strict equality to match the TS-SDK producer, but consensus
/// reference (aptos-core) is the authoritative spec.
pub(in crate::verify::aptos) fn validate(mk: &MultiKeyInner, ms: &MultiKeySigInner) -> Result<()> {
    if mk.signatures_required == 0 {
        return Err(anyhow!("multi_key: signatures_required must be >= 1"));
    }
    if mk.public_keys.is_empty() {
        return Err(anyhow!("multi_key: public_keys cannot be empty"));
    }
    if mk.public_keys.len() > MAX_NUM_OF_SIGS {
        return Err(anyhow!(
            "multi_key: public_keys.len() {} exceeds max {}",
            mk.public_keys.len(),
            MAX_NUM_OF_SIGS
        ));
    }
    if mk.public_keys.len() < mk.signatures_required as usize {
        return Err(anyhow!(
            "multi_key: public_keys.len() {} < signatures_required {}",
            mk.public_keys.len(),
            mk.signatures_required
        ));
    }
    if ms.bitmap.len() > MAX_BITMAP_BYTES {
        return Err(anyhow!(
            "multi_key: bitmap.len() {} exceeds max {} bytes",
            ms.bitmap.len(),
            MAX_BITMAP_BYTES
        ));
    }
    let set_bits: Vec<usize> = bitmap_iter_ones(&ms.bitmap).collect();
    if set_bits.len() != ms.signatures.len() {
        return Err(anyhow!(
            "multi_key: bitmap set-bit count {} != signatures.len() {}",
            set_bits.len(),
            ms.signatures.len()
        ));
    }
    if ms.signatures.len() < mk.signatures_required as usize {
        return Err(anyhow!(
            "multi_key: signatures.len() {} < signatures_required {}",
            ms.signatures.len(),
            mk.signatures_required
        ));
    }
    if let Some(&bad) = set_bits.iter().find(|&&p| p >= mk.public_keys.len()) {
        return Err(anyhow!(
            "multi_key: bitmap position {} >= public_keys.len() {}",
            bad,
            mk.public_keys.len()
        ));
    }
    Ok(())
}

// ── Auth-key check ──────────────────────────────────────────────────────────

/// Checks that the on-chain `authentication_key` for `userAddr` equals
/// `SHA3-256( BCS(MultiKey) || 0x03 )` ([`authentication_key`]). Only one
/// such check is needed per MultiKey request (not one per signing position)
/// — the MultiKey wraps the full per-position public-key set into one
/// auth-key.
async fn check_multi_key_auth_key(
    proof: &AptosProofOfPermission,
    mk: &MultiKeyInner,
    rpc: &vss_common::AptosRpc,
) -> Result<()> {
    let computed = authentication_key(mk);

    let user_addr_str = format!("0x{}", hex::encode(proof.user_addr));
    let account = rpc
        .get_account(&user_addr_str)
        .await
        .map_err(|e| anyhow!("checkAuthKey: get_account {}: {}", user_addr_str, e))?;

    let onchain = hex::decode(account.authentication_key.trim_start_matches("0x"))
        .map_err(|e| anyhow!("checkAuthKey: parse onchain auth key: {}", e))?;

    if onchain.as_slice() != computed.as_ref() {
        return Err(anyhow!(
            "checkAuthKey: multi_key auth key mismatch for {}",
            user_addr_str
        ));
    }
    Ok(())
}

// ── Verification entry point ─────────────────────────────────────────────────

pub(super) async fn verify(
    req: &BasicFlowRequest,
    contract: &AptosContractId,
    proof: &AptosProofOfPermission,
    mk: &MultiKeyInner,
    ms: &MultiKeySigInner,
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    // 1. Synchronous structural validation — fail fast before any RPC.
    validate(mk, ms)?;

    // 2. Pair each set bitmap position with its signature; build the
    //    per-position verify futures. Each future fully verifies one
    //    position's signature (cryptographic check only; no auth-key,
    //    no ACL).
    let positions = bitmap_iter_ones(&ms.bitmap).zip(ms.signatures.iter());
    let position_futs: Vec<_> = positions
        .map(|(pos, sig)| {
            let pk = &mk.public_keys[pos];
            super::any::verify_position(req, contract, proof, pk, sig, chain_rpc)
        })
        .collect();

    // 3. Run per-position signature checks alongside the MultiKey-level
    //    auth-key check and the dapp ACL view, all in parallel.
    let rpc = chain_rpc.aptos_rpc_for_chain_id(contract.chain_id)?;
    let (sig_res, auth_res, perm_res) = tokio::join!(
        futures::future::try_join_all(position_futs),
        check_multi_key_auth_key(proof, mk, rpc),
        check_permission(contract, &req.payload.domain, proof, rpc),
    );
    sig_res?;
    auth_res?;
    perm_res?;
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// MSB-first iteration: bit 0 = top of first byte, bit 7 = bottom of
    /// first byte, bit 8 = top of second byte.
    #[test]
    fn bitmap_iter_ones_msb_first() {
        // 0xA0 = 0b1010_0000 — positions 0 and 2 set.
        assert_eq!(bitmap_iter_ones(&[0xA0]).collect::<Vec<_>>(), vec![0, 2]);
        // 0x05 = 0b0000_0101 — positions 5 and 7 set.
        assert_eq!(bitmap_iter_ones(&[0x05]).collect::<Vec<_>>(), vec![5, 7]);
        // Two-byte: 0x80 0x01 = bit 0 + bit 15.
        assert_eq!(
            bitmap_iter_ones(&[0x80, 0x01]).collect::<Vec<_>>(),
            vec![0, 15]
        );
        // Empty bitmap → empty iter.
        assert_eq!(bitmap_iter_ones(&[]).collect::<Vec<_>>(), Vec::<usize>::new());
        // All zeros → empty iter.
        assert_eq!(
            bitmap_iter_ones(&[0x00, 0x00, 0x00, 0x00]).collect::<Vec<_>>(),
            Vec::<usize>::new()
        );
    }

    /// MultiKey auth-key preimage shape: SHA3-256(BCS(MultiKey) || 0x03).
    /// Spot-checks against a hand-built 2-of-2 MultiKey with two zero
    /// Ed25519 public keys.
    #[test]
    fn auth_key_known_preimage() {
        let mk = MultiKeyInner {
            public_keys: vec![
                AnyPublicKeyInner::Ed25519(vec![0u8; 32]),
                AnyPublicKeyInner::Ed25519(vec![0u8; 32]),
            ],
            signatures_required: 2,
        };
        let got = authentication_key(&mk);

        // BCS(MultiKey) for this hand-built input:
        //   ULEB128(len=2)=0x02 || pk0_bcs || pk1_bcs || u8(2)
        // pk_i_bcs = ULEB128(variant=0)=0x00 || ULEB128(32)=0x20 || 32×0x00
        // → bytes = [0x02, 0x00, 0x20, 0×32, 0x00, 0x20, 0×32, 0x02]
        let mut preimage = Vec::new();
        preimage.push(0x02);              // Vec len = 2
        preimage.push(0x00);              // AnyPublicKey variant 0 = Ed25519
        preimage.push(0x20);              // ULEB128(32)
        preimage.extend_from_slice(&[0u8; 32]);
        preimage.push(0x00);
        preimage.push(0x20);
        preimage.extend_from_slice(&[0u8; 32]);
        preimage.push(0x02);              // signatures_required = 2

        let mut h = Sha3_256::new();
        h.update(&preimage);
        h.update([SCHEME_MULTI_KEY]);     // 0x03
        let expected: [u8; 32] = h.finalize().into();

        assert_eq!(got, expected);
    }

    fn ed25519_pk() -> AnyPublicKeyInner {
        AnyPublicKeyInner::Ed25519(vec![0u8; 32])
    }
    fn ed25519_sig() -> AnySignatureInner {
        AnySignatureInner::Ed25519(vec![0u8; 64])
    }

    #[test]
    fn validate_rejects_zero_threshold() {
        let mk = MultiKeyInner {
            public_keys: vec![ed25519_pk(), ed25519_pk()],
            signatures_required: 0,
        };
        let ms = MultiKeySigInner { signatures: vec![], bitmap: vec![] };
        let err = validate(&mk, &ms).unwrap_err().to_string();
        assert!(err.contains("signatures_required"), "got: {}", err);
    }

    #[test]
    fn validate_rejects_too_many_signers() {
        let mk = MultiKeyInner {
            public_keys: (0..33).map(|_| ed25519_pk()).collect(),
            signatures_required: 1,
        };
        let ms = MultiKeySigInner {
            signatures: vec![ed25519_sig()],
            bitmap: vec![0x80],
        };
        let err = validate(&mk, &ms).unwrap_err().to_string();
        assert!(err.contains("exceeds max"), "got: {}", err);
    }

    #[test]
    fn validate_rejects_bitmap_popcount_mismatch() {
        // 2-of-3 with bitmap claiming bits 0 + 1 (popcount=2) but only one signature.
        let mk = MultiKeyInner {
            public_keys: vec![ed25519_pk(), ed25519_pk(), ed25519_pk()],
            signatures_required: 2,
        };
        let ms = MultiKeySigInner {
            signatures: vec![ed25519_sig()],
            bitmap: vec![0xC0], // 0b1100_0000 — bits 0,1
        };
        let err = validate(&mk, &ms).unwrap_err().to_string();
        assert!(err.contains("set-bit count"), "got: {}", err);
    }

    #[test]
    fn validate_rejects_too_few_signatures() {
        // signatures.len() = 2 but signatures_required = 3 — under threshold.
        let mk = MultiKeyInner {
            public_keys: vec![ed25519_pk(), ed25519_pk(), ed25519_pk()],
            signatures_required: 3,
        };
        let ms = MultiKeySigInner {
            signatures: vec![ed25519_sig(), ed25519_sig()],
            bitmap: vec![0xC0], // bits 0,1 — popcount=2
        };
        let err = validate(&mk, &ms).unwrap_err().to_string();
        assert!(err.contains("signatures_required"), "got: {}", err);
    }

    #[test]
    fn validate_accepts_oversigning() {
        // Threshold = 2 but 3 signatures supplied at positions {0,1,2}. aptos-core
        // accepts this as long as every signature verifies (and downstream sig
        // verify will catch invalid ones).
        let mk = MultiKeyInner {
            public_keys: vec![ed25519_pk(), ed25519_pk(), ed25519_pk()],
            signatures_required: 2,
        };
        let ms = MultiKeySigInner {
            signatures: vec![ed25519_sig(), ed25519_sig(), ed25519_sig()],
            bitmap: vec![0xE0], // 0b1110_0000 — bits 0,1,2
        };
        validate(&mk, &ms).expect("3-of-2 over-signing should validate");
    }

    #[test]
    fn validate_rejects_threshold_exceeds_pks() {
        // Threshold > public_keys.len() — MultiKey itself is malformed
        // (aptos-core's MultiKey::new rejects this with the same message).
        let mk = MultiKeyInner {
            public_keys: vec![ed25519_pk(), ed25519_pk()],
            signatures_required: 3,
        };
        let ms = MultiKeySigInner {
            signatures: vec![ed25519_sig(), ed25519_sig()],
            bitmap: vec![0xC0],
        };
        let err = validate(&mk, &ms).unwrap_err().to_string();
        assert!(err.contains("signatures_required"), "got: {}", err);
    }

    #[test]
    fn validate_rejects_oob_bit_position() {
        // bit 7 set but only 2 public keys; valid positions are {0, 1}.
        let mk = MultiKeyInner {
            public_keys: vec![ed25519_pk(), ed25519_pk()],
            signatures_required: 1,
        };
        let ms = MultiKeySigInner {
            signatures: vec![ed25519_sig()],
            bitmap: vec![0x01], // 0b0000_0001 — bit 7
        };
        let err = validate(&mk, &ms).unwrap_err().to_string();
        assert!(err.contains("position"), "got: {}", err);
    }

    #[test]
    fn validate_accepts_2_of_3_ed25519() {
        // Positions 0 and 2 signed; positions 0/1/2 in the public key set.
        let mk = MultiKeyInner {
            public_keys: vec![ed25519_pk(), ed25519_pk(), ed25519_pk()],
            signatures_required: 2,
        };
        let ms = MultiKeySigInner {
            signatures: vec![ed25519_sig(), ed25519_sig()],
            bitmap: vec![0xA0], // 0b1010_0000 — bits 0,2
        };
        validate(&mk, &ms).expect("2-of-3 Ed25519 should validate");
    }
}
