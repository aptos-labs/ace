// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Verification for the legacy K-of-N `MultiEd25519` account type —
//! Aptos `pk_scheme = 2` / `sig_scheme = 2`.
//!
//! A `MultiEd25519` account holds a flat list of raw 32-byte Ed25519
//! public keys plus a threshold:
//!
//!   `auth_key = SHA3-256( pk_1 || pk_2 || ... || pk_N || threshold || 0x01 )`
//!
//! where `0x01` is `Scheme::MultiEd25519` (aptos-core
//! `types/src/transaction/authenticator.rs` `Scheme::MultiEd25519 = 1`).
//! The `MultiEd25519Signature` carries a flat list of 64-byte raw Ed25519
//! signatures plus a fixed 4-byte bitmap that picks which N of the M
//! public-key positions signed. Bits are MSB-first within each byte —
//! bit i ⇔ `bitmap[i/8] & (0x80 >> (i%8))` — and traversed in ascending
//! position order. Signatures pair with set positions positionally: the
//! i-th set bit's position picks `public_keys[pos]`, paired with
//! `signatures[i]`.
//!
//! Wire layout is **flat byte concatenation** (different from the modern
//! `MultiKey` scheme which uses `Vec<AnyPublicKey>` / `Vec<AnySignature>`):
//!
//!   `MultiEd25519PublicKey` BCS = `serialize_bytes(pk_1 || ... || pk_N || threshold)`
//!   `MultiEd25519Signature` BCS = `serialize_bytes(sig_1 || ... || sig_K || bitmap[4])`
//!
//! See aptos-core `crates/aptos-crypto/src/multi_ed25519.rs::to_bytes`. The
//! outer length prefix comes from aptos-crypto-derive's `SerializeKey`
//! macro which emits `serialize_newtype_struct(name, serde_bytes::Bytes(...))`
//! — equivalent to `serialize_bytes(...)` at the BCS level.
//!
//! Verification (one request):
//!   1. Parse the flat byte layouts into [`MultiEd25519PublicKeyInner`]
//!      and [`MultiEd25519SignatureInner`] (done by the custom serde in
//!      [`super::AptosProofOfPermission`]).
//!   2. Structural validation (cheap, fail-fast before any RPC) —
//!      [`validate`] mirrors aptos-core's `verify_arbitrary_msg`
//!      structural checks at `crates/aptos-crypto/src/multi_ed25519.rs:511`.
//!   3. `tokio::join!` over (per-position signature verification — Ed25519
//!      against the pretty-message string, reusing
//!      the account-level Ed25519 signature helper — plus the
//!      MultiEd25519-level on-chain auth-key match, plus one dapp ACL
//!      view call against `proof.user_addr`).
//!
//! Like `MultiKey`, `MultiEd25519` accepts over-signing
//! (`signatures.len() >= signatures_required`) as long as every supplied
//! signature verifies. Matches aptos-core's
//! `verify_arbitrary_msg`/MultiKeyAuthenticator policy.

use anyhow::{anyhow, Result};
use sha3::{Digest, Sha3_256};

// `Scheme::MultiEd25519 = 1` — final suffix byte in the MultiEd25519
// auth-key preimage. See `aptos_types::transaction::authenticator::Scheme`.
const SCHEME_MULTI_ED25519: u8 = 1;

// Mirrors aptos-core's `MAX_NUM_OF_KEYS: usize = 32` for MultiEd25519
// (`crates/aptos-crypto/src/multi_ed25519.rs:25`).
const MAX_NUM_OF_KEYS: usize = 32;

// `BITMAP_NUM_OF_BYTES = 4` in aptos-core — MultiEd25519's bitmap is a
// fixed 4-byte field, not variable-length like MultiKey's.
pub(crate) const BITMAP_NUM_OF_BYTES: usize = 4;

const ED25519_PK_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;

// ── Wire types ────────────────────────────────────────────────────────────────

/// Parsed inner shape of `MultiEd25519PublicKey`. The on-the-wire BCS is
/// `serialize_bytes(pk_1 || ... || pk_N || threshold)`; the custom serde in
/// [`super::AptosProofOfPermission`] reads the `ByteBuf` and calls
/// [`MultiEd25519PublicKeyInner::from_flat_bytes`] to parse the inner
/// structure.
#[derive(Clone, Debug)]
pub struct MultiEd25519PublicKeyInner {
    pub public_keys: Vec<[u8; ED25519_PK_LEN]>,
    pub threshold: u8,
}

/// Parsed inner shape of `MultiEd25519Signature`. The on-the-wire BCS is
/// `serialize_bytes(sig_1 || ... || sig_K || bitmap[4])`; the custom serde
/// in [`super::AptosProofOfPermission`] reads the `ByteBuf` and calls
/// [`MultiEd25519SignatureInner::from_flat_bytes`] to parse the inner
/// structure.
#[derive(Clone, Debug)]
pub struct MultiEd25519SignatureInner {
    pub signatures: Vec<[u8; ED25519_SIG_LEN]>,
    pub bitmap: [u8; BITMAP_NUM_OF_BYTES],
}

impl MultiEd25519PublicKeyInner {
    /// Parses `pk_1 || pk_2 || ... || pk_N || threshold` into the inner
    /// structure. Length must be `N * 32 + 1` for some `1 <= N <= 32`.
    pub fn from_flat_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(anyhow!("multi_ed25519: public_key bytes empty"));
        }
        let payload_len = bytes.len() - 1;
        if payload_len % ED25519_PK_LEN != 0 {
            return Err(anyhow!(
                "multi_ed25519: public_key payload length {} not a multiple of {} (plus 1 threshold byte)",
                payload_len,
                ED25519_PK_LEN,
            ));
        }
        let n = payload_len / ED25519_PK_LEN;
        if n == 0 || n > MAX_NUM_OF_KEYS {
            return Err(anyhow!(
                "multi_ed25519: public_keys.len() {} not in 1..={}",
                n,
                MAX_NUM_OF_KEYS,
            ));
        }
        let mut public_keys = Vec::with_capacity(n);
        for i in 0..n {
            let mut pk = [0u8; ED25519_PK_LEN];
            pk.copy_from_slice(&bytes[i * ED25519_PK_LEN..(i + 1) * ED25519_PK_LEN]);
            public_keys.push(pk);
        }
        let threshold = bytes[payload_len];
        Ok(Self {
            public_keys,
            threshold,
        })
    }

    /// Re-emits the flat byte layout `pk_1 || ... || pk_N || threshold`.
    /// Used by the custom serializer + the auth-key preimage.
    pub fn to_flat_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.public_keys.len() * ED25519_PK_LEN + 1);
        for pk in &self.public_keys {
            out.extend_from_slice(pk);
        }
        out.push(self.threshold);
        out
    }
}

impl MultiEd25519SignatureInner {
    /// Parses `sig_1 || ... || sig_K || bitmap[4]` into the inner structure.
    /// Length must be `K * 64 + 4` for some `1 <= K <= 32`.
    pub fn from_flat_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < BITMAP_NUM_OF_BYTES {
            return Err(anyhow!(
                "multi_ed25519: signature bytes too short ({} < {})",
                bytes.len(),
                BITMAP_NUM_OF_BYTES,
            ));
        }
        let sigs_len = bytes.len() - BITMAP_NUM_OF_BYTES;
        if sigs_len % ED25519_SIG_LEN != 0 {
            return Err(anyhow!(
                "multi_ed25519: signature payload length {} not a multiple of {} (plus 4 bitmap bytes)",
                sigs_len,
                ED25519_SIG_LEN,
            ));
        }
        let k = sigs_len / ED25519_SIG_LEN;
        if k == 0 || k > MAX_NUM_OF_KEYS {
            return Err(anyhow!(
                "multi_ed25519: signatures.len() {} not in 1..={}",
                k,
                MAX_NUM_OF_KEYS,
            ));
        }
        let mut signatures = Vec::with_capacity(k);
        for i in 0..k {
            let mut sig = [0u8; ED25519_SIG_LEN];
            sig.copy_from_slice(&bytes[i * ED25519_SIG_LEN..(i + 1) * ED25519_SIG_LEN]);
            signatures.push(sig);
        }
        let mut bitmap = [0u8; BITMAP_NUM_OF_BYTES];
        bitmap.copy_from_slice(&bytes[sigs_len..]);
        Ok(Self { signatures, bitmap })
    }

    /// Re-emits the flat byte layout `sig_1 || ... || sig_K || bitmap[4]`.
    pub fn to_flat_bytes(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(self.signatures.len() * ED25519_SIG_LEN + BITMAP_NUM_OF_BYTES);
        for sig in &self.signatures {
            out.extend_from_slice(sig);
        }
        out.extend_from_slice(&self.bitmap);
        out
    }
}

// ── Authentication-key derivation ────────────────────────────────────────────

/// Computes the on-chain authentication key for a MultiEd25519 account:
///
///   `auth_key = SHA3-256( pk_1 || ... || pk_N || threshold || 0x01 )`
///
/// Mirrors aptos-core's `AuthenticationKey::multi_ed25519` (which calls
/// `from_preimage(public_key.to_bytes(), Scheme::MultiEd25519)`).
pub(crate) fn authentication_key(pk: &MultiEd25519PublicKeyInner) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    for k in &pk.public_keys {
        hasher.update(k);
    }
    hasher.update([pk.threshold]);
    hasher.update([SCHEME_MULTI_ED25519]);
    hasher.finalize().into()
}

// ── Bitmap iteration ─────────────────────────────────────────────────────────

/// Iterates set-bit positions in MSB-first order across the fixed 4-byte
/// bitmap. Matches aptos-core's `bitmap_get_bit`: position p maps to
/// `bitmap[p/8] & (0x80 >> (p%8))`.
pub(crate) fn bitmap_iter_ones(
    bitmap: &[u8; BITMAP_NUM_OF_BYTES],
) -> impl Iterator<Item = usize> + '_ {
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

/// Cheap synchronous checks that reject malformed MultiEd25519 wire payloads
/// before any RPC. Mirrors aptos-core's
/// `MultiEd25519Signature::verify_arbitrary_msg` structural invariants
/// (`crates/aptos-crypto/src/multi_ed25519.rs:511-558`):
///
///   1. `threshold >= 1`                       — MultiEd25519PublicKey::new
///   2. `1 <= public_keys.len() <= 32`         — MultiEd25519PublicKey::new
///   3. `public_keys.len() >= threshold`       — MultiEd25519PublicKey::new
///   4. `popcount(bitmap) == signatures.len()` — verify_arbitrary_msg
///   5. `popcount(bitmap) >= threshold`        — verify_arbitrary_msg
///   6. `last_set_bit(bitmap) < public_keys.len()` — verify_arbitrary_msg
pub(crate) fn validate(
    pk: &MultiEd25519PublicKeyInner,
    sig: &MultiEd25519SignatureInner,
) -> Result<()> {
    if pk.threshold == 0 {
        return Err(anyhow!("multi_ed25519: threshold must be >= 1"));
    }
    if pk.public_keys.is_empty() {
        return Err(anyhow!("multi_ed25519: public_keys cannot be empty"));
    }
    if pk.public_keys.len() > MAX_NUM_OF_KEYS {
        return Err(anyhow!(
            "multi_ed25519: public_keys.len() {} exceeds max {}",
            pk.public_keys.len(),
            MAX_NUM_OF_KEYS,
        ));
    }
    if pk.public_keys.len() < pk.threshold as usize {
        return Err(anyhow!(
            "multi_ed25519: public_keys.len() {} < threshold {}",
            pk.public_keys.len(),
            pk.threshold,
        ));
    }
    let set_bits: Vec<usize> = bitmap_iter_ones(&sig.bitmap).collect();
    if set_bits.len() != sig.signatures.len() {
        return Err(anyhow!(
            "multi_ed25519: bitmap set-bit count {} != signatures.len() {}",
            set_bits.len(),
            sig.signatures.len(),
        ));
    }
    if sig.signatures.len() < pk.threshold as usize {
        return Err(anyhow!(
            "multi_ed25519: signatures.len() {} < threshold {}",
            sig.signatures.len(),
            pk.threshold,
        ));
    }
    if let Some(&bad) = set_bits.iter().find(|&&p| p >= pk.public_keys.len()) {
        return Err(anyhow!(
            "multi_ed25519: bitmap position {} >= public_keys.len() {}",
            bad,
            pk.public_keys.len(),
        ));
    }
    Ok(())
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn pk(byte: u8) -> [u8; 32] {
        [byte; 32]
    }
    fn sig_bytes() -> [u8; 64] {
        [0u8; 64]
    }

    #[test]
    fn bitmap_iter_ones_msb_first() {
        // 0xA0 = 0b1010_0000 — positions 0 and 2 set.
        assert_eq!(
            bitmap_iter_ones(&[0xA0, 0, 0, 0]).collect::<Vec<_>>(),
            vec![0, 2]
        );
        // Two-byte: 0x80 0x01 = bit 0 + bit 15.
        assert_eq!(
            bitmap_iter_ones(&[0x80, 0x01, 0, 0]).collect::<Vec<_>>(),
            vec![0, 15]
        );
        // All zeros → empty iter.
        assert_eq!(
            bitmap_iter_ones(&[0, 0, 0, 0]).collect::<Vec<_>>(),
            Vec::<usize>::new()
        );
    }

    #[test]
    fn auth_key_known_preimage() {
        // 2-of-2 over two distinguishable pks. Preimage is
        //   pk_a (32B = 0xAA) || pk_b (32B = 0xBB) || threshold=0x02 || 0x01.
        let inner = MultiEd25519PublicKeyInner {
            public_keys: vec![pk(0xAA), pk(0xBB)],
            threshold: 2,
        };
        let got = authentication_key(&inner);

        let mut h = Sha3_256::new();
        h.update(pk(0xAA));
        h.update(pk(0xBB));
        h.update([0x02u8, 0x01u8]);
        let expected: [u8; 32] = h.finalize().into();
        assert_eq!(got, expected);
    }

    #[test]
    fn flat_bytes_roundtrip_pk() {
        let inner = MultiEd25519PublicKeyInner {
            public_keys: vec![pk(0x01), pk(0x02), pk(0x03)],
            threshold: 2,
        };
        let flat = inner.to_flat_bytes();
        assert_eq!(flat.len(), 3 * 32 + 1);
        let back = MultiEd25519PublicKeyInner::from_flat_bytes(&flat).unwrap();
        assert_eq!(back.public_keys, inner.public_keys);
        assert_eq!(back.threshold, inner.threshold);
    }

    #[test]
    fn flat_bytes_roundtrip_sig() {
        let inner = MultiEd25519SignatureInner {
            signatures: vec![sig_bytes(), sig_bytes()],
            bitmap: [0xC0, 0, 0, 0],
        };
        let flat = inner.to_flat_bytes();
        assert_eq!(flat.len(), 2 * 64 + 4);
        let back = MultiEd25519SignatureInner::from_flat_bytes(&flat).unwrap();
        assert_eq!(back.signatures.len(), 2);
        assert_eq!(back.bitmap, [0xC0, 0, 0, 0]);
    }

    #[test]
    fn from_flat_bytes_rejects_bad_pk_length() {
        // 1 byte short — not a multiple of 32 after stripping threshold byte.
        let err = MultiEd25519PublicKeyInner::from_flat_bytes(&[0u8; 32]).unwrap_err();
        assert!(err.to_string().contains("not a multiple"), "{}", err);
    }

    #[test]
    fn from_flat_bytes_rejects_bad_sig_length() {
        // Only 3 bytes — short of the 4-byte bitmap.
        let err = MultiEd25519SignatureInner::from_flat_bytes(&[0u8; 3]).unwrap_err();
        assert!(err.to_string().contains("too short"), "{}", err);
    }

    #[test]
    fn validate_rejects_zero_threshold() {
        let pk = MultiEd25519PublicKeyInner {
            public_keys: vec![pk(0x01)],
            threshold: 0,
        };
        let sig = MultiEd25519SignatureInner {
            signatures: vec![],
            bitmap: [0; 4],
        };
        let err = validate(&pk, &sig).unwrap_err().to_string();
        assert!(err.contains("threshold"), "got: {}", err);
    }

    #[test]
    fn validate_rejects_threshold_exceeds_pks() {
        let pk = MultiEd25519PublicKeyInner {
            public_keys: vec![pk(0x01), pk(0x02)],
            threshold: 3,
        };
        let sig = MultiEd25519SignatureInner {
            signatures: vec![sig_bytes(), sig_bytes()],
            bitmap: [0xC0, 0, 0, 0],
        };
        let err = validate(&pk, &sig).unwrap_err().to_string();
        assert!(err.contains("threshold"), "got: {}", err);
    }

    #[test]
    fn validate_rejects_too_many_signers() {
        let pk = MultiEd25519PublicKeyInner {
            public_keys: (0..33).map(|_| pk(0x01)).collect(),
            threshold: 1,
        };
        let sig = MultiEd25519SignatureInner {
            signatures: vec![sig_bytes()],
            bitmap: [0x80, 0, 0, 0],
        };
        let err = validate(&pk, &sig).unwrap_err().to_string();
        assert!(err.contains("exceeds max"), "got: {}", err);
    }

    #[test]
    fn validate_rejects_popcount_mismatch() {
        let pk = MultiEd25519PublicKeyInner {
            public_keys: vec![pk(0x01), pk(0x02), pk(0x03)],
            threshold: 2,
        };
        let sig = MultiEd25519SignatureInner {
            signatures: vec![sig_bytes()], // 1 sig but bitmap has 2 set
            bitmap: [0xC0, 0, 0, 0],       // bits 0,1
        };
        let err = validate(&pk, &sig).unwrap_err().to_string();
        assert!(err.contains("set-bit count"), "got: {}", err);
    }

    #[test]
    fn validate_rejects_too_few_signatures() {
        let pk = MultiEd25519PublicKeyInner {
            public_keys: vec![pk(0x01), pk(0x02), pk(0x03)],
            threshold: 3,
        };
        let sig = MultiEd25519SignatureInner {
            signatures: vec![sig_bytes(), sig_bytes()], // 2 sigs but threshold 3
            bitmap: [0xC0, 0, 0, 0],
        };
        let err = validate(&pk, &sig).unwrap_err().to_string();
        assert!(err.contains("threshold"), "got: {}", err);
    }

    #[test]
    fn validate_rejects_oob_bit_position() {
        // bitmap[0] = 0b0010_0000 → bit 2 set; only 2 pubkeys → positions {0,1} valid.
        let pk = MultiEd25519PublicKeyInner {
            public_keys: vec![pk(0x01), pk(0x02)],
            threshold: 1,
        };
        let sig = MultiEd25519SignatureInner {
            signatures: vec![sig_bytes()],
            bitmap: [0x20, 0, 0, 0],
        };
        let err = validate(&pk, &sig).unwrap_err().to_string();
        assert!(err.contains("position"), "got: {}", err);
    }

    #[test]
    fn validate_accepts_2_of_3() {
        let pk = MultiEd25519PublicKeyInner {
            public_keys: vec![pk(0x01), pk(0x02), pk(0x03)],
            threshold: 2,
        };
        let sig = MultiEd25519SignatureInner {
            signatures: vec![sig_bytes(), sig_bytes()],
            bitmap: [0xA0, 0, 0, 0], // bits 0,2
        };
        validate(&pk, &sig).expect("2-of-3 should validate");
    }

    #[test]
    fn validate_accepts_oversigning() {
        // 3-of-2: 3 valid sigs, threshold 2 — aptos-core accepts.
        let pk = MultiEd25519PublicKeyInner {
            public_keys: vec![pk(0x01), pk(0x02), pk(0x03)],
            threshold: 2,
        };
        let sig = MultiEd25519SignatureInner {
            signatures: vec![sig_bytes(), sig_bytes(), sig_bytes()],
            bitmap: [0xE0, 0, 0, 0], // bits 0,1,2
        };
        validate(&pk, &sig).expect("3-of-2 over-signing should validate");
    }
}
