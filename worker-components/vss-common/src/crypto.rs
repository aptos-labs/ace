// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Cryptographic primitives matching `ts-sdk/src/utils.ts` and `ts-sdk/src/pke/elgamal_otp_ristretto255.ts`.
//!
//! All byte formats are wire-compatible with the TypeScript implementation.

use ark_bls12_381::Fr;
use ark_ec::{AffineRepr, CurveGroup};
use ark_ff::PrimeField;
use ark_serialize::CanonicalSerialize;
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};

use crate::pke;

// ── KDF ───────────────────────────────────────────────────────────────────────

/// KDF matching `ts-sdk/src/utils.ts::kdf`.
///
/// Each 32-byte block: SHA3-256(BCS(seed) ++ BCS(dst) ++ LE64(target_len) ++ LE64(block_idx))
/// where BCS(bytes) = ULEB128(len) ++ bytes.
///
/// `seed` must be >= 32 bytes (it is the BCS-encoded Ristretto255 group element = 33 bytes).
pub fn kdf(seed: &[u8], dst: &[u8], target_len: usize) -> Vec<u8> {
    let mut output = Vec::with_capacity(target_len);
    let mut block_idx: u64 = 0;
    let mut remaining = target_len;
    while remaining > 0 {
        let mut hasher = Sha3_256::new();
        // serializeBytes(seed) = ULEB128(seed.len()) ++ seed
        update_with_bcs_bytes(&mut hasher, seed);
        // serializeBytes(dst) = ULEB128(dst.len()) ++ dst
        update_with_bcs_bytes(&mut hasher, dst);
        // serializeU64(target_len) = LE64
        hasher.update((target_len as u64).to_le_bytes());
        // serializeU64(block_idx) = LE64
        hasher.update(block_idx.to_le_bytes());

        let block = hasher.finalize();
        let take = remaining.min(32);
        output.extend_from_slice(&block[..take]);
        remaining -= take;
        block_idx += 1;
    }
    output
}

/// Write ULEB128(bytes.len()) ++ bytes into the hasher.
fn update_with_bcs_bytes(hasher: &mut Sha3_256, bytes: &[u8]) {
    let mut len_buf = Vec::new();
    crate::vss_types::write_uleb128(&mut len_buf, bytes.len() as u64);
    hasher.update(&len_buf);
    hasher.update(bytes);
}

// ── HMAC-SHA3-256 ─────────────────────────────────────────────────────────────

/// HMAC-SHA3-256 matching `ts-sdk/src/utils.ts::hmac_sha3_256`.
///
/// 32-byte key is padded to 64 bytes by appending 32 zero bytes.
/// Standard HMAC construction with ipad=0x36 and opad=0x5c.
pub fn hmac_sha3_256(key: &[u8; 32], msg: &[u8]) -> [u8; 32] {
    let mut padded = [0u8; 64];
    padded[..32].copy_from_slice(key);
    // padded[32..64] = 0x00 (already zero)

    let ipad = [0x36u8; 64];
    let opad = [0x5cu8; 64];

    let inner_key: Vec<u8> = padded.iter().zip(ipad.iter()).map(|(a, b)| a ^ b).collect();
    let outer_key: Vec<u8> = padded.iter().zip(opad.iter()).map(|(a, b)| a ^ b).collect();

    let mut inner = Sha3_256::new();
    inner.update(&inner_key);
    inner.update(msg);
    let inner_hash = inner.finalize();

    let mut outer = Sha3_256::new();
    outer.update(&outer_key);
    outer.update(inner_hash);
    outer.finalize().into()
}

// ── PKE encrypt ───────────────────────────────────────────────────────────────

/// Encrypt `plaintext` under `key`, matching `ts-sdk/src/pke/elgamal_otp_ristretto255.ts::encrypt`.
pub fn pke_encrypt(key: &pke::EncryptionKey, plaintext: &[u8]) -> pke::Ciphertext {
    match key {
        pke::EncryptionKey::ElGamalOtpRistretto255 { enc_base, public_point } => {
            let enc_base_pt = CompressedRistretto(*enc_base)
                .decompress()
                .expect("enc_base is not a valid Ristretto point");
            let public_point_pt = CompressedRistretto(*public_point)
                .decompress()
                .expect("public_point is not a valid Ristretto point");

            // elgamalPtxt = random Ristretto point (the "message" in ElGamal)
            let ephemeral_pt = RistrettoPoint::random(&mut OsRng);
            // elgamalRand = random scalar (ElGamal randomness)
            let r = Scalar::random(&mut OsRng);

            // c0 = r * enc_base_pt
            let c0 = (r * enc_base_pt).compress().to_bytes();
            // c1 = ephemeral_pt + r * public_point_pt
            let c1 = (ephemeral_pt + r * public_point_pt).compress().to_bytes();

            // seed = element.toBytes() = serializeBytes(compressed_point) = [ULEB128(32)][32B]
            let ephemeral_compressed = ephemeral_pt.compress().to_bytes();
            let mut seed = Vec::with_capacity(33);
            seed.push(0x20u8); // ULEB128(32) = 0x20
            seed.extend_from_slice(&ephemeral_compressed);
            // seed is now 33 bytes, matching TypeScript's `elgamalPtxt.toBytes()`

            let otp = kdf(&seed, b"OTP/ELGAMAL_OTP_RISTRETTO255", plaintext.len());
            let sym_ciph: Vec<u8> = otp.iter().zip(plaintext.iter()).map(|(a, b)| a ^ b).collect();

            let hmac_key_vec = kdf(&seed, b"HMAC/ELGAMAL_OTP_RISTRETTO255", 32);
            let hmac_key: [u8; 32] = hmac_key_vec.try_into().expect("kdf produced 32 bytes");
            let mac = hmac_sha3_256(&hmac_key, &sym_ciph);

            pke::Ciphertext::ElGamalOtpRistretto255 { c0, c1, sym_ciph, mac }
        }
    }
}

// ── BLS12-381 Fr helpers ──────────────────────────────────────────────────────

/// Serialize a BLS12-381 Fr element to 32-byte little-endian canonical form.
/// Matches TypeScript `numberToBytesLE(scalar, 32)`.
pub fn fr_to_le_bytes(f: Fr) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    f.serialize_uncompressed(&mut bytes[..]).expect("Fr serialize failed");
    bytes
}

/// Derive a BLS12-381 Fr polynomial coefficient from a PKE decryption key and index.
///
/// Uses SHA3-256("vss-coef-v1/" || dk_bytes || LE64(idx)) reduced mod Fr.
/// Deterministic: same dk + idx always gives the same coefficient.
pub fn fr_from_dk_bytes(dk: &[u8], idx: usize) -> Fr {
    let mut hasher = Sha3_256::new();
    hasher.update(b"vss-coef-v1/");
    hasher.update(dk);
    hasher.update((idx as u64).to_le_bytes());
    let hash: [u8; 32] = hasher.finalize().into();
    Fr::from_le_bytes_mod_order(&hash)
}

/// Deserialize a BLS12-381 Fr element from 32-byte little-endian bytes.
/// Reduces mod Fr order, matching `Fr::from_le_bytes_mod_order`.
pub fn fr_from_le_bytes(bytes: [u8; 32]) -> Fr {
    Fr::from_le_bytes_mod_order(&bytes)
}

/// Evaluate polynomial at `x` using Horner's method.
/// `coefs[0]` is the constant term (secret), `coefs[t-1]` is the highest-degree coefficient.
pub fn poly_eval(coefs: &[Fr], x: Fr) -> Fr {
    let mut result = Fr::from(0u64);
    for c in coefs.iter().rev() {
        result = result * x + c;
    }
    result
}

/// Compute the compressed 48-byte BLS12-381 G1 point `scalar * G1::generator`.
/// Matches TypeScript `bls12_381.G1.ProjectivePoint.BASE.multiply(scalar).toBytes()`.
pub fn g1_compressed(scalar: Fr) -> [u8; 48] {
    let pt: ark_bls12_381::G1Affine =
        (ark_bls12_381::G1Affine::generator() * scalar).into_affine();
    let mut bytes = [0u8; 48];
    pt.serialize_compressed(&mut bytes[..]).expect("G1 serialize failed");
    bytes
}
