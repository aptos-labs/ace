// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! PKE types mirroring `contracts/pke/sources/pke.move`.
//! Schemes 0/1/2 are also mirrored in `ts-sdk/src/pke/index.ts`; scheme 2 is a
//! post-quantum/hybrid prototype and is not production-audited.
//!
//! `EncryptionKey` and `Ciphertext` are serde-derived enums. BCS encodes an enum as
//! `[ULEB128 variant tag][variant fields...]`; for tags 0/1 the ULEB128 is a single
//! byte, so the on-wire format matches `[scheme byte][inner]` exactly. Adding a new
//! scheme is one new variant + one match arm — no per-scheme size table, no manual
//! byte-walking.

pub mod pke_hybrid_x25519_mlkem768_chacha20poly1305;
pub mod pke_hpke_x25519_chacha20poly1305;

use anyhow::{anyhow, Result};
use curve25519_dalek::{ristretto::CompressedRistretto, RistrettoPoint, Scalar};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::pke_hybrid_x25519_mlkem768_chacha20poly1305 as hybrid_pq_scheme;
use crate::pke_hpke_x25519_chacha20poly1305 as hpke_scheme;

pub const SCHEME_ELGAMAL_OTP_RISTRETTO255: u8 = 0;
pub const SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305: u8 = 1;
pub const SCHEME_HYBRID_X25519_MLKEM768_CHACHA20POLY1305: u8 = 2;

// ── Legacy ElGamal KDF/MAC helpers ───────────────────────────────────────────

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

/// Write ULEB128(bytes.len()) ++ bytes into the hasher.
fn update_with_bcs_bytes(hasher: &mut Sha3_256, bytes: &[u8]) {
    let mut len_buf = Vec::new();
    write_uleb128(&mut len_buf, bytes.len() as u64);
    hasher.update(&len_buf);
    hasher.update(bytes);
}

fn write_uleb128(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}

// ── EncryptionKey ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EncryptionKey {
    ElGamalOtpRistretto255(ElGamalOtpRistretto255EncKey),
    HpkeX25519ChaCha20Poly1305(hpke_scheme::EncryptionKey),
    HybridX25519MlKem768ChaCha20Poly1305(hybrid_pq_scheme::EncryptionKey),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElGamalOtpRistretto255EncKey {
    pub enc_base: Vec<u8>,     // 32 bytes
    pub public_point: Vec<u8>, // 32 bytes
}

// ── Ciphertext ────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Ciphertext {
    ElGamalOtpRistretto255(ElGamalOtpRistretto255Ciphertext),
    HpkeX25519ChaCha20Poly1305(hpke_scheme::Ciphertext),
    HybridX25519MlKem768ChaCha20Poly1305(hybrid_pq_scheme::Ciphertext),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElGamalOtpRistretto255Ciphertext {
    pub c0: Vec<u8>,       // 32 bytes
    pub c1: Vec<u8>,       // 32 bytes
    pub sym_ciph: Vec<u8>,
    pub mac: Vec<u8>,      // 32 bytes
}

// ── PKE encrypt ───────────────────────────────────────────────────────────────

/// Encrypt `plaintext` under `key`, matching the TypeScript SDK PKE schemes.
pub fn pke_encrypt(key: &EncryptionKey, plaintext: &[u8]) -> Ciphertext {
    match key {
        EncryptionKey::ElGamalOtpRistretto255(inner) => {
            let enc_base_arr: [u8; 32] = inner
                .enc_base
                .as_slice()
                .try_into()
                .expect("enc_base must be 32 bytes");
            let public_point_arr: [u8; 32] = inner
                .public_point
                .as_slice()
                .try_into()
                .expect("public_point must be 32 bytes");

            let enc_base_pt = CompressedRistretto(enc_base_arr)
                .decompress()
                .expect("enc_base is not a valid Ristretto point");
            let public_point_pt = CompressedRistretto(public_point_arr)
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

            let otp = kdf(&seed, b"OTP/ELGAMAL_OTP_RISTRETTO255", plaintext.len());
            let sym_ciph: Vec<u8> = otp
                .iter()
                .zip(plaintext.iter())
                .map(|(a, b)| a ^ b)
                .collect();

            let hmac_key_vec = kdf(&seed, b"HMAC/ELGAMAL_OTP_RISTRETTO255", 32);
            let hmac_key: [u8; 32] = hmac_key_vec.try_into().expect("kdf produced 32 bytes");
            let mac = hmac_sha3_256(&hmac_key, &sym_ciph);

            Ciphertext::ElGamalOtpRistretto255(ElGamalOtpRistretto255Ciphertext {
                c0: c0.to_vec(),
                c1: c1.to_vec(),
                sym_ciph,
                mac: mac.to_vec(),
            })
        }
        EncryptionKey::HpkeX25519ChaCha20Poly1305(ek) => {
            let ct = hpke_scheme::encrypt(ek, plaintext, b"")
                .expect("HPKE encrypt: invalid public key");
            Ciphertext::HpkeX25519ChaCha20Poly1305(ct)
        }
        EncryptionKey::HybridX25519MlKem768ChaCha20Poly1305(ek) => {
            let ct = hybrid_pq_scheme::encrypt(ek, plaintext, b"")
                .expect("hybrid PKE encrypt: invalid public key");
            Ciphertext::HybridX25519MlKem768ChaCha20Poly1305(ct)
        }
    }
}

// ── PKE decrypt ───────────────────────────────────────────────────────────────

/// Decrypt a `Ciphertext` using the given decryption key. `dk_bytes` is the wire-format
/// decryption key (`[scheme byte][inner BCS]`); the leading scheme byte must match `ct`.
pub fn pke_decrypt(dk_bytes: &[u8], ct: &Ciphertext) -> Result<Vec<u8>> {
    if dk_bytes.is_empty() {
        return Err(anyhow!("empty decryption-key bytes"));
    }
    match ct {
        Ciphertext::ElGamalOtpRistretto255(inner) => {
            if dk_bytes[0] != SCHEME_ELGAMAL_OTP_RISTRETTO255 {
                return Err(anyhow!(
                    "PKE scheme mismatch: dk={}, ct=ElGamalOtpRistretto255",
                    dk_bytes[0]
                ));
            }
            elgamal_otp_ristretto255_decrypt(dk_bytes, inner)
        }
        Ciphertext::HpkeX25519ChaCha20Poly1305(inner) => {
            if dk_bytes[0] != SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305 {
                return Err(anyhow!(
                    "PKE scheme mismatch: dk={}, ct=HpkeX25519ChaCha20Poly1305",
                    dk_bytes[0]
                ));
            }
            let dk = hpke_scheme::DecryptionKey::from_bytes(&dk_bytes[1..])?;
            hpke_scheme::decrypt(&dk, inner, b"")
        }
        Ciphertext::HybridX25519MlKem768ChaCha20Poly1305(inner) => {
            if dk_bytes[0] != SCHEME_HYBRID_X25519_MLKEM768_CHACHA20POLY1305 {
                return Err(anyhow!(
                    "PKE scheme mismatch: dk={}, ct=HybridX25519MlKem768ChaCha20Poly1305",
                    dk_bytes[0]
                ));
            }
            let dk = hybrid_pq_scheme::DecryptionKey::from_bytes(&dk_bytes[1..])?;
            hybrid_pq_scheme::decrypt(&dk, inner, b"")
        }
    }
}

/// Decrypt a ciphertext from its on-wire BCS bytes.
pub fn pke_decrypt_bytes(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<Vec<u8>> {
    let ct: Ciphertext = bcs::from_bytes(ct_bytes)
        .map_err(|e| anyhow!("pke_decrypt_bytes: BCS parse: {}", e))?;
    pke_decrypt(dk_bytes, &ct)
}

/// Decrypt the ElGamal-OTP-Ristretto255 variant.
///
/// `dk_bytes` format: `[0x00 scheme][0x20 ULEB128(32)][32B encBase][0x20 ULEB128(32)][32B privateScalar]` — 67 bytes
/// (matches `pke.DecryptionKey.toBytes()` from the TypeScript SDK).
/// Decryption only uses `privateScalar` (bytes [35..67]).
fn elgamal_otp_ristretto255_decrypt(
    dk_bytes: &[u8],
    ct: &ElGamalOtpRistretto255Ciphertext,
) -> Result<Vec<u8>> {
    if dk_bytes.len() < 67 || dk_bytes[0] != SCHEME_ELGAMAL_OTP_RISTRETTO255 {
        return Err(anyhow!("invalid dk format (expected 67 bytes with scheme 0x00)"));
    }
    // privateScalar is at bytes[35..67]; bytes[2..34] is encBase (not needed for decryption)
    let dk = Scalar::from_canonical_bytes(
        dk_bytes[35..67].try_into().map_err(|_| anyhow!("dk scalar slice wrong length"))?,
    )
    .into_option()
    .ok_or_else(|| anyhow!("invalid dk scalar"))?;

    let c0_arr: [u8; 32] = ct.c0.as_slice().try_into().map_err(|_| anyhow!("c0 must be 32 bytes"))?;
    let c1_arr: [u8; 32] = ct.c1.as_slice().try_into().map_err(|_| anyhow!("c1 must be 32 bytes"))?;
    let mac_arr: [u8; 32] = ct.mac.as_slice().try_into().map_err(|_| anyhow!("mac must be 32 bytes"))?;

    let c0_pt = CompressedRistretto(c0_arr)
        .decompress()
        .ok_or_else(|| anyhow!("c0 not a valid Ristretto point"))?;
    let c1_pt = CompressedRistretto(c1_arr)
        .decompress()
        .ok_or_else(|| anyhow!("c1 not a valid Ristretto point"))?;

    // ephemeral = c1 - dk * c0
    let ephemeral = c1_pt - dk * c0_pt;
    let mut seed = vec![0x20u8]; // ULEB128(32)
    seed.extend_from_slice(&ephemeral.compress().to_bytes());

    // HMAC verify
    let hmac_key_vec = kdf(&seed, b"HMAC/ELGAMAL_OTP_RISTRETTO255", 32);
    let hmac_key: [u8; 32] = hmac_key_vec.try_into().unwrap();
    let expected_mac = hmac_sha3_256(&hmac_key, &ct.sym_ciph);
    if expected_mac != mac_arr {
        return Err(anyhow!("PKE decryption failed: HMAC mismatch"));
    }

    // Decrypt
    let otp = kdf(&seed, b"OTP/ELGAMAL_OTP_RISTRETTO255", ct.sym_ciph.len());
    Ok(otp.iter().zip(ct.sym_ciph.iter()).map(|(a, b)| a ^ b).collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hybrid_scheme_dispatch_round_trip() {
        let (ek_inner, dk_inner) = hybrid_pq_scheme::keygen();
        let ek = EncryptionKey::HybridX25519MlKem768ChaCha20Poly1305(ek_inner);
        let ct = pke_encrypt(&ek, b"hybrid dispatch plaintext");

        let mut dk_bytes = vec![SCHEME_HYBRID_X25519_MLKEM768_CHACHA20POLY1305];
        dk_bytes.extend_from_slice(&dk_inner.to_bytes());

        let got = pke_decrypt(&dk_bytes, &ct).unwrap();
        assert_eq!(got, b"hybrid dispatch plaintext");
    }

    #[test]
    fn hybrid_scheme_mismatch_rejected() {
        let (ek_inner, dk_inner) = hybrid_pq_scheme::keygen();
        let ek = EncryptionKey::HybridX25519MlKem768ChaCha20Poly1305(ek_inner);
        let ct = pke_encrypt(&ek, b"hybrid dispatch plaintext");

        let mut dk_bytes = vec![SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305];
        dk_bytes.extend_from_slice(&dk_inner.to_bytes());

        assert!(pke_decrypt(&dk_bytes, &ct).is_err());
    }
}
