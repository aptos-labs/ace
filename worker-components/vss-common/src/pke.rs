// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! PKE types mirroring `ts-sdk/src/pke/index.ts` and `contracts/pke/sources/pke.move`.
//!
//! `EncryptionKey` and `Ciphertext` are serde-derived enums. BCS encodes an enum as
//! `[ULEB128 variant tag][variant fields...]`; for tags 0/1 the ULEB128 is a single
//! byte, so the on-wire format matches `[scheme byte][inner]` exactly. Adding a new
//! scheme is one new variant + one match arm — no per-scheme size table, no manual
//! byte-walking.

use anyhow::{anyhow, Result};
use curve25519_dalek::{ristretto::CompressedRistretto, Scalar};
use serde::{Deserialize, Serialize};

use crate::pke_hpke_x25519_chacha20poly1305 as hpke_scheme;

pub const SCHEME_ELGAMAL_OTP_RISTRETTO255: u8 = 0;
pub const SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305: u8 = 1;

// ── EncryptionKey ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EncryptionKey {
    ElGamalOtpRistretto255(ElGamalOtpRistretto255EncKey),
    HpkeX25519ChaCha20Poly1305(hpke_scheme::EncryptionKey),
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
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ElGamalOtpRistretto255Ciphertext {
    pub c0: Vec<u8>,       // 32 bytes
    pub c1: Vec<u8>,       // 32 bytes
    pub sym_ciph: Vec<u8>,
    pub mac: Vec<u8>,      // 32 bytes
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
    let hmac_key_vec = crate::crypto::kdf(&seed, b"HMAC/ELGAMAL_OTP_RISTRETTO255", 32);
    let hmac_key: [u8; 32] = hmac_key_vec.try_into().unwrap();
    let expected_mac = crate::crypto::hmac_sha3_256(&hmac_key, &ct.sym_ciph);
    if expected_mac != mac_arr {
        return Err(anyhow!("PKE decryption failed: HMAC mismatch"));
    }

    // Decrypt
    let otp = crate::crypto::kdf(&seed, b"OTP/ELGAMAL_OTP_RISTRETTO255", ct.sym_ciph.len());
    Ok(otp.iter().zip(ct.sym_ciph.iter()).map(|(a, b)| a ^ b).collect())
}
