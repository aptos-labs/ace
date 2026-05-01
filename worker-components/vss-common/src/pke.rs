// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! PKE types mirroring `ts-sdk/src/pke/index.ts` and `contracts/pke/sources/pke.move`.
//!
//! Outer enums use a 1-byte scheme tag manually prepended; inner struct fields are
//! serialized with `bcs::to_bytes()` to match the BCS wire format.

use anyhow::{anyhow, Result};
use curve25519_dalek::{ristretto::CompressedRistretto, Scalar};
use serde::{Deserialize, Serialize};

pub const SCHEME_ELGAMAL_OTP_RISTRETTO255: u8 = 0;

// ── EncryptionKey ─────────────────────────────────────────────────────────────

/// Wire: [u8 scheme=0x00] [ULEB128(32)][32B enc_base] [ULEB128(32)][32B public_point]
pub enum EncryptionKey {
    ElGamalOtpRistretto255 {
        enc_base: [u8; 32],
        public_point: [u8; 32],
    },
}

#[derive(Serialize, Deserialize)]
struct ElGamalOtpRistretto255EncKeyInner {
    enc_base: Vec<u8>,
    public_point: Vec<u8>,
}

impl EncryptionKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            EncryptionKey::ElGamalOtpRistretto255 { enc_base, public_point } => {
                let inner = ElGamalOtpRistretto255EncKeyInner {
                    enc_base: enc_base.to_vec(),
                    public_point: public_point.to_vec(),
                };
                let mut out = vec![SCHEME_ELGAMAL_OTP_RISTRETTO255];
                out.extend(bcs::to_bytes(&inner).expect("bcs serialization failed"));
                out
            }
        }
    }

    /// Parse from `get_pke_enc_key_bcs` output: [0x00][ULEB128(32)+32B enc_base][ULEB128(32)+32B public_point] = 67 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() {
            return Err(anyhow!("empty bytes"));
        }
        match bytes[0] {
            SCHEME_ELGAMAL_OTP_RISTRETTO255 => {
                let inner: ElGamalOtpRistretto255EncKeyInner = bcs::from_bytes(&bytes[1..])
                    .map_err(|e| anyhow!("pke::EncryptionKey::from_bytes: {}", e))?;
                Ok(EncryptionKey::ElGamalOtpRistretto255 {
                    enc_base: inner
                        .enc_base
                        .try_into()
                        .map_err(|_| anyhow!("enc_base must be 32 bytes"))?,
                    public_point: inner
                        .public_point
                        .try_into()
                        .map_err(|_| anyhow!("public_point must be 32 bytes"))?,
                })
            }
            s => Err(anyhow!("unsupported PKE scheme {}", s)),
        }
    }
}

// ── Ciphertext ────────────────────────────────────────────────────────────────

/// Wire: [u8 scheme=0x00] [ULEB128(32)+32B c0] [ULEB128(32)+32B c1] [ULEB128(len)+sym_ciph] [ULEB128(32)+32B mac]
pub enum Ciphertext {
    ElGamalOtpRistretto255 {
        c0: [u8; 32],
        c1: [u8; 32],
        sym_ciph: Vec<u8>,
        mac: [u8; 32],
    },
}

#[derive(Serialize)]
struct ElGamalOtpRistretto255CiphertextInner {
    c0: Vec<u8>,
    c1: Vec<u8>,
    sym_ciph: Vec<u8>,
    mac: Vec<u8>,
}

impl Ciphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Ciphertext::ElGamalOtpRistretto255 { c0, c1, sym_ciph, mac } => {
                let inner = ElGamalOtpRistretto255CiphertextInner {
                    c0: c0.to_vec(),
                    c1: c1.to_vec(),
                    sym_ciph: sym_ciph.clone(),
                    mac: mac.to_vec(),
                };
                let mut out = vec![SCHEME_ELGAMAL_OTP_RISTRETTO255];
                out.extend(bcs::to_bytes(&inner).expect("bcs serialization failed"));
                out
            }
        }
    }
}

// ── BCS mirror types (for decoding get_session_bcs view output) ───────────────

/// BCS mirror of `pke_elgamal_otp_ristretto255::Ciphertext`.
/// `CompressedRistretto { data: Vec<u8> }` BCS-encodes identically to `Vec<u8>`.
#[derive(Serialize, Deserialize)]
pub struct BcsCiphertextInner {
    pub c0: Vec<u8>,
    pub c1: Vec<u8>,
    pub sym_ciph: Vec<u8>,
    pub mac: Vec<u8>,
}

/// BCS mirror of `pke::Ciphertext` enum (variant 0 = ElGamalOtpRistretto255).
#[derive(Serialize, Deserialize)]
pub enum BcsCiphertext {
    ElGamalOtpRistretto255(BcsCiphertextInner),
}

impl From<&Ciphertext> for BcsCiphertext {
    fn from(ct: &Ciphertext) -> Self {
        match ct {
            Ciphertext::ElGamalOtpRistretto255 { c0, c1, sym_ciph, mac } => {
                BcsCiphertext::ElGamalOtpRistretto255(BcsCiphertextInner {
                    c0: c0.to_vec(),
                    c1: c1.to_vec(),
                    sym_ciph: sym_ciph.clone(),
                    mac: mac.to_vec(),
                })
            }
        }
    }
}

// ── PKE decrypt ───────────────────────────────────────────────────────────────

/// Decrypt a ciphertext from wire bytes `[scheme][BCS inner]` using the given decryption key.
pub fn pke_decrypt_bytes(dk_bytes: &[u8], ct_bytes: &[u8]) -> Result<Vec<u8>> {
    if ct_bytes.is_empty() {
        return Err(anyhow!("empty ciphertext bytes"));
    }
    if ct_bytes[0] != SCHEME_ELGAMAL_OTP_RISTRETTO255 {
        return Err(anyhow!("unsupported PKE scheme {}", ct_bytes[0]));
    }
    let ct_inner: BcsCiphertextInner = bcs::from_bytes(&ct_bytes[1..])
        .map_err(|e| anyhow!("pke_decrypt_bytes: BCS parse: {}", e))?;
    pke_decrypt(dk_bytes, &ct_inner)
}

/// Decrypt a ciphertext using the given decryption key.
///
/// `dk_bytes` format: `[0x00 scheme][0x20 ULEB128(32)][32B encBase][0x20 ULEB128(32)][32B privateScalar]` — 67 bytes
/// (matches `pke.DecryptionKey.toBytes()` from the TypeScript SDK).
/// Decryption only uses `privateScalar` (bytes [35..67]).
pub fn pke_decrypt(dk_bytes: &[u8], ct: &BcsCiphertextInner) -> Result<Vec<u8>> {
    if dk_bytes.len() < 67 || dk_bytes[0] != SCHEME_ELGAMAL_OTP_RISTRETTO255 {
        return Err(anyhow!("invalid dk format (expected 67 bytes with scheme 0x00)"));
    }
    // privateScalar is at bytes[35..67]; bytes[2..34] is encBase (not needed for decryption)
    let dk = Scalar::from_canonical_bytes(
        dk_bytes[35..67].try_into().map_err(|_| anyhow!("dk scalar slice wrong length"))?,
    )
    .into_option()
    .ok_or_else(|| anyhow!("invalid dk scalar"))?;

    let c0_pt = CompressedRistretto(
        ct.c0.as_slice().try_into().map_err(|_| anyhow!("c0 must be 32 bytes"))?,
    )
    .decompress()
    .ok_or_else(|| anyhow!("c0 not a valid Ristretto point"))?;

    let c1_pt = CompressedRistretto(
        ct.c1.as_slice().try_into().map_err(|_| anyhow!("c1 must be 32 bytes"))?,
    )
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
    if expected_mac[..] != ct.mac[..] {
        return Err(anyhow!("PKE decryption failed: HMAC mismatch"));
    }

    // Decrypt
    let otp = crate::crypto::kdf(&seed, b"OTP/ELGAMAL_OTP_RISTRETTO255", ct.sym_ciph.len());
    Ok(otp.iter().zip(ct.sym_ciph.iter()).map(|(a, b)| a ^ b).collect())
}
