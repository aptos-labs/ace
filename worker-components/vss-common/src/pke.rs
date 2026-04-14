// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! PKE types mirroring `ts-sdk/src/pke/index.ts` and `contracts/pke/sources/pke.move`.
//!
//! Outer enums use a 1-byte scheme tag manually prepended; inner struct fields are
//! serialized with `bcs::to_bytes()` to match the BCS wire format.

use anyhow::{anyhow, Result};
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
