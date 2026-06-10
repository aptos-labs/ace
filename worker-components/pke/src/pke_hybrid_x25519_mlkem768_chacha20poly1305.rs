// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Hybrid PKE for long-lived on-chain share transport:
//!   inner: HPKE-X25519-HKDF-SHA256-ChaCha20Poly1305
//!   outer: ML-KEM-768 shared secret -> HKDF-SHA256 -> ChaCha20-Poly1305
//!
//! This is intentionally a nested construction. The plaintext is first encrypted
//! with the existing X25519 HPKE scheme, and the serialized HPKE ciphertext is then
//! encrypted with a key derived from ML-KEM-768. Historical ciphertexts remain
//! confidential if either X25519 or ML-KEM-768 remains secure.
//!
//! BCS layout (no leading scheme byte; the abstract `pke` outer enum prepends it):
//!   EncryptionKey = HpkeEncryptionKey || [ULEB128(1184)] [1184B ML-KEM ek]
//!   DecryptionKey = HpkeDecryptionKey || [ULEB128(64)]   [64B ML-KEM seed]
//!   Ciphertext    = [ULEB128(1088)] [1088B ML-KEM ct]
//!                   [ULEB128(12)]   [12B nonce]
//!                   [ULEB128(len)]  [len B outer AEAD ct]

use anyhow::{anyhow, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use hkdf::Hkdf;
use ml_kem::{
    kem::{Decapsulate, Encapsulate, Kem, KeyExport},
    MlKem768, Seed,
};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::Sha256;

use crate::pke_hpke_x25519_chacha20poly1305 as hpke_scheme;

const MLKEM768_EK_BYTES: usize = 1184;
const MLKEM768_DK_SEED_BYTES: usize = 64;
const MLKEM768_CT_BYTES: usize = 1088;
const AEAD_KEY_BYTES: usize = 32;
const AEAD_NONCE_BYTES: usize = 12;
const AEAD_TAG_BYTES: usize = 16;
const HKDF_SALT: &[u8] = b"ACE-PKE-HYBRID-X25519-MLKEM768-CHACHA20POLY1305/v0";

// ── BCS wire structs ──────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionKey {
    pub hpke_x25519: hpke_scheme::EncryptionKey,
    pub mlkem768_ek: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionKey {
    pub hpke_x25519: hpke_scheme::DecryptionKey,
    pub mlkem768_seed: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext {
    pub mlkem768_ct: Vec<u8>,
    pub aead_nonce: Vec<u8>,
    pub aead_ct: Vec<u8>,
}

impl EncryptionKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).expect("BCS serialization cannot fail for Vec<u8>")
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let ek: EncryptionKey =
            bcs::from_bytes(data).map_err(|e| anyhow!("Hybrid EncryptionKey BCS decode: {}", e))?;
        ek.validate()?;
        Ok(ek)
    }

    fn validate(&self) -> Result<()> {
        hpke_scheme::EncryptionKey::from_bytes(&self.hpke_x25519.to_bytes())?;
        if self.mlkem768_ek.len() != MLKEM768_EK_BYTES {
            return Err(anyhow!(
                "Hybrid EncryptionKey: mlkem768_ek must be {} bytes, got {}",
                MLKEM768_EK_BYTES,
                self.mlkem768_ek.len()
            ));
        }
        let _ = mlkem768_encapsulation_key(&self.mlkem768_ek)?;
        Ok(())
    }
}

impl DecryptionKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).expect("BCS serialization cannot fail for Vec<u8>")
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let dk: DecryptionKey =
            bcs::from_bytes(data).map_err(|e| anyhow!("Hybrid DecryptionKey BCS decode: {}", e))?;
        dk.validate()?;
        Ok(dk)
    }

    fn validate(&self) -> Result<()> {
        hpke_scheme::DecryptionKey::from_bytes(&self.hpke_x25519.to_bytes())?;
        if self.mlkem768_seed.len() != MLKEM768_DK_SEED_BYTES {
            return Err(anyhow!(
                "Hybrid DecryptionKey: mlkem768_seed must be {} bytes, got {}",
                MLKEM768_DK_SEED_BYTES,
                self.mlkem768_seed.len()
            ));
        }
        let _ = mlkem768_decapsulation_key(&self.mlkem768_seed)?;
        Ok(())
    }
}

impl Ciphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).expect("BCS serialization cannot fail for Vec<u8>")
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let ct: Ciphertext =
            bcs::from_bytes(data).map_err(|e| anyhow!("Hybrid Ciphertext BCS decode: {}", e))?;
        ct.validate()?;
        Ok(ct)
    }

    fn validate(&self) -> Result<()> {
        if self.mlkem768_ct.len() != MLKEM768_CT_BYTES {
            return Err(anyhow!(
                "Hybrid Ciphertext: mlkem768_ct must be {} bytes, got {}",
                MLKEM768_CT_BYTES,
                self.mlkem768_ct.len()
            ));
        }
        if self.aead_nonce.len() != AEAD_NONCE_BYTES {
            return Err(anyhow!(
                "Hybrid Ciphertext: aead_nonce must be {} bytes, got {}",
                AEAD_NONCE_BYTES,
                self.aead_nonce.len()
            ));
        }
        if self.aead_ct.len() < AEAD_TAG_BYTES {
            return Err(anyhow!(
                "Hybrid Ciphertext: aead_ct must be >= {} bytes, got {}",
                AEAD_TAG_BYTES,
                self.aead_ct.len()
            ));
        }
        Ok(())
    }
}

// ── Hybrid PKE ops ────────────────────────────────────────────────────────────

/// Generate a fresh hybrid keypair using OS randomness.
pub fn keygen() -> (EncryptionKey, DecryptionKey) {
    let (hpke_ek, hpke_dk) = hpke_scheme::keygen();
    let (mlkem_dk, mlkem_ek) = MlKem768::generate_keypair();
    let mlkem_seed = mlkem_dk
        .to_seed()
        .expect("ML-KEM keygen returns seed-backed decapsulation keys");

    (
        EncryptionKey {
            hpke_x25519: hpke_ek,
            mlkem768_ek: mlkem_ek.to_bytes().as_slice().to_vec(),
        },
        DecryptionKey {
            hpke_x25519: hpke_dk,
            mlkem768_seed: mlkem_seed.as_slice().to_vec(),
        },
    )
}

/// Derive the public hybrid key from a private hybrid key.
pub fn derive_encryption_key(dk: &DecryptionKey) -> Result<EncryptionKey> {
    dk.validate()?;
    let hpke_x25519 = hpke_scheme::derive_encryption_key(&dk.hpke_x25519)?;
    let mlkem_dk = mlkem768_decapsulation_key(&dk.mlkem768_seed)?;
    let mlkem768_ek = mlkem_dk
        .encapsulation_key()
        .to_bytes()
        .as_slice()
        .to_vec();
    Ok(EncryptionKey {
        hpke_x25519,
        mlkem768_ek,
    })
}

pub fn encrypt(ek: &EncryptionKey, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
    ek.validate()?;

    let inner_hpke_ct = hpke_scheme::encrypt(&ek.hpke_x25519, plaintext, aad)?;
    let inner_hpke_bytes = inner_hpke_ct.to_bytes();

    let mlkem_ek = mlkem768_encapsulation_key(&ek.mlkem768_ek)?;
    let (mlkem_ct, shared_secret) = mlkem_ek.encapsulate();

    let key = derive_outer_key(shared_secret.as_slice(), mlkem_ct.as_slice(), aad)?;
    let mut nonce = [0u8; AEAD_NONCE_BYTES];
    OsRng.fill_bytes(&mut nonce);

    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let aead_ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &inner_hpke_bytes,
                aad,
            },
        )
        .map_err(|_| anyhow!("Hybrid outer AEAD encrypt failed"))?;

    Ok(Ciphertext {
        mlkem768_ct: mlkem_ct.as_slice().to_vec(),
        aead_nonce: nonce.to_vec(),
        aead_ct,
    })
}

pub fn decrypt(dk: &DecryptionKey, ct: &Ciphertext, aad: &[u8]) -> Result<Vec<u8>> {
    dk.validate()?;
    ct.validate()?;

    let mlkem_dk = mlkem768_decapsulation_key(&dk.mlkem768_seed)?;
    let mlkem_ct = mlkem768_ciphertext(&ct.mlkem768_ct)?;
    let shared_secret = mlkem_dk.decapsulate(&mlkem_ct);

    let key = derive_outer_key(shared_secret.as_slice(), &ct.mlkem768_ct, aad)?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let inner_hpke_bytes = cipher
        .decrypt(
            Nonce::from_slice(&ct.aead_nonce),
            Payload {
                msg: &ct.aead_ct,
                aad,
            },
        )
        .map_err(|_| anyhow!("Hybrid outer AEAD open failed"))?;

    let inner_hpke_ct = hpke_scheme::Ciphertext::from_bytes(&inner_hpke_bytes)?;
    hpke_scheme::decrypt(&dk.hpke_x25519, &inner_hpke_ct, aad)
}

fn derive_outer_key(shared_secret: &[u8], mlkem_ct: &[u8], aad: &[u8]) -> Result<[u8; 32]> {
    let mut info = Vec::with_capacity(HKDF_SALT.len() + mlkem_ct.len() + aad.len() + 16);
    info.extend_from_slice(HKDF_SALT);
    info.extend_from_slice(&(mlkem_ct.len() as u64).to_le_bytes());
    info.extend_from_slice(mlkem_ct);
    info.extend_from_slice(&(aad.len() as u64).to_le_bytes());
    info.extend_from_slice(aad);

    let hk = Hkdf::<Sha256>::new(Some(HKDF_SALT), shared_secret);
    let mut key = [0u8; AEAD_KEY_BYTES];
    hk.expand(&info, &mut key)
        .map_err(|_| anyhow!("Hybrid HKDF expand failed"))?;
    Ok(key)
}

fn mlkem768_encapsulation_key(
    bytes: &[u8],
) -> Result<<MlKem768 as Kem>::EncapsulationKey> {
    let key = ml_kem_key_array::from_slice::<<MlKem768 as Kem>::EncapsulationKey>(bytes)?;
    <<MlKem768 as Kem>::EncapsulationKey>::new(&key)
        .map_err(|_| anyhow!("invalid ML-KEM-768 encapsulation key"))
}

fn mlkem768_decapsulation_key(
    bytes: &[u8],
) -> Result<<MlKem768 as Kem>::DecapsulationKey> {
    let seed: Seed = bytes
        .try_into()
        .map_err(|_| anyhow!("invalid ML-KEM-768 seed length"))?;
    Ok(<<MlKem768 as Kem>::DecapsulationKey>::from_seed(seed))
}

fn mlkem768_ciphertext(bytes: &[u8]) -> Result<ml_kem::Ciphertext<MlKem768>> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("invalid ML-KEM-768 ciphertext length"))
}

mod ml_kem_key_array {
    use anyhow::{anyhow, Result};
    use ml_kem::kem::{Key, KeySizeUser};

    pub fn from_slice<T>(bytes: &[u8]) -> Result<Key<T>>
    where
        T: KeySizeUser,
    {
        bytes
            .try_into()
            .map_err(|_| anyhow!("invalid ML-KEM key length"))
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn round_trip() {
        let (ek, dk) = keygen();
        let pt = b"hello hybrid pke";
        let ct = encrypt(&ek, pt, b"").unwrap();
        let got = decrypt(&dk, &ct, b"").unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn derive_pk_matches_keygen() {
        let (ek, dk) = keygen();
        let derived = derive_encryption_key(&dk).unwrap();
        assert_eq!(derived, ek);
    }

    #[test]
    fn aad_must_match() {
        let (ek, dk) = keygen();
        let ct = encrypt(&ek, b"msg", b"ctx-A").unwrap();
        assert_eq!(decrypt(&dk, &ct, b"ctx-A").unwrap(), b"msg");
        assert!(decrypt(&dk, &ct, b"ctx-B").is_err());
    }

    #[test]
    fn tamper_outer_aead_rejected() {
        let (ek, dk) = keygen();
        let mut ct = encrypt(&ek, b"secret", b"").unwrap();
        ct.aead_ct[0] ^= 1;
        assert!(decrypt(&dk, &ct, b"").is_err());
    }

    #[test]
    fn tamper_mlkem_ciphertext_rejected_by_outer_aead() {
        let (ek, dk) = keygen();
        let mut ct = encrypt(&ek, b"secret", b"").unwrap();
        ct.mlkem768_ct[0] ^= 1;
        assert!(decrypt(&dk, &ct, b"").is_err());
    }

    #[test]
    fn wrong_key_rejected() {
        let (ek, _) = keygen();
        let (_, wrong_dk) = keygen();
        let ct = encrypt(&ek, b"secret", b"").unwrap();
        assert!(decrypt(&wrong_dk, &ct, b"").is_err());
    }

    #[test]
    fn bcs_round_trips_and_checks_lengths() {
        let (ek, dk) = keygen();
        assert_eq!(ek.mlkem768_ek.len(), MLKEM768_EK_BYTES);
        assert_eq!(dk.mlkem768_seed.len(), MLKEM768_DK_SEED_BYTES);

        let ek_back = EncryptionKey::from_bytes(&ek.to_bytes()).unwrap();
        let dk_back = DecryptionKey::from_bytes(&dk.to_bytes()).unwrap();
        assert_eq!(ek_back, ek);
        assert_eq!(dk_back, dk);

        let ct = encrypt(&ek, b"xyzzy", b"").unwrap();
        assert_eq!(ct.mlkem768_ct.len(), MLKEM768_CT_BYTES);
        assert_eq!(ct.aead_nonce.len(), AEAD_NONCE_BYTES);
        assert!(ct.aead_ct.len() >= AEAD_TAG_BYTES);
        let ct_back = Ciphertext::from_bytes(&ct.to_bytes()).unwrap();
        assert_eq!(ct_back, ct);
    }

    #[test]
    fn invalid_lengths_rejected() {
        let (mut ek, mut dk) = keygen();
        ek.mlkem768_ek.pop();
        assert!(ek.validate().is_err());
        dk.mlkem768_seed.pop();
        assert!(dk.validate().is_err());

        let (ek, _) = keygen();
        let mut ct = encrypt(&ek, b"secret", b"").unwrap();
        ct.mlkem768_ct.pop();
        assert!(ct.validate().is_err());
    }

    /// Easy-to-run benchmark.
    ///   cargo test -p ace-pke --release bench_hybrid_x25519_mlkem768 -- --ignored --nocapture
    #[test]
    #[ignore]
    fn bench_hybrid_x25519_mlkem768() {
        const ITERS: u32 = 300;
        const SIZES: &[(&str, usize)] = &[("32B", 32), ("1KB", 1024), ("64KB", 64 * 1024)];

        let t = Instant::now();
        for _ in 0..ITERS {
            let _ = keygen();
        }
        let per = t.elapsed().as_secs_f64() * 1000.0 / ITERS as f64;
        println!("keygen:                   {:8.3} ms  ({:>8.0} ops/s)", per, 1000.0 / per);

        for (label, n) in SIZES {
            let (ek, dk) = keygen();
            let pt = vec![0xa5u8; *n];

            let t = Instant::now();
            for _ in 0..ITERS {
                let _ = encrypt(&ek, &pt, b"").unwrap();
            }
            let per = t.elapsed().as_secs_f64() * 1000.0 / ITERS as f64;
            println!(
                "encrypt {:>4}:             {:8.3} ms  ({:>8.0} ops/s)",
                label,
                per,
                1000.0 / per
            );

            let ct = encrypt(&ek, &pt, b"").unwrap();
            let t = Instant::now();
            for _ in 0..ITERS {
                let _ = decrypt(&dk, &ct, b"").unwrap();
            }
            let per = t.elapsed().as_secs_f64() * 1000.0 / ITERS as f64;
            println!(
                "decrypt {:>4}:             {:8.3} ms  ({:>8.0} ops/s)",
                label,
                per,
                1000.0 / per
            );
        }
    }
}
