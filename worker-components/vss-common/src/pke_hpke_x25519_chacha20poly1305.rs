// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! HPKE base mode, ciphersuite:
//!   KEM:  DHKEM(X25519, HKDF-SHA256)   (KemId 0x0020)
//!   KDF:  HKDF-SHA256                  (KdfId 0x0001)
//!   AEAD: ChaCha20-Poly1305            (AeadId 0x0003)
//!
//! Wire-compatible with `ts-sdk/src/pke/hpke_x25519_chacha20poly1305.ts`.
//!
//! BCS layout (no leading scheme byte; the abstract `pke` outer enum prepends it):
//!   EncryptionKey   = [ULEB128(32)] [32B X25519 public key]
//!   DecryptionKey   = [ULEB128(32)] [32B X25519 private key]
//!   Ciphertext      = [ULEB128(32)] [32B enc] [ULEB128(len)] [len B aead_ct]
//!
//! `aead_ct` is `inner_ciphertext || 16-byte Poly1305 tag` (matches `hpke-js`'s
//! `seal()` output and the `hpke` crate's `seal()` output).

use anyhow::{anyhow, Result};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, single_shot_open,
    single_shot_seal, Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

const X25519_KEY_BYTES: usize = 32;

// ── BCS wire structs ──────────────────────────────────────────────────────────

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptionKey {
    pub pk: Vec<u8>, // 32B X25519 public key
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptionKey {
    pub sk: Vec<u8>, // 32B X25519 private key
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ciphertext {
    pub enc: Vec<u8>,     // 32B encapsulated key
    pub aead_ct: Vec<u8>, // AEAD ciphertext (incl 16B Poly1305 tag at the end)
}

impl EncryptionKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).expect("BCS serialization cannot fail for Vec<u8>")
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let ek: EncryptionKey =
            bcs::from_bytes(data).map_err(|e| anyhow!("EncryptionKey BCS decode: {}", e))?;
        if ek.pk.len() != X25519_KEY_BYTES {
            return Err(anyhow!(
                "EncryptionKey: pk must be {} bytes, got {}",
                X25519_KEY_BYTES,
                ek.pk.len()
            ));
        }
        Ok(ek)
    }
}

impl DecryptionKey {
    pub fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).expect("BCS serialization cannot fail for Vec<u8>")
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let dk: DecryptionKey =
            bcs::from_bytes(data).map_err(|e| anyhow!("DecryptionKey BCS decode: {}", e))?;
        if dk.sk.len() != X25519_KEY_BYTES {
            return Err(anyhow!(
                "DecryptionKey: sk must be {} bytes, got {}",
                X25519_KEY_BYTES,
                dk.sk.len()
            ));
        }
        Ok(dk)
    }
}

impl Ciphertext {
    pub fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).expect("BCS serialization cannot fail for Vec<u8>")
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let ct: Ciphertext =
            bcs::from_bytes(data).map_err(|e| anyhow!("Ciphertext BCS decode: {}", e))?;
        if ct.enc.len() != X25519_KEY_BYTES {
            return Err(anyhow!(
                "Ciphertext: enc must be {} bytes, got {}",
                X25519_KEY_BYTES,
                ct.enc.len()
            ));
        }
        if ct.aead_ct.len() < 16 {
            return Err(anyhow!(
                "Ciphertext: aead_ct must be >= 16 bytes (Poly1305 tag), got {}",
                ct.aead_ct.len()
            ));
        }
        Ok(ct)
    }
}

// ── HPKE ops ──────────────────────────────────────────────────────────────────

/// Generate a fresh keypair using OsRng.
pub fn keygen() -> (EncryptionKey, DecryptionKey) {
    let (sk, pk) = Kem::gen_keypair(&mut OsRng);
    (
        EncryptionKey { pk: pk.to_bytes().to_vec() },
        DecryptionKey { sk: sk.to_bytes().to_vec() },
    )
}

/// Derive the public key from a private key.
pub fn derive_encryption_key(dk: &DecryptionKey) -> Result<EncryptionKey> {
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(&dk.sk)
        .map_err(|e| anyhow!("invalid private key bytes: {:?}", e))?;
    let pk = <Kem as KemTrait>::sk_to_pk(&sk);
    Ok(EncryptionKey { pk: pk.to_bytes().to_vec() })
}

pub fn encrypt(ek: &EncryptionKey, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(&ek.pk)
        .map_err(|e| anyhow!("invalid public key bytes: {:?}", e))?;
    let mut csprng = OsRng;
    let (encapped, aead_ct) = single_shot_seal::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &pk,
        &[], // info
        plaintext,
        aad,
        &mut csprng,
    )
    .map_err(|e| anyhow!("HPKE seal: {:?}", e))?;
    Ok(Ciphertext { enc: encapped.to_bytes().to_vec(), aead_ct })
}

pub fn decrypt(dk: &DecryptionKey, ct: &Ciphertext, aad: &[u8]) -> Result<Vec<u8>> {
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(&dk.sk)
        .map_err(|e| anyhow!("invalid private key bytes: {:?}", e))?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&ct.enc)
        .map_err(|e| anyhow!("invalid encapped key: {:?}", e))?;
    single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk,
        &encapped,
        &[], // info
        &ct.aead_ct,
        aad,
    )
    .map_err(|e| anyhow!("HPKE open: {:?}", e))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    fn round_trip() {
        let (ek, dk) = keygen();
        let pt = b"hello hpke";
        let ct = encrypt(&ek, pt, b"").unwrap();
        let got = decrypt(&dk, &ct, b"").unwrap();
        assert_eq!(got, pt);
    }

    #[test]
    fn derive_pk_matches_keygen() {
        let (ek, dk) = keygen();
        let derived = derive_encryption_key(&dk).unwrap();
        assert_eq!(derived.pk, ek.pk);
    }

    #[test]
    fn aad_must_match() {
        let (ek, dk) = keygen();
        let ct = encrypt(&ek, b"msg", b"ctx-A").unwrap();
        assert_eq!(decrypt(&dk, &ct, b"ctx-A").unwrap(), b"msg");
        assert!(decrypt(&dk, &ct, b"ctx-B").is_err());
    }

    #[test]
    fn tamper_aead_ct_rejected() {
        let (ek, dk) = keygen();
        let mut ct = encrypt(&ek, b"hello hpke", b"").unwrap();
        ct.aead_ct[0] ^= 1;
        assert!(decrypt(&dk, &ct, b"").is_err());
    }

    #[test]
    fn tamper_enc_rejected() {
        let (ek, dk) = keygen();
        let mut ct = encrypt(&ek, b"hello hpke", b"").unwrap();
        ct.enc[0] ^= 1;
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
    fn enc_key_bcs_round_trip() {
        let (ek, _) = keygen();
        let bytes = ek.to_bytes();
        // ULEB128(32) = 0x20 + 32B pk
        assert_eq!(bytes.len(), 33);
        assert_eq!(bytes[0], 0x20);

        let back = EncryptionKey::from_bytes(&bytes).unwrap();
        assert_eq!(back, ek);

        // Trailing bytes rejected.
        let mut trailing = bytes.clone();
        trailing.push(0xff);
        assert!(EncryptionKey::from_bytes(&trailing).is_err());

        // Wrong length pk rejected.
        let wrong_len = vec![0x10u8; 17]; // ULEB(16) + 16 zero bytes
        assert!(EncryptionKey::from_bytes(&wrong_len).is_err());
    }

    #[test]
    fn ciphertext_bcs_round_trip() {
        let (ek, _) = keygen();
        let ct = encrypt(&ek, b"xyzzy", b"").unwrap();
        let bytes = ct.to_bytes();

        // 1 + 32 (enc) + 1 + (5 + 16) (aead_ct) = 55
        assert_eq!(bytes.len(), 1 + 32 + 1 + 5 + 16);

        let back = Ciphertext::from_bytes(&bytes).unwrap();
        assert_eq!(back, ct);

        // Trailing bytes rejected.
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(Ciphertext::from_bytes(&trailing).is_err());
    }

    /// Easy-to-run benchmark.
    ///   cargo test -p vss-common --release bench_hpke -- --ignored --nocapture
    #[test]
    #[ignore]
    fn bench_hpke() {
        const ITERS: u32 = 1000;
        const SIZES: &[(&str, usize)] = &[("32B", 32), ("1KB", 1024), ("64KB", 64 * 1024)];

        // keygen
        let t = Instant::now();
        for _ in 0..ITERS {
            let _ = keygen();
        }
        let per = t.elapsed().as_secs_f64() * 1000.0 / ITERS as f64;
        println!("keygen:                   {:8.3} ms  ({:>8.0} ops/s)", per, 1000.0 / per);

        for (label, n) in SIZES {
            let (ek, dk) = keygen();
            let pt = vec![0xa5u8; *n];

            // encrypt
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

            // decrypt
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
