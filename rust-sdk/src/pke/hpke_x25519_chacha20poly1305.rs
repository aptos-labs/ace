// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/pke/hpke_x25519_chacha20poly1305.ts`.
//!
//! HPKE base mode (RFC 9180), ciphersuite:
//!   KEM:  DHKEM(X25519, HKDF-SHA256)   (KemId 0x0020)
//!   KDF:  HKDF-SHA256                  (KdfId 0x0001)
//!   AEAD: ChaCha20-Poly1305            (AeadId 0x0003)
//!
//! BCS wire format (no leading scheme byte; the tagged `pke` wrapper prepends it):
//!   EncryptionKey   = [ULEB128(32)] [32B X25519 public key]
//!   DecryptionKey   = [ULEB128(32)] [32B X25519 private key]
//!   Ciphertext      = [ULEB128(32)] [32B enc] [ULEB128(len)] [len B aead_ct]
//!
//! `aead_ct` includes the 16-byte Poly1305 tag. `info` is always empty (as in TS).

use crate::error::{AceError, Result};
use crate::group::wire_via_serialize;
use crate::wire::{from_bytes_exact, Deserializer, Serializer, Wire};
use hpke::{
    aead::ChaCha20Poly1305, kdf::HkdfSha256, kem::X25519HkdfSha256, single_shot_open,
    single_shot_seal, Deserializable, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};

type Kem = X25519HkdfSha256;
type Kdf = HkdfSha256;
type Aead = ChaCha20Poly1305;

pub const X25519_KEY_BYTES: usize = 32;
pub const ENCAPSULATED_KEY_BYTES: usize = 32;
pub const AEAD_TAG_BYTES: usize = 16;

fn fixed32(v: Vec<u8>, label: &str) -> Result<[u8; 32]> {
    v.try_into().map_err(|v: Vec<u8>| {
        AceError::wire(format!("{label}: expected 32 bytes, got {}", v.len()))
    })
}

/// Raw 32-byte X25519 public key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct EncryptionKey {
    pub pk: [u8; X25519_KEY_BYTES],
}

impl EncryptionKey {
    pub fn serialize(&self, s: &mut Serializer) {
        s.bytes(&self.pk);
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(Self {
            pk: fixed32(d.bytes()?, "EncryptionKey: pk")?,
        })
    }
}
wire_via_serialize!(EncryptionKey);

/// Raw 32-byte X25519 private key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct DecryptionKey {
    pub sk: [u8; X25519_KEY_BYTES],
}

impl DecryptionKey {
    pub fn serialize(&self, s: &mut Serializer) {
        s.bytes(&self.sk);
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(Self {
            sk: fixed32(d.bytes()?, "DecryptionKey: sk")?,
        })
    }
}
wire_via_serialize!(DecryptionKey);

/// `enc` = 32-byte encapsulated key (ephemeral X25519 pubkey), `aead_ct` = ciphertext || tag.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ciphertext {
    pub enc: [u8; ENCAPSULATED_KEY_BYTES],
    pub aead_ct: Vec<u8>,
}

impl Ciphertext {
    pub fn new(enc: [u8; ENCAPSULATED_KEY_BYTES], aead_ct: Vec<u8>) -> Result<Self> {
        if aead_ct.len() < AEAD_TAG_BYTES {
            return Err(AceError::wire(format!(
                "Ciphertext: aead_ct must be >= {AEAD_TAG_BYTES} bytes (Poly1305 tag), got {}",
                aead_ct.len()
            )));
        }
        Ok(Self { enc, aead_ct })
    }
    pub fn serialize(&self, s: &mut Serializer) {
        s.bytes(&self.enc);
        s.bytes(&self.aead_ct);
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let enc = fixed32(d.bytes()?, "Ciphertext: enc")?;
        let aead_ct = d.bytes()?;
        Self::new(enc, aead_ct)
    }
}
wire_via_serialize!(Ciphertext);

/// Fresh X25519 keypair from the OS CSPRNG.
pub fn keygen() -> (EncryptionKey, DecryptionKey) {
    let (sk, pk) = Kem::gen_keypair(&mut rand::rngs::OsRng);
    (
        EncryptionKey {
            pk: pk.to_bytes().into(),
        },
        DecryptionKey {
            sk: sk.to_bytes().into(),
        },
    )
}

/// X25519 scalar-base-mult of the private key.
pub fn derive_encryption_key(dk: &DecryptionKey) -> EncryptionKey {
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(&dk.sk)
        .expect("32-byte X25519 private key is always decodable");
    let pk = Kem::sk_to_pk(&sk);
    EncryptionKey {
        pk: pk.to_bytes().into(),
    }
}

/// HPKE base-mode single-shot seal with empty `info`.
pub fn encrypt(ek: &EncryptionKey, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext> {
    let pk = <Kem as KemTrait>::PublicKey::from_bytes(&ek.pk)
        .map_err(|e| AceError::crypto(format!("hpke: invalid recipient public key: {e}")))?;
    let (encapped, aead_ct) = single_shot_seal::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &pk,
        &[], // info
        plaintext,
        aad,
        &mut rand::rngs::OsRng,
    )
    .map_err(|e| AceError::crypto(format!("hpke seal failed: {e}")))?;
    Ciphertext::new(encapped.to_bytes().into(), aead_ct)
}

/// HPKE base-mode single-shot open with empty `info`.
pub fn decrypt(dk: &DecryptionKey, ct: &Ciphertext, aad: &[u8]) -> Result<Vec<u8>> {
    let sk = <Kem as KemTrait>::PrivateKey::from_bytes(&dk.sk)
        .map_err(|e| AceError::crypto(format!("hpke: invalid recipient private key: {e}")))?;
    let encapped = <Kem as KemTrait>::EncappedKey::from_bytes(&ct.enc)
        .map_err(|e| AceError::crypto(format!("hpke: invalid encapsulated key: {e}")))?;
    single_shot_open::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &sk,
        &encapped,
        &[], // info
        &ct.aead_ct,
        aad,
    )
    .map_err(|e| AceError::crypto(format!("hpke open failed: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pke as tagged;

    const FIXTURE: &str = include_str!("../../../test-fixtures/python-sdk-cross-impl.json");

    #[test]
    fn roundtrip() {
        let (ek, dk) = keygen();
        assert_eq!(derive_encryption_key(&dk), ek);
        let pt = b"hello hpke";
        let ct = encrypt(&ek, pt, b"aad").unwrap();
        assert_eq!(decrypt(&dk, &ct, b"aad").unwrap(), pt);
        let ct2 = Ciphertext::from_bytes(&ct.to_bytes()).unwrap();
        assert_eq!(ct2, ct);
        assert_eq!(EncryptionKey::from_hex(&ek.to_hex()).unwrap(), ek);
        assert_eq!(DecryptionKey::from_hex(&dk.to_hex()).unwrap(), dk);
        assert_eq!(ct.to_bytes().len(), 1 + 32 + 1 + pt.len() + AEAD_TAG_BYTES);
    }

    #[test]
    fn tamper_fails() {
        let (ek, dk) = keygen();
        let ct = encrypt(&ek, b"secret", &[]).unwrap();
        let mut bad = ct.clone();
        bad.aead_ct[0] ^= 1;
        assert!(decrypt(&dk, &bad, &[]).is_err());
        let mut bad = ct.clone();
        bad.enc[0] ^= 1;
        assert!(decrypt(&dk, &bad, &[]).is_err());
        assert!(decrypt(&dk, &ct, b"wrong aad").is_err());
        let (_, other) = keygen();
        assert!(decrypt(&other, &ct, &[]).is_err());
    }

    #[test]
    fn cross_impl_fixture() {
        let v: serde_json::Value = serde_json::from_str(FIXTURE).unwrap();
        let h = &v["hpke"];
        let pt = h["plaintext_utf8"].as_str().unwrap().as_bytes();
        let dk =
            tagged::DecryptionKey::from_hex(h["decryption_key_hex"].as_str().unwrap()).unwrap();
        assert_eq!(
            dk.scheme(),
            tagged::SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305
        );
        let ek = tagged::derive_encryption_key(&dk);
        assert_eq!(ek.to_hex(), h["encryption_key_hex"].as_str().unwrap());
        assert_eq!(dk.to_hex(), h["decryption_key_hex"].as_str().unwrap());
        for key in ["typescript_ciphertext_hex", "python_ciphertext_hex"] {
            let hex = h[key].as_str().unwrap();
            let ct = tagged::Ciphertext::from_hex(hex).unwrap();
            assert_eq!(ct.to_hex(), hex, "{key} re-encodes");
            assert_eq!(tagged::decrypt(&dk, &ct).unwrap(), pt, "{key} decrypts");
        }
        // Fresh encryption under the fixture key also decrypts.
        let ct = tagged::encrypt(&ek, pt).unwrap();
        assert_eq!(tagged::decrypt(&dk, &ct).unwrap(), pt);
    }
}
