// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/pke/elgamal_otp_ristretto255.ts`: ElGamal-KEM over Ristretto255 with a
//! KDF-derived one-time pad and an HMAC-SHA3-256 tag.

use super::elgamal;
use super::group::{Element, Scalar};
use crate::error::{AceError, Result};
use crate::group::wire_via_serialize;
use crate::utils::{hmac_sha3_256, kdf, xor_bytes};
use crate::wire::{from_bytes_exact, Deserializer, Serializer, Wire};

const OTP_DST: &[u8] = b"OTP/ELGAMAL_OTP_RISTRETTO255";
const HMAC_DST: &[u8] = b"HMAC/ELGAMAL_OTP_RISTRETTO255";

/// BCS: `ElGamal.EncKey`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct EncryptionKey {
    pub elgamal_ek: elgamal::EncKey,
}

impl EncryptionKey {
    pub fn new(elgamal_ek: elgamal::EncKey) -> Self {
        Self { elgamal_ek }
    }

    pub fn serialize(&self, s: &mut Serializer) {
        self.elgamal_ek.encode(s);
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(Self::new(elgamal::EncKey::decode(d)?))
    }
}
wire_via_serialize!(EncryptionKey);

/// BCS: `ElGamal.DecKey`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DecryptionKey {
    pub elgamal_dk: elgamal::DecKey,
}

impl DecryptionKey {
    pub fn new(elgamal_dk: elgamal::DecKey) -> Self {
        Self { elgamal_dk }
    }

    pub fn serialize(&self, s: &mut Serializer) {
        self.elgamal_dk.encode(s);
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(Self::new(elgamal::DecKey::decode(d)?))
    }
}
wire_via_serialize!(DecryptionKey);

/// BCS: `ElGamal.Ciphertext ++ bytes(symmetric_ciph) ++ bytes(mac)`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Ciphertext {
    pub elgamal_ciph: elgamal::Ciphertext,
    pub symmetric_ciph: Vec<u8>,
    pub mac: Vec<u8>,
}

impl Ciphertext {
    pub fn new(elgamal_ciph: elgamal::Ciphertext, symmetric_ciph: Vec<u8>, mac: Vec<u8>) -> Self {
        Self {
            elgamal_ciph,
            symmetric_ciph,
            mac,
        }
    }

    pub fn serialize(&self, s: &mut Serializer) {
        self.elgamal_ciph.encode(s);
        s.bytes(&self.symmetric_ciph);
        s.bytes(&self.mac);
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let elgamal_ciph = elgamal::Ciphertext::decode(d)?;
        let symmetric_ciph = d.bytes()?;
        let mac = d.bytes()?;
        Ok(Self::new(elgamal_ciph, symmetric_ciph, mac))
    }
}
wire_via_serialize!(Ciphertext);

/// Random encryption base + random private scalar.
pub fn keygen() -> DecryptionKey {
    let enc_base = Element::rand();
    let private_scalar = Scalar::rand();
    DecryptionKey::new(elgamal::DecKey::new(enc_base, private_scalar))
}

/// `public_point = enc_base * private_scalar`.
///
/// Panics (like the TS, which throws) if the decryption key holds malformed element bytes.
pub fn derive_encryption_key(dk: &DecryptionKey) -> EncryptionKey {
    let elgamal::DecKey {
        enc_base,
        private_scalar,
    } = &dk.elgamal_dk;
    let public_point = enc_base
        .scale(private_scalar)
        .expect("DecryptionKey holds malformed ristretto255 bytes");
    EncryptionKey::new(elgamal::EncKey::new(enc_base.clone(), public_point))
}

/// Encrypt with a fresh random ElGamal plaintext (the KEM seed) and randomizer.
///
/// Panics (like the TS, which throws) if the encryption key holds malformed element bytes.
pub fn encrypt(encryption_key: &EncryptionKey, plaintext: &[u8]) -> Ciphertext {
    let elgamal_ptxt = Element::rand();
    let elgamal_rand = Scalar::rand();
    let elgamal_ciph = elgamal::enc(&encryption_key.elgamal_ek, &elgamal_rand, &elgamal_ptxt)
        .expect("EncryptionKey holds malformed ristretto255 bytes");
    // Seed is the BCS encoding (length-prefixed) of the element, same as TS `toBytes()`.
    let seed = elgamal_ptxt.to_bytes();
    let otp = kdf(&seed, OTP_DST, plaintext.len());
    let symmetric_ciph = xor_bytes(&otp, plaintext);
    let hmac_key = kdf(&seed, HMAC_DST, 32);
    let mac = hmac_sha3_256(&hmac_key, &symmetric_ciph).to_vec();
    Ciphertext::new(elgamal_ciph, symmetric_ciph, mac)
}

/// Recover the KEM seed, verify the MAC (constant-time), then strip the pad.
pub fn decrypt(dk: &DecryptionKey, ciphertext: &Ciphertext) -> Result<Vec<u8>> {
    let elgamal_ptxt = elgamal::dec(&dk.elgamal_dk, &ciphertext.elgamal_ciph)?;
    let seed = elgamal_ptxt.to_bytes();
    let otp = kdf(&seed, OTP_DST, ciphertext.symmetric_ciph.len());
    let hmac_key = kdf(&seed, HMAC_DST, 32);
    let expected_mac = hmac_sha3_256(&hmac_key, &ciphertext.symmetric_ciph);
    if expected_mac.len() != ciphertext.mac.len() {
        return Err(AceError::Verify("MAC verification failed".into()));
    }
    let mut diff = 0u8;
    for (a, b) in expected_mac.iter().zip(ciphertext.mac.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        return Err(AceError::Verify("MAC verification failed".into()));
    }
    Ok(xor_bytes(&otp, &ciphertext.symmetric_ciph))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pke::group::{msm, scalar_from_512bit_hash};

    #[test]
    fn roundtrip() {
        let dk = keygen();
        let ek = derive_encryption_key(&dk);
        for len in [0usize, 1, 31, 32, 33, 100, 1000] {
            let msg = crate::utils::rand_bytes(len);
            let ct = encrypt(&ek, &msg);
            assert_eq!(ct.mac.len(), 32);
            assert_eq!(decrypt(&dk, &ct).unwrap(), msg);
        }
    }

    #[test]
    fn tampered_fails() {
        let dk = keygen();
        let ek = derive_encryption_key(&dk);
        let ct = encrypt(&ek, b"hello world");
        let mut bad = ct.clone();
        bad.symmetric_ciph[0] ^= 1;
        assert!(matches!(decrypt(&dk, &bad), Err(AceError::Verify(_))));
        let mut bad = ct.clone();
        bad.mac[5] ^= 0x80;
        assert!(matches!(decrypt(&dk, &bad), Err(AceError::Verify(_))));
        let mut bad = ct.clone();
        bad.mac.pop();
        assert!(matches!(decrypt(&dk, &bad), Err(AceError::Verify(_))));
        let other = keygen();
        assert!(matches!(decrypt(&other, &ct), Err(AceError::Verify(_))));
    }

    #[test]
    fn wire_roundtrip() {
        let dk = keygen();
        let ek = derive_encryption_key(&dk);
        let ct = encrypt(&ek, b"payload");
        assert_eq!(DecryptionKey::from_bytes(&dk.to_bytes()).unwrap(), dk);
        assert_eq!(EncryptionKey::from_hex(&ek.to_hex()).unwrap(), ek);
        assert_eq!(Ciphertext::from_bytes(&ct.to_bytes()).unwrap(), ct);
        // Layout: ElGamal ct = 2 * (1 + 32), symmetric = 1 + 7, mac = 1 + 32.
        assert_eq!(ct.to_bytes().len(), 66 + 8 + 33);
        assert_eq!(dk.to_bytes().len(), 66);
        let mut trailing = ct.to_bytes();
        trailing.push(0);
        assert!(Ciphertext::from_bytes(&trailing).is_err());
        assert_eq!(
            Element::from_bytes(&Element::rand().to_bytes())
                .unwrap()
                .bytes
                .len(),
            32
        );
    }

    #[test]
    fn group_arithmetic() {
        let a = Element::rand();
        let b = Element::rand();
        let id = Element::group_identity();
        assert_eq!(a.scale(&Scalar::dummy()).unwrap(), id);
        assert_eq!(a.sub(&a).unwrap(), id);
        assert_eq!(a.add(&id).unwrap(), a);
        assert_eq!(a.add(&b).unwrap().sub(&b).unwrap(), a);
        let s = Scalar::rand();
        let t = Scalar::rand();
        assert_eq!(
            a.scale(&s).unwrap().scale(&t).unwrap(),
            a.scale(&s.mul(&t).unwrap()).unwrap()
        );
        let sum = a.scale(&s.add(&t).unwrap()).unwrap();
        assert_eq!(
            a.scale(&s).unwrap().add(&a.scale(&t).unwrap()).unwrap(),
            sum
        );
        assert_eq!(
            msm(&[a.clone(), a.clone()], &[s.clone(), t.clone()]).unwrap(),
            sum
        );
        assert!(s.sub(&s).unwrap().is_zero());
        assert!(s.add(&s.neg().unwrap()).unwrap().is_zero());
        assert_eq!(
            Scalar::from_u64(7).mul(&Scalar::from_u64(6)).unwrap(),
            Scalar::from_u64(42)
        );
        // from_le_bytes_mod_q: 2^64 + 1 given as 9 bytes.
        let x = Scalar::from_le_bytes_mod_q(&[1u8, 0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(x.bytes[0], 1);
        assert_eq!(x.bytes[8], 1);
        // q itself reduces to zero.
        let q = hex::decode("edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010")
            .unwrap();
        assert!(Scalar::from_le_bytes_mod_q(&q).is_zero());
        assert_eq!(scalar_from_512bit_hash(&[0u8; 64]), Scalar::from_u64(1));
    }
}
