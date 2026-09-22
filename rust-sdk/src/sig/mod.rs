// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/sig/index.ts`: scheme-tagged Ed25519 keys and signatures.
//! BCS layout for all three types: `uleb128(scheme) ++ bytes(raw)`.

use ed25519_dalek::{Signer as _, Verifier as _};

use crate::error::{AceError, Result};
use crate::group::wire_via_serialize;
use crate::wire::{from_bytes_exact, Deserializer, Serializer, Wire};

pub const SCHEME_ED25519: u32 = 0;

fn check_scheme(scheme: u32, what: &str) -> Result<()> {
    if scheme != SCHEME_ED25519 {
        return Err(AceError::Other(format!(
            "unsupported sig {what} scheme {scheme}"
        )));
    }
    Ok(())
}

fn fixed<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| AceError::wire(format!("{what} must be {N} bytes, got {}", bytes.len())))
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PublicKey {
    pub scheme: u32,
    pub bytes: [u8; 32],
}

impl PublicKey {
    pub fn new(scheme: u32, bytes: &[u8]) -> Result<Self> {
        check_scheme(scheme, "public key")?;
        Ok(Self {
            scheme,
            bytes: fixed(bytes, "Ed25519 public key")?,
        })
    }
    pub fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        if signature.scheme != self.scheme {
            return false;
        }
        let Ok(vk) = ed25519_dalek::VerifyingKey::from_bytes(&self.bytes) else {
            return false;
        };
        vk.verify(
            message,
            &ed25519_dalek::Signature::from_bytes(&signature.bytes),
        )
        .is_ok()
    }
    pub fn serialize(&self, s: &mut Serializer) {
        s.uleb128(self.scheme).bytes(&self.bytes);
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let scheme = d.uleb128()?;
        Self::new(scheme, &d.bytes()?)
    }
}
wire_via_serialize!(PublicKey);

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Signature {
    pub scheme: u32,
    pub bytes: [u8; 64],
}

impl Signature {
    pub fn new(scheme: u32, bytes: &[u8]) -> Result<Self> {
        check_scheme(scheme, "signature")?;
        Ok(Self {
            scheme,
            bytes: fixed(bytes, "Ed25519 signature")?,
        })
    }
    pub fn serialize(&self, s: &mut Serializer) {
        s.uleb128(self.scheme).bytes(&self.bytes);
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let scheme = d.uleb128()?;
        Self::new(scheme, &d.bytes()?)
    }
}
wire_via_serialize!(Signature);

#[derive(Clone, PartialEq, Eq)]
pub struct SigningKey {
    pub scheme: u32,
    pub bytes: [u8; 32],
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SigningKey(scheme={}, <redacted>)", self.scheme)
    }
}

impl SigningKey {
    pub fn new(scheme: u32, bytes: &[u8]) -> Result<Self> {
        check_scheme(scheme, "signing key")?;
        Ok(Self {
            scheme,
            bytes: fixed(bytes, "Ed25519 signing key")?,
        })
    }
    pub fn random() -> Self {
        let sk = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        Self {
            scheme: SCHEME_ED25519,
            bytes: sk.to_bytes(),
        }
    }
    fn dalek(&self) -> ed25519_dalek::SigningKey {
        ed25519_dalek::SigningKey::from_bytes(&self.bytes)
    }
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            scheme: self.scheme,
            bytes: self.dalek().verifying_key().to_bytes(),
        }
    }
    pub fn sign(&self, message: &[u8]) -> Signature {
        Signature {
            scheme: self.scheme,
            bytes: self.dalek().sign(message).to_bytes(),
        }
    }
    pub fn serialize(&self, s: &mut Serializer) {
        s.uleb128(self.scheme).bytes(&self.bytes);
    }
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let scheme = d.uleb128()?;
        Self::new(scheme, &d.bytes()?)
    }
}
wire_via_serialize!(SigningKey);

pub fn keygen() -> (PublicKey, SigningKey) {
    let sk = SigningKey::random();
    (sk.public_key(), sk)
}

pub fn verify(message: &[u8], signature: &Signature, public_key: &PublicKey) -> bool {
    public_key.verify(message, signature)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_verify_roundtrip_and_layout() {
        let (pk, sk) = keygen();
        let sig = sk.sign(b"hello");
        assert!(verify(b"hello", &sig, &pk));
        assert!(!verify(b"hellp", &sig, &pk));
        // layout: uleb(0)=0x00, then bytes(32)= 0x20 ++ 32B
        let b = pk.to_bytes();
        assert_eq!(b.len(), 34);
        assert_eq!(&b[..2], &[0x00, 0x20]);
        assert_eq!(PublicKey::from_bytes(&b).unwrap(), pk);
        assert_eq!(sig.to_bytes().len(), 66);
        assert_eq!(Signature::from_bytes(&sig.to_bytes()).unwrap(), sig);
        assert_eq!(SigningKey::from_bytes(&sk.to_bytes()).unwrap(), sk);
        assert!(PublicKey::from_bytes(&[0x01, 0x20]).is_err());
    }
}
