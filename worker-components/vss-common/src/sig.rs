// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Node-to-node messaging signature types.

use anyhow::{anyhow, Result};
use ed25519_dalek::{Signer, Verifier};
use serde::{Deserialize, Serialize};

pub const SCHEME_ED25519: u8 = 0;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PublicKey {
    Ed25519(Ed25519PublicKey),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519PublicKey {
    pub bytes: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Signature {
    Ed25519(Ed25519Signature),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ed25519Signature {
    pub bytes: Vec<u8>,
}

impl PublicKey {
    pub fn ed25519(bytes: Vec<u8>) -> Result<Self> {
        validate_ed25519_public_key(&bytes)?;
        Ok(Self::Ed25519(Ed25519PublicKey { bytes }))
    }

    pub fn from_ed25519_verifying_key(vk: &ed25519_dalek::VerifyingKey) -> Self {
        Self::Ed25519(Ed25519PublicKey {
            bytes: vk.as_bytes().to_vec(),
        })
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let pk: Self =
            bcs::from_bytes(data).map_err(|e| anyhow!("sig PublicKey BCS decode: {}", e))?;
        pk.validate()?;
        Ok(pk)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).expect("BCS serialization cannot fail for sig PublicKey")
    }

    pub fn scheme(&self) -> u8 {
        match self {
            Self::Ed25519(_) => SCHEME_ED25519,
        }
    }

    pub fn verify(&self, message: &[u8], signature: &Signature) -> Result<bool> {
        match (self, signature) {
            (Self::Ed25519(pk), Signature::Ed25519(sig)) => {
                let vk = validate_ed25519_public_key(&pk.bytes)?;
                let signature = parse_ed25519_signature(&sig.bytes)?;
                Ok(vk.verify(message, &signature).is_ok())
            }
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Ed25519(pk) => {
                validate_ed25519_public_key(&pk.bytes)?;
                Ok(())
            }
        }
    }
}

impl Signature {
    pub fn ed25519(bytes: Vec<u8>) -> Result<Self> {
        parse_ed25519_signature(&bytes)?;
        Ok(Self::Ed25519(Ed25519Signature { bytes }))
    }

    pub fn from_bytes(data: &[u8]) -> Result<Self> {
        let signature: Self =
            bcs::from_bytes(data).map_err(|e| anyhow!("sig Signature BCS decode: {}", e))?;
        signature.validate()?;
        Ok(signature)
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        bcs::to_bytes(self).expect("BCS serialization cannot fail for sig Signature")
    }

    pub fn scheme(&self) -> u8 {
        match self {
            Self::Ed25519(_) => SCHEME_ED25519,
        }
    }

    pub fn validate(&self) -> Result<()> {
        match self {
            Self::Ed25519(sig) => {
                parse_ed25519_signature(&sig.bytes)?;
                Ok(())
            }
        }
    }
}

pub fn sign_ed25519(signing_key: &ed25519_dalek::SigningKey, message: &[u8]) -> Signature {
    let signature = signing_key.sign(message);
    Signature::Ed25519(Ed25519Signature {
        bytes: signature.to_bytes().to_vec(),
    })
}

fn validate_ed25519_public_key(bytes: &[u8]) -> Result<ed25519_dalek::VerifyingKey> {
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow!("Ed25519 public key must be 32 bytes, got {}", bytes.len()))?;
    ed25519_dalek::VerifyingKey::from_bytes(&arr)
        .map_err(|e| anyhow!("invalid Ed25519 public key: {}", e))
}

fn parse_ed25519_signature(bytes: &[u8]) -> Result<ed25519_dalek::Signature> {
    ed25519_dalek::Signature::from_slice(bytes)
        .map_err(|e| anyhow!("invalid Ed25519 signature: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ed25519_round_trip_and_verify() {
        let sk = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let pk = PublicKey::from_ed25519_verifying_key(&sk.verifying_key());
        let msg = b"ace sig test";
        let sig = sign_ed25519(&sk, msg);

        let pk2 = PublicKey::from_bytes(&pk.to_bytes()).unwrap();
        let sig2 = Signature::from_bytes(&sig.to_bytes()).unwrap();
        assert!(pk2.verify(msg, &sig2).unwrap());
        assert!(!pk2.verify(b"wrong", &sig2).unwrap());
    }

    #[test]
    fn rejects_bad_public_key_len() {
        let bytes =
            bcs::to_bytes(&PublicKey::Ed25519(Ed25519PublicKey { bytes: vec![1] })).unwrap();
        assert!(PublicKey::from_bytes(&bytes).is_err());
    }

    #[test]
    fn rejects_bad_signature_len() {
        let bytes =
            bcs::to_bytes(&Signature::Ed25519(Ed25519Signature { bytes: vec![1] })).unwrap();
        assert!(Signature::from_bytes(&bytes).is_err());
    }
}
