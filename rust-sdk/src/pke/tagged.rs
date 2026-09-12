// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/pke/index.ts`: scheme-tagged PKE keys/ciphertexts.
//! BCS layout of every type: `u8(scheme) ++ inner`.

use super::{elgamal_otp_ristretto255 as elgamal, hpke_x25519_chacha20poly1305 as hpke_x25519};
use crate::error::{AceError, Result};
use crate::group::wire_via_serialize;
use crate::wire::{from_bytes_exact, Deserializer, Serializer, Wire};

pub const SCHEME_ELGAMAL_OTP_RISTRETTO255: u8 = 0;
pub const SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305: u8 = 1;
/// TS `keygen()` default.
pub const DEFAULT_SCHEME: u8 = SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305;

pub fn scheme_supported(scheme: u8) -> bool {
    scheme == SCHEME_ELGAMAL_OTP_RISTRETTO255
        || scheme == SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305
}

macro_rules! tagged_enum {
    ($name:ident, $inner:ident) => {
        #[derive(Clone, PartialEq, Eq, Debug)]
        pub enum $name {
            ElgamalOtpRistretto255(elgamal::$inner),
            HpkeX25519(hpke_x25519::$inner),
        }

        impl $name {
            pub fn scheme(&self) -> u8 {
                match self {
                    $name::ElgamalOtpRistretto255(_) => SCHEME_ELGAMAL_OTP_RISTRETTO255,
                    $name::HpkeX25519(_) => SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305,
                }
            }
            pub fn as_elgamal_otp_ristretto255(&self) -> Result<&elgamal::$inner> {
                match self {
                    $name::ElgamalOtpRistretto255(x) => Ok(x),
                    _ => Err(AceError::crypto("wrong scheme")),
                }
            }
            pub fn as_hpke_x25519(&self) -> Result<&hpke_x25519::$inner> {
                match self {
                    $name::HpkeX25519(x) => Ok(x),
                    _ => Err(AceError::crypto("wrong scheme")),
                }
            }
            pub fn serialize(&self, s: &mut Serializer) {
                s.u8(self.scheme());
                match self {
                    $name::ElgamalOtpRistretto255(x) => x.serialize(s),
                    $name::HpkeX25519(x) => x.serialize(s),
                }
            }
            pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
                match d.u8()? {
                    SCHEME_ELGAMAL_OTP_RISTRETTO255 => Ok($name::ElgamalOtpRistretto255(
                        elgamal::$inner::deserialize(d)?,
                    )),
                    SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305 => {
                        Ok($name::HpkeX25519(hpke_x25519::$inner::deserialize(d)?))
                    }
                    other => Err(AceError::UnsupportedScheme(other)),
                }
            }
        }
        wire_via_serialize!($name);
    };
}

tagged_enum!(EncryptionKey, EncryptionKey);
tagged_enum!(DecryptionKey, DecryptionKey);
tagged_enum!(Ciphertext, Ciphertext);

/// Generate a fresh decryption key for `scheme` (use [`derive_encryption_key`] for the public half).
pub fn keygen(scheme: u8) -> Result<DecryptionKey> {
    match scheme {
        SCHEME_ELGAMAL_OTP_RISTRETTO255 => {
            Ok(DecryptionKey::ElgamalOtpRistretto255(elgamal::keygen()))
        }
        SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305 => {
            let (_, dk) = hpke_x25519::keygen();
            Ok(DecryptionKey::HpkeX25519(dk))
        }
        other => Err(AceError::UnsupportedScheme(other)),
    }
}

pub fn derive_encryption_key(dk: &DecryptionKey) -> EncryptionKey {
    match dk {
        DecryptionKey::ElgamalOtpRistretto255(x) => {
            EncryptionKey::ElgamalOtpRistretto255(elgamal::derive_encryption_key(x))
        }
        DecryptionKey::HpkeX25519(x) => {
            EncryptionKey::HpkeX25519(hpke_x25519::derive_encryption_key(x))
        }
    }
}

/// Encrypt with no AAD (matches the TS tagged wrapper, which never passes `aad`).
pub fn encrypt(ek: &EncryptionKey, plaintext: &[u8]) -> Result<Ciphertext> {
    match ek {
        EncryptionKey::ElgamalOtpRistretto255(x) => Ok(Ciphertext::ElgamalOtpRistretto255(
            elgamal::encrypt(x, plaintext),
        )),
        EncryptionKey::HpkeX25519(x) => Ok(Ciphertext::HpkeX25519(hpke_x25519::encrypt(
            x,
            plaintext,
            &[],
        )?)),
    }
}

pub fn decrypt(dk: &DecryptionKey, ct: &Ciphertext) -> Result<Vec<u8>> {
    match (dk, ct) {
        (DecryptionKey::ElgamalOtpRistretto255(k), Ciphertext::ElgamalOtpRistretto255(c)) => {
            elgamal::decrypt(k, c)
        }
        (DecryptionKey::HpkeX25519(k), Ciphertext::HpkeX25519(c)) => {
            hpke_x25519::decrypt(k, c, &[])
        }
        _ => Err(AceError::crypto(format!(
            "decrypt: scheme mismatch (dk={}, ct={})",
            dk.scheme(),
            ct.scheme()
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hpke_tagged_roundtrip_and_mismatch() {
        let dk = keygen(DEFAULT_SCHEME).unwrap();
        assert_eq!(dk.scheme(), 1);
        let ek = derive_encryption_key(&dk);
        assert_eq!(ek.to_bytes()[0], 1);
        assert_eq!(ek.to_bytes().len(), 1 + 1 + 32);
        let ct = encrypt(&ek, b"tagged").unwrap();
        assert_eq!(ct.to_bytes()[0], 1);
        assert_eq!(decrypt(&dk, &ct).unwrap(), b"tagged");
        assert_eq!(Ciphertext::from_bytes(&ct.to_bytes()).unwrap(), ct);
        assert_eq!(DecryptionKey::from_hex(&dk.to_hex()).unwrap(), dk);
        assert!(matches!(keygen(7), Err(AceError::UnsupportedScheme(7))));
        assert!(EncryptionKey::from_bytes(&[9, 32]).is_err());
        let other = keygen(SCHEME_ELGAMAL_OTP_RISTRETTO255).unwrap();
        assert!(decrypt(&other, &ct).is_err());
    }
}
