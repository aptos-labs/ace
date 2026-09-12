// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/t-ibe/index.ts`: scheme-tagged wrappers over the concrete t-IBE schemes.
//!
//! Wire format for every type: `u8(scheme) ++ inner`.
//!
//!   scheme 0 = Boneh-Franklin BLS12-381 short-pk OTP+HMAC (G1 mpk, G2 IDK shares)
//!   scheme 1 = Boneh-Franklin BLS12-381 short-sig AEAD    (G2 mpk, G1 IDK shares)

use super::bfibe_bls12381_shortpk_otp_hmac as shortpk;
use super::bfibe_bls12381_shortsig_aead as shortsig;
use crate::error::{AceError, Result};
use crate::group::bls12381fr::Fr;
use crate::group::{Element, SCHEME_BLS12381G1, SCHEME_BLS12381G2};
use crate::wire::{from_bytes_exact, Deserializer, Serializer, Wire};

pub const SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC: u8 = 0;
pub const SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD: u8 = 1;

/// Generates a scheme-tagged enum with two variants plus the shared boilerplate
/// (`scheme()`, `as_*` accessors, `serialize`/`deserialize`, `Wire`).
macro_rules! tagged_enum {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, PartialEq, Eq, Debug)]
        pub enum $name {
            ShortPkOtpHmac(shortpk::$name),
            ShortSigAead(shortsig::$name),
        }

        impl $name {
            pub fn scheme(&self) -> u8 {
                match self {
                    $name::ShortPkOtpHmac(_) => SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC,
                    $name::ShortSigAead(_) => SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD,
                }
            }
            pub fn as_shortpk_otp_hmac(&self) -> Result<&shortpk::$name> {
                match self {
                    $name::ShortPkOtpHmac(x) => Ok(x),
                    _ => Err(AceError::crypto(concat!(
                        stringify!($name),
                        ": wrong scheme (expected shortpk-otp-hmac)"
                    ))),
                }
            }
            pub fn as_shortsig_aead(&self) -> Result<&shortsig::$name> {
                match self {
                    $name::ShortSigAead(x) => Ok(x),
                    _ => Err(AceError::crypto(concat!(
                        stringify!($name),
                        ": wrong scheme (expected shortsig-aead)"
                    ))),
                }
            }
            pub fn serialize(&self, s: &mut Serializer) {
                s.u8(self.scheme());
                match self {
                    $name::ShortPkOtpHmac(x) => x.serialize(s),
                    $name::ShortSigAead(x) => x.serialize(s),
                }
            }
            pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
                match d.u8()? {
                    SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC => {
                        Ok($name::ShortPkOtpHmac(shortpk::$name::deserialize(d)?))
                    }
                    SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD => {
                        Ok($name::ShortSigAead(shortsig::$name::deserialize(d)?))
                    }
                    s => Err(AceError::UnsupportedScheme(s)),
                }
            }
        }
        crate::group::wire_via_serialize!($name);
    };
}

tagged_enum!(
    /// BCS: `u8(scheme) ++ inner MasterPublicKey`.
    MasterPublicKey
);
tagged_enum!(
    /// BCS: `u8(scheme) ++ inner MasterPrivateKey`.
    MasterPrivateKey
);
tagged_enum!(
    /// BCS: `u8(scheme) ++ inner Ciphertext`.
    Ciphertext
);
tagged_enum!(
    /// BCS: `u8(scheme) ++ inner IdentityDecryptionKeyShare`.
    IdentityDecryptionKeyShare
);

// ── MasterPublicKey constructors ────────────────────────────────────────────────────────────

impl MasterPublicKey {
    /// Build a shortpk-otp-hmac `MasterPublicKey` from G1 group elements.
    pub fn new_boneh_franklin_bls12381_shortpk_otp_hmac(
        base_point: &Element,
        pk: &Element,
    ) -> Result<Self> {
        let base_point = *base_point.as_bls12381g1()?;
        let pk = *pk.as_bls12381g1()?;
        Ok(MasterPublicKey::ShortPkOtpHmac(shortpk::MasterPublicKey {
            base_point,
            pk,
        }))
    }

    /// Build a shortsig-aead `MasterPublicKey` from on-chain G2 elements.
    pub fn new_boneh_franklin_bls12381_shortsig_aead(
        base_point: &Element,
        pk: &Element,
    ) -> Result<Self> {
        let base_point = *base_point.as_bls12381g2()?;
        let pk = *pk.as_bls12381g2()?;
        Ok(MasterPublicKey::ShortSigAead(
            shortsig::MasterPublicKey::new(base_point, pk),
        ))
    }

    /// Build a `MasterPublicKey` for the requested t-IBE `scheme` from on-chain DKG group
    /// elements, validating that the elements live in the group expected by `scheme`.
    ///
    ///   shortpk-otp-hmac (= 0) requires basePoint + resultPk in BLS12-381 G1.
    ///   shortsig-aead    (= 1) requires basePoint + resultPk in BLS12-381 G2.
    pub fn from_group_elements(
        scheme: u8,
        base_point: &Element,
        result_pk: &Element,
    ) -> Result<Self> {
        match scheme {
            SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC => {
                if base_point.scheme() != SCHEME_BLS12381G1
                    || result_pk.scheme() != SCHEME_BLS12381G1
                {
                    return Err(AceError::crypto(format!(
                        "tibe.MasterPublicKey.from_group_elements: scheme=shortpk-otp-hmac requires G1 basepoint and resultPk, got basePoint.scheme={}, resultPk.scheme={}",
                        base_point.scheme(),
                        result_pk.scheme()
                    )));
                }
                Self::new_boneh_franklin_bls12381_shortpk_otp_hmac(base_point, result_pk)
            }
            SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD => {
                if base_point.scheme() != SCHEME_BLS12381G2
                    || result_pk.scheme() != SCHEME_BLS12381G2
                {
                    return Err(AceError::crypto(format!(
                        "tibe.MasterPublicKey.from_group_elements: scheme=shortsig-aead requires G2 basepoint and resultPk, got basePoint.scheme={}, resultPk.scheme={}",
                        base_point.scheme(),
                        result_pk.scheme()
                    )));
                }
                Self::new_boneh_franklin_bls12381_shortsig_aead(base_point, result_pk)
            }
            s => Err(AceError::UnsupportedScheme(s)),
        }
    }
}

// ── IdentityDecryptionKeyShare constructors ─────────────────────────────────────────────────

impl IdentityDecryptionKeyShare {
    /// shortpk-otp-hmac share; `idk_share` is in G2.
    pub fn new_boneh_franklin_bls12381_shortpk_otp_hmac(
        eval_point: u64,
        idk_share: crate::group::bls12381g2::PublicPoint,
        proof: Option<Vec<u8>>,
    ) -> Self {
        IdentityDecryptionKeyShare::ShortPkOtpHmac(shortpk::IdentityDecryptionKeyShare {
            eval_point,
            idk_share,
            proof,
        })
    }

    /// shortsig-aead share; `idk_share` is in G1 (48 bytes compressed).
    pub fn new_boneh_franklin_bls12381_shortsig_aead(
        eval_point: u64,
        idk_share: crate::group::bls12381g1::PublicPoint,
        proof: Option<Vec<u8>>,
    ) -> Self {
        IdentityDecryptionKeyShare::ShortSigAead(shortsig::IdentityDecryptionKeyShare::new(
            eval_point, idk_share, proof,
        ))
    }
}

// ── Free functions ──────────────────────────────────────────────────────────────────────────

/// Random master private key for `scheme`. Tests only.
pub fn keygen_for_testing(scheme: u8) -> Result<MasterPrivateKey> {
    match scheme {
        SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC => Ok(MasterPrivateKey::ShortPkOtpHmac(
            shortpk::keygen_for_testing(),
        )),
        SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD => Ok(MasterPrivateKey::ShortSigAead(
            shortsig::keygen_for_testing(),
        )),
        s => Err(AceError::UnsupportedScheme(s)),
    }
}

pub fn derive_public_key(msk: &MasterPrivateKey) -> MasterPublicKey {
    match msk {
        MasterPrivateKey::ShortPkOtpHmac(m) => {
            MasterPublicKey::ShortPkOtpHmac(shortpk::derive_public_key(m))
        }
        MasterPrivateKey::ShortSigAead(m) => {
            MasterPublicKey::ShortSigAead(shortsig::derive_public_key(m))
        }
    }
}

/// Encrypt `plaintext` to `id` under `mpk` with fresh randomness.
pub fn encrypt(mpk: &MasterPublicKey, id: &[u8], plaintext: &[u8]) -> Result<Ciphertext> {
    match mpk {
        MasterPublicKey::ShortPkOtpHmac(m) => Ok(Ciphertext::ShortPkOtpHmac(shortpk::encrypt(
            m, id, plaintext,
        )?)),
        MasterPublicKey::ShortSigAead(m) => Ok(Ciphertext::ShortSigAead(shortsig::encrypt(
            m, id, plaintext,
        )?)),
    }
}

/// Do NOT use this unless you are a maintainer (cross-impl fixtures). Use [`encrypt`] instead.
pub fn encrypt_with_randomness(
    mpk: &MasterPublicKey,
    id: &[u8],
    plaintext: &[u8],
    randomness: &[u8],
) -> Result<Ciphertext> {
    match mpk {
        MasterPublicKey::ShortPkOtpHmac(m) => Ok(Ciphertext::ShortPkOtpHmac(
            shortpk::encrypt_with_randomness(m, id, plaintext, randomness)?,
        )),
        MasterPublicKey::ShortSigAead(m) => Ok(Ciphertext::ShortSigAead(
            shortsig::encrypt_with_randomness(m, id, plaintext, randomness)?,
        )),
    }
}

/// Verify an IDK share against the on-chain `share_pk` for the same evaluation point.
/// The group elements must match the share's scheme (scheme 0 → G1, scheme 1 → G2);
/// a mismatch is an `Err`, not `Ok(false)`.
pub fn verify_share(
    base_point: &Element,
    share_pk: &Element,
    id: &[u8],
    share: &IdentityDecryptionKeyShare,
) -> Result<bool> {
    match share {
        IdentityDecryptionKeyShare::ShortPkOtpHmac(s) => Ok(shortpk::verify_share(
            base_point.as_bls12381g1()?,
            share_pk.as_bls12381g1()?,
            id,
            s,
        )),
        IdentityDecryptionKeyShare::ShortSigAead(s) => Ok(shortsig::verify_share(
            base_point.as_bls12381g2()?,
            share_pk.as_bls12381g2()?,
            id,
            s,
        )),
    }
}

/// Extract the full identity decryption key for `id` from the master-secret scalar, wrapped as
/// a single share at eval point 1 (usable directly with [`decrypt`]). Admin / disaster-recovery
/// counterpart to the committee's threshold extraction.
///
/// TS only supports shortsig-aead here; we additionally support shortpk-otp-hmac (also at eval
/// point 1) since the underlying Rust module exposes it.
pub fn extract(scheme: u8, msk_scalar: &Fr, id: &[u8]) -> Result<IdentityDecryptionKeyShare> {
    match scheme {
        SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD => Ok(IdentityDecryptionKeyShare::ShortSigAead(
            shortsig::extract(msk_scalar, id)?,
        )),
        SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC => Ok(IdentityDecryptionKeyShare::ShortPkOtpHmac(
            shortpk::extract(msk_scalar, 1, id)?,
        )),
        s => Err(AceError::UnsupportedScheme(s)),
    }
}

/// Decrypt with IDK shares at distinct eval points. All shares must carry the ciphertext's scheme.
pub fn decrypt(
    idk_shares: &[IdentityDecryptionKeyShare],
    ciphertext: &Ciphertext,
) -> Result<Vec<u8>> {
    let scheme = ciphertext.scheme();
    if idk_shares.iter().any(|s| s.scheme() != scheme) {
        return Err(AceError::crypto("decrypt: scheme mismatch"));
    }
    match ciphertext {
        Ciphertext::ShortPkOtpHmac(ct) => {
            let inner: Vec<shortpk::IdentityDecryptionKeyShare> = idk_shares
                .iter()
                .map(|s| s.as_shortpk_otp_hmac().cloned())
                .collect::<Result<_>>()?;
            shortpk::decrypt(&inner, ct)
        }
        Ciphertext::ShortSigAead(ct) => {
            let inner: Vec<shortsig::IdentityDecryptionKeyShare> = idk_shares
                .iter()
                .map(|s| s.as_shortsig_aead().cloned())
                .collect::<Result<_>>()?;
            shortsig::decrypt(&inner, ct)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::{bls12381g1, bls12381g2};

    fn fixture() -> serde_json::Value {
        let v: serde_json::Value = serde_json::from_str(include_str!(
            "../../../test-fixtures/python-sdk-cross-impl.json"
        ))
        .unwrap();
        v["t_ibe_shortsig_aead"].clone()
    }

    fn s(v: &serde_json::Value, k: &str) -> String {
        v[k].as_str().unwrap().to_string()
    }

    #[test]
    fn cross_impl_fixture_shortsig_aead_is_tagged() {
        let f = fixture();
        let identity = s(&f, "identity_utf8").into_bytes();
        let plaintext = s(&f, "plaintext_utf8").into_bytes();
        let randomness = hex::decode(s(&f, "randomness_hex")).unwrap();

        let mpk = MasterPublicKey::from_hex(&s(&f, "master_public_key_hex")).unwrap();
        let msk = MasterPrivateKey::from_hex(&s(&f, "master_private_key_hex")).unwrap();
        let idk =
            IdentityDecryptionKeyShare::from_hex(&s(&f, "identity_decryption_key_hex")).unwrap();
        assert_eq!(mpk.scheme(), SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD);
        assert_eq!(msk.scheme(), SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD);
        assert_eq!(idk.scheme(), SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD);
        assert_eq!(derive_public_key(&msk), mpk);
        assert_eq!(mpk.to_hex(), s(&f, "master_public_key_hex"));
        assert_eq!(msk.to_hex(), s(&f, "master_private_key_hex"));
        assert_eq!(idk.to_hex(), s(&f, "identity_decryption_key_hex"));

        let ct = encrypt_with_randomness(&mpk, &identity, &plaintext, &randomness).unwrap();
        assert_eq!(ct.scheme(), SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD);
        assert_eq!(ct.to_hex(), s(&f, "typescript_ciphertext_hex"));
        assert_eq!(ct.to_hex(), s(&f, "python_ciphertext_hex"));

        for key in ["typescript_ciphertext_hex", "python_ciphertext_hex"] {
            let parsed = Ciphertext::from_hex(&s(&f, key)).unwrap();
            assert_eq!(parsed.to_hex(), s(&f, key));
            assert_eq!(decrypt(&[idk.clone()], &parsed).unwrap(), plaintext);
        }
        assert_eq!(decrypt(std::slice::from_ref(&idk), &ct).unwrap(), plaintext);

        // extract() from the msk scalar reproduces the fixture IDK.
        let scalar = msk.as_shortsig_aead().unwrap().scalar;
        let extracted = extract(SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD, &scalar, &identity).unwrap();
        assert_eq!(extracted, idk);
    }

    #[test]
    fn scheme0_roundtrip_via_tagged_api() {
        let id = b"tagged scheme0 id";
        let pt = b"tagged scheme0 plaintext";
        let msk = keygen_for_testing(SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC).unwrap();
        assert_eq!(msk.scheme(), 0);
        let mpk = derive_public_key(&msk);
        assert_eq!(mpk.scheme(), 0);
        let ct = encrypt(&mpk, id, pt).unwrap();
        assert_eq!(ct.scheme(), 0);

        let inner_msk = msk.as_shortpk_otp_hmac().unwrap();
        let share = extract(
            SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC,
            &inner_msk.scalar,
            id,
        )
        .unwrap();
        assert_eq!(share.as_shortpk_otp_hmac().unwrap().eval_point, 1);

        let inner_mpk = mpk.as_shortpk_otp_hmac().unwrap();
        let base = Element::Bls12381G1(inner_mpk.base_point);
        let pk = Element::Bls12381G1(inner_mpk.pk);
        assert!(verify_share(&base, &pk, id, &share).unwrap());
        assert!(!verify_share(&base, &pk, b"other id", &share).unwrap());
        // Wrong group elements for a scheme-0 share -> Err.
        let g2 = Element::Bls12381G2(bls12381g2::generator());
        assert!(verify_share(&g2, &g2, id, &share).is_err());

        assert_eq!(decrypt(&[share.clone()], &ct).unwrap(), pt);

        // Wire roundtrips.
        assert_eq!(MasterPublicKey::from_bytes(&mpk.to_bytes()).unwrap(), mpk);
        assert_eq!(MasterPrivateKey::from_bytes(&msk.to_bytes()).unwrap(), msk);
        assert_eq!(Ciphertext::from_bytes(&ct.to_bytes()).unwrap(), ct);
        assert_eq!(
            IdentityDecryptionKeyShare::from_bytes(&share.to_bytes()).unwrap(),
            share
        );
        assert_eq!(mpk.to_bytes()[0], 0);

        // from_group_elements(0, G1) == derived mpk.
        assert_eq!(
            MasterPublicKey::from_group_elements(0, &base, &pk).unwrap(),
            mpk
        );
    }

    #[test]
    fn scheme_mismatch_and_unknown_scheme_errors() {
        let id = b"mismatch id";
        // scheme-0 share vs scheme-1 ciphertext.
        let msk0 = keygen_for_testing(0).unwrap();
        let share0 = extract(0, &msk0.as_shortpk_otp_hmac().unwrap().scalar, id).unwrap();
        let msk1 = keygen_for_testing(1).unwrap();
        let mpk1 = derive_public_key(&msk1);
        let ct1 = encrypt(&mpk1, id, b"hello").unwrap();
        assert!(decrypt(&[share0.clone()], &ct1).is_err());
        // Mixed shares also rejected.
        let share1 = extract(1, &msk1.as_shortsig_aead().unwrap().scalar, id).unwrap();
        assert!(decrypt(&[share1.clone(), share0], &ct1).is_err());
        assert_eq!(decrypt(&[share1], &ct1).unwrap(), b"hello");

        // from_group_elements(1, G1 elements) -> Err; (0, G2 elements) -> Err.
        let g1 = Element::Bls12381G1(bls12381g1::generator());
        let g2 = Element::Bls12381G2(bls12381g2::generator());
        assert!(MasterPublicKey::from_group_elements(1, &g1, &g1).is_err());
        assert!(MasterPublicKey::from_group_elements(0, &g2, &g2).is_err());
        assert!(MasterPublicKey::from_group_elements(1, &g2, &g1).is_err());
        assert!(MasterPublicKey::from_group_elements(1, &g2, &g2).is_ok());
        assert!(matches!(
            MasterPublicKey::from_group_elements(7, &g2, &g2),
            Err(AceError::UnsupportedScheme(7))
        ));

        // Unknown scheme byte on the wire.
        let mut bytes = mpk1.to_bytes();
        bytes[0] = 9;
        assert!(matches!(
            MasterPublicKey::from_bytes(&bytes),
            Err(AceError::UnsupportedScheme(9))
        ));
        assert!(matches!(
            Ciphertext::from_bytes(&[9u8, 1, 2, 3]),
            Err(AceError::UnsupportedScheme(9))
        ));
        assert!(matches!(
            keygen_for_testing(5),
            Err(AceError::UnsupportedScheme(5))
        ));
        assert!(matches!(
            extract(5, &msk0.as_shortpk_otp_hmac().unwrap().scalar, id),
            Err(AceError::UnsupportedScheme(5))
        ));
        // as_* accessors on the wrong variant.
        assert!(mpk1.as_shortpk_otp_hmac().is_err());
        assert!(mpk1.as_shortsig_aead().is_ok());
    }
}
