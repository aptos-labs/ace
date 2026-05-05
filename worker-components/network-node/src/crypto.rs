// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Threshold-IBE partial key extraction.
//!
//! Two t-IBE schemes are supported:
//!
//! - `SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC = 0x00`: identity hashed to G2,
//!   IDK share computed as `H_G2(id) · scalar` (96-byte G2 element). DEM is
//!   OTP+HMAC, decided client-side.
//!
//! - `SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD = 0x01`: identity hashed to G1,
//!   IDK share computed as `H_G1(id) · scalar` (48-byte G1 element). DEM is
//!   ChaCha20-Poly1305, decided client-side.
//!
//! Which scheme to use is decided by the caller (the worker derives it from the
//! on-chain DKG basepoint group). Wire format of the returned BCS bytes matches
//! `ts-sdk/src/t-ibe/index.ts::IdentityDecryptionKeyShare` for the corresponding
//! scheme.

use anyhow::{anyhow, Result};
use ark_bls12_381::{Fr, G1Projective, G2Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    CurveGroup,
};
use ark_ff::{field_hashers::DefaultFieldHasher, BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use sha2::Sha256;

pub const SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC: u8 = 0;
pub const SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD: u8 = 1;

const DST_HASH_TO_G2_SHORTPK: &[u8] = b"BONEH_FRANKLIN_BLS12381_SHORT_PK/HASH_ID_TO_CURVE";
const DST_HASH_TO_G1_SHORTSIG: &[u8] = b"BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/HASH_ID_TO_CURVE";

type G2Hasher =
    MapToCurveBasedHasher<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<ark_bls12_381::g2::Config>>;
type G1Hasher =
    MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<ark_bls12_381::g1::Config>>;

/// Map from on-chain DKG basepoint group (`group::Element` scheme byte) to the t-IBE scheme
/// the worker should serve from a share derived from that DKG.
///
/// 1-to-1 for the variants currently defined:
/// - DKG basepoint in G1 (group scheme 0) → master pk in G1 → `bfibe-bls12381-shortpk-otp-hmac`
/// - DKG basepoint in G2 (group scheme 1) → master pk in G2 → `bfibe-bls12381-shortsig-aead`
pub fn tibe_scheme_for_group(group_scheme: u8) -> Result<u8> {
    use vss_common::group::{SCHEME_BLS12381G1, SCHEME_BLS12381G2};
    match group_scheme {
        SCHEME_BLS12381G1 => Ok(SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC),
        SCHEME_BLS12381G2 => Ok(SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD),
        s => Err(anyhow!("tibe_scheme_for_group: unsupported group scheme {}", s)),
    }
}

/// Compute this worker's IDK share for the given identity and return BCS-encoded
/// `tibe.IdentityDecryptionKeyShare` bytes (as hex) for the requested t-IBE scheme.
///
/// Wire format (depends on `tibe_scheme`):
///
/// **shortpk-otp-hmac** (132 bytes):
///   `[0x00]` outer scheme
///   `[0x20][32B evalPoint LE Fr]`
///   `[0x60][96B G2 compressed]`
///   `[0x00]` no proof
///
/// **shortsig-aead** (84 bytes):
///   `[0x01]` outer scheme
///   `[0x20][32B evalPoint LE Fr]`
///   `[0x30][48B G1 compressed]`
///   `[0x00]` no proof
pub fn partial_extract_idk_share(
    tibe_scheme: u8,
    id_bytes: &[u8],
    scalar_le32: &[u8; 32],
    eval_point: u64,
) -> Result<String> {
    let scalar_fr = Fr::from_le_bytes_mod_order(scalar_le32);

    // Compute the share point in the right group, plus the on-wire length tag byte.
    let (share_bytes, share_len_tag) = match tibe_scheme {
        SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC => {
            let h2c = G2Hasher::new(DST_HASH_TO_G2_SHORTPK)
                .map_err(|e| anyhow!("G2Hasher::new: {:?}", e))?;
            let id_proj: G2Projective = h2c
                .hash(id_bytes)
                .map_err(|e| anyhow!("hash id to G2: {:?}", e))?
                .into();
            let result = (id_proj * scalar_fr).into_affine();
            let mut buf = Vec::with_capacity(96);
            result
                .serialize_compressed(&mut buf)
                .map_err(|e| anyhow!("G2 serialize_compressed: {:?}", e))?;
            if buf.len() != 96 {
                return Err(anyhow!("G2 compressed must be 96 bytes, got {}", buf.len()));
            }
            (buf, 0x60u8) // ULEB128(96)
        }
        SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD => {
            let h2c = G1Hasher::new(DST_HASH_TO_G1_SHORTSIG)
                .map_err(|e| anyhow!("G1Hasher::new: {:?}", e))?;
            let id_proj: G1Projective = h2c
                .hash(id_bytes)
                .map_err(|e| anyhow!("hash id to G1: {:?}", e))?
                .into();
            let result = (id_proj * scalar_fr).into_affine();
            let mut buf = Vec::with_capacity(48);
            result
                .serialize_compressed(&mut buf)
                .map_err(|e| anyhow!("G1 serialize_compressed: {:?}", e))?;
            if buf.len() != 48 {
                return Err(anyhow!("G1 compressed must be 48 bytes, got {}", buf.len()));
            }
            (buf, 0x30u8) // ULEB128(48)
        }
        s => return Err(anyhow!("partial_extract_idk_share: unsupported t-IBE scheme {}", s)),
    };

    // evalPoint as 32-byte LE Fr.
    let eval_fr = Fr::from(eval_point);
    let eval_le = eval_fr.into_bigint().to_bytes_le();
    let mut eval_bytes = [0u8; 32];
    let copy_len = eval_le.len().min(32);
    eval_bytes[..copy_len].copy_from_slice(&eval_le[..copy_len]);

    // Build BCS output: [scheme][ULEB(32)][eval_bytes][ULEB(point_len)][point_bytes][0x00]
    let mut out = Vec::with_capacity(1 + 1 + 32 + 1 + share_bytes.len() + 1);
    out.push(tibe_scheme);
    out.push(0x20u8); // ULEB128(32)
    out.extend_from_slice(&eval_bytes);
    out.push(share_len_tag);
    out.extend_from_slice(&share_bytes);
    out.push(0x00u8); // no proof flag

    Ok(hex::encode(&out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shortpk_share_is_132_bytes() {
        let share_hex = partial_extract_idk_share(
            SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC,
            b"id",
            &[1u8; 32],
            42,
        )
        .unwrap();
        let bytes = hex::decode(&share_hex).unwrap();
        assert_eq!(bytes.len(), 132);
        assert_eq!(bytes[0], SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC);
        assert_eq!(bytes[1], 0x20); // ULEB(32)
        assert_eq!(bytes[34], 0x60); // ULEB(96)
        assert_eq!(*bytes.last().unwrap(), 0x00); // no proof
    }

    #[test]
    fn shortsig_share_is_84_bytes() {
        let share_hex = partial_extract_idk_share(
            SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD,
            b"id",
            &[1u8; 32],
            42,
        )
        .unwrap();
        let bytes = hex::decode(&share_hex).unwrap();
        assert_eq!(bytes.len(), 84);
        assert_eq!(bytes[0], SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD);
        assert_eq!(bytes[1], 0x20); // ULEB(32)
        assert_eq!(bytes[34], 0x30); // ULEB(48)
        assert_eq!(*bytes.last().unwrap(), 0x00); // no proof
    }

    #[test]
    fn unknown_scheme_rejected() {
        let r = partial_extract_idk_share(0xff, b"id", &[1u8; 32], 1);
        assert!(r.is_err());
    }

    #[test]
    fn group_to_tibe_mapping() {
        use vss_common::group::{SCHEME_BLS12381G1, SCHEME_BLS12381G2};
        assert_eq!(
            tibe_scheme_for_group(SCHEME_BLS12381G1).unwrap(),
            SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC
        );
        assert_eq!(
            tibe_scheme_for_group(SCHEME_BLS12381G2).unwrap(),
            SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
        );
        assert!(tibe_scheme_for_group(0xff).is_err());
    }
}
