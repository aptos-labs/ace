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
use vss_common::group::{BcsElement, BcsPublicPoint, SCHEME_BLS12381G2};

pub const SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC: u8 = 0;
pub const SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD: u8 = 1;

const DST_HASH_TO_G2_SHORTPK: &[u8] = b"BONEH_FRANKLIN_BLS12381_SHORT_PK/HASH_ID_TO_CURVE";
const DST_HASH_TO_G1_SHORTSIG: &[u8] = b"BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/HASH_ID_TO_CURVE";
const DST_THRESHOLD_VRF_G1: &[u8] = b"ACE_THRESHOLD_VRF_BLS12381G1/HASH_TO_CURVE/v1";

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

/// Inverse of [`tibe_scheme_for_group`] in spirit — but **not** an inverse in
/// general. A group can back multiple t-IBE schemes; this maps a specific
/// t-IBE scheme to the unique group it is built over. Used by the V2 request
/// path to validate `request.tibe_scheme` is compatible with the share's
/// stored `group_scheme`.
pub fn group_scheme_for_tibe(tibe_scheme: u8) -> Result<u8> {
    use vss_common::group::{SCHEME_BLS12381G1, SCHEME_BLS12381G2};
    match tibe_scheme {
        SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC => Ok(SCHEME_BLS12381G1),
        SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD => Ok(SCHEME_BLS12381G2),
        s => Err(anyhow!("group_scheme_for_tibe: unsupported t-IBE scheme {}", s)),
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

#[derive(serde::Serialize)]
struct ThresholdVrfInput<'a> {
    keypair_id: &'a [u8; 32],
    chain_id: u8,
    account_address: &'a [u8; 32],
    label: &'a [u8],
}

#[derive(serde::Serialize, serde::Deserialize)]
struct ThresholdVrfShareWire {
    eval_point: u64,
    share: BcsElement,
}

/// Compute this worker's threshold-VRF share and return the BCS bytes consumed
/// by `ts-sdk/src/t-vrf/index.ts::ThresholdVrfShare`.
///
/// The DKG public commitments live in G2; the VRF share itself is in G1 so the
/// client can verify `e(share_i, G2) == e(H_to_G1(input), P_i)`.
pub fn partial_derive_threshold_vrf_share(
    keypair_id: &[u8; 32],
    chain_id: u8,
    account_address: &[u8; 32],
    label: &[u8],
    scalar_le32: &[u8; 32],
    eval_point: u64,
    group_scheme: u8,
) -> Result<Vec<u8>> {
    if group_scheme != SCHEME_BLS12381G2 {
        return Err(anyhow!(
            "partial_derive_threshold_vrf_share: threshold VRF requires BLS12-381 G2 DKG shares, got group scheme {}",
            group_scheme
        ));
    }

    let input = ThresholdVrfInput {
        keypair_id,
        chain_id,
        account_address,
        label,
    };
    let input_bytes = bcs::to_bytes(&input)
        .map_err(|e| anyhow!("partial_derive_threshold_vrf_share: encode input: {}", e))?;
    let scalar_fr = Fr::from_le_bytes_mod_order(scalar_le32);
    let h2c = G1Hasher::new(DST_THRESHOLD_VRF_G1)
        .map_err(|e| anyhow!("threshold VRF G1Hasher::new: {:?}", e))?;
    let id_proj: G1Projective = h2c
        .hash(&input_bytes)
        .map_err(|e| anyhow!("threshold VRF hash input to G1: {:?}", e))?
        .into();
    let result = (id_proj * scalar_fr).into_affine();
    let mut point = Vec::with_capacity(48);
    result
        .serialize_compressed(&mut point)
        .map_err(|e| anyhow!("threshold VRF G1 serialize_compressed: {:?}", e))?;
    if point.len() != 48 {
        return Err(anyhow!(
            "threshold VRF G1 compressed must be 48 bytes, got {}",
            point.len()
        ));
    }

    let share = ThresholdVrfShareWire {
        eval_point,
        share: BcsElement::Bls12381G1(BcsPublicPoint { point }),
    };
    bcs::to_bytes(&share)
        .map_err(|e| anyhow!("partial_derive_threshold_vrf_share: encode share: {}", e))
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

    #[test]
    fn threshold_vrf_share_is_eval_point_plus_g1_element() {
        let share = partial_derive_threshold_vrf_share(
            &[0xab; 32],
            4,
            &[0xcd; 32],
            b"label-1",
            &[1u8; 32],
            42,
            SCHEME_BLS12381G2,
        )
        .unwrap();
        let decoded: ThresholdVrfShareWire = bcs::from_bytes(&share).unwrap();
        assert_eq!(decoded.eval_point, 42);
        assert_eq!(decoded.share.scheme(), vss_common::group::SCHEME_BLS12381G1);
        assert_eq!(decoded.share.point_bytes().len(), 48);
    }
}
