// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Threshold-IBE partial key extraction: H_G2(id)^scalar.

use anyhow::{anyhow, Result};
use ark_bls12_381::{Fr, G2Projective};
use ark_ec::{
    hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve},
    CurveGroup,
};
use ark_ff::{field_hashers::DefaultFieldHasher, BigInteger, PrimeField};
use ark_serialize::CanonicalSerialize;
use sha2::Sha256;

/// DST matching the TS SDK `bfibe-bls12381-shortpk-otp-hmac.ts`.
const DST_ID_HASH: &[u8] = b"BONEH_FRANKLIN_BLS12381_SHORT_PK/HASH_ID_TO_CURVE";

type G2Hasher =
    MapToCurveBasedHasher<G2Projective, DefaultFieldHasher<Sha256, 128>, WBMap<ark_bls12_381::g2::Config>>;

/// Computes `H_G2(id_bytes) ^ scalar` and returns BCS-encoded `tibe.IdentityDecryptionKeyShare` as hex.
///
/// Wire format (132 bytes):
///   `[0x00]` outer scheme = SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC
///   `[0x20][32B evalPoint LE Fr]` inner serializeBytes(evalPoint)
///   `[0x60][96B G2 compressed]`  inner serializeBytes(idkShare)
///   `[0x00]`                      no proof
pub fn partial_extract_idk_share(
    id_bytes: &[u8],
    scalar_le32: &[u8; 32],
    eval_point: u64,
) -> Result<String> {
    // 1. Hash id_bytes to G2 using the BLS12-381 hash-to-G2 standard.
    let h2c = G2Hasher::new(DST_ID_HASH)
        .map_err(|e| anyhow!("G2Hasher::new: {:?}", e))?;
    let id_proj: G2Projective = h2c
        .hash(id_bytes)
        .map_err(|e| anyhow!("hash id to G2: {:?}", e))?
        .into();

    // 2. Scalar multiplication: H_G2(id) ^ scalar.
    let scalar_fr = Fr::from_le_bytes_mod_order(scalar_le32);
    let result_proj = id_proj * scalar_fr;

    // 3. Serialize compressed G2 → 96 bytes.
    let result_affine = result_proj.into_affine();
    let mut g2_bytes = Vec::with_capacity(96);
    result_affine
        .serialize_compressed(&mut g2_bytes)
        .map_err(|e| anyhow!("G2 serialize_compressed: {:?}", e))?;
    if g2_bytes.len() != 96 {
        return Err(anyhow!("G2 compressed must be 96 bytes, got {}", g2_bytes.len()));
    }

    // 4. Build evalPoint as 32-byte LE Fr.
    let eval_fr = Fr::from(eval_point);
    let eval_le = eval_fr.into_bigint().to_bytes_le();
    let mut eval_bytes = [0u8; 32];
    let copy_len = eval_le.len().min(32);
    eval_bytes[..copy_len].copy_from_slice(&eval_le[..copy_len]);

    // 5. Build BCS output: [scheme][ULEB(32)][eval_bytes][ULEB(96)][g2_bytes][0x00]
    let mut out = Vec::with_capacity(132);
    out.push(0x00u8); // outer scheme = SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC
    out.push(0x20u8); // ULEB128(32) = 0x20
    out.extend_from_slice(&eval_bytes);
    out.push(0x60u8); // ULEB128(96) = 0x60
    out.extend_from_slice(&g2_bytes);
    out.push(0x00u8); // no proof flag

    Ok(hex::encode(&out))
}
