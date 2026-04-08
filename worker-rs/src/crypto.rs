// BLS12-381 partial key extraction for threshold IBE
// Computes s_i * H_G2(id) using ark-bls12-381

use anyhow::{anyhow, Result};
use ark_bls12_381::{Fr, G2Projective};
use ark_ec::hashing::{curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve};
use ark_ff::{field_hashers::DefaultFieldHasher, PrimeField};
use ark_serialize::CanonicalSerialize;
use sha2::Sha256;
use sha3::{Digest, Sha3_256};

const DST_ID_HASH: &[u8] = b"BONEH_FRANKLIN_BLS12381_SHORT_PK/HASH_ID_TO_CURVE";

type G2Hasher = MapToCurveBasedHasher<
    G2Projective,
    DefaultFieldHasher<Sha256, 128>,
    WBMap<ark_bls12_381::g2::Config>,
>;

/// Compute partial identity key: s_i * H_G2(id)
/// Returns [1 byte workerIndex][96 bytes G2 compressed] = 97 bytes as hex
pub fn partial_extract(id_bytes: &[u8], scalar_share_le32: &[u8; 32], worker_index: u8) -> Result<String> {
    // Hash identity to G2 point
    let hasher = G2Hasher::new(DST_ID_HASH)
        .map_err(|e| anyhow!("Failed to create G2 hasher: {:?}", e))?;
    let id_point: G2Projective = hasher
        .hash(id_bytes)
        .map_err(|e| anyhow!("Hash to G2 failed: {:?}", e))?.into();

    // Convert scalar from LE bytes
    let scalar = Fr::from_le_bytes_mod_order(scalar_share_le32);

    // Compute partial: s_i * H_G2(id)
    let partial = id_point * scalar;

    // Serialize G2 point (compressed, 96 bytes)
    let g2_affine: ark_bls12_381::G2Affine = partial.into();
    let mut g2_bytes = Vec::new();
    g2_affine.serialize_compressed(&mut g2_bytes)
        .map_err(|e| anyhow!("G2 serialization failed: {:?}", e))?;

    // Build result: [worker_index][96 bytes]
    let mut result = vec![worker_index];
    result.extend_from_slice(&g2_bytes);

    Ok(hex::encode(result))
}

/// Derive Shamir polynomial coefficient a_k deterministically.
/// a_k = sha3_256(r_le32 || epoch_le8 || k_le4) mod Fr
pub fn derive_coefficient(r_bytes: &[u8], epoch: u64, k: u32) -> Fr {
    let mut input = Vec::with_capacity(r_bytes.len() + 8 + 4);
    input.extend_from_slice(r_bytes);
    input.extend_from_slice(&epoch.to_le_bytes());
    input.extend_from_slice(&k.to_le_bytes());

    let hash: [u8; 32] = Sha3_256::digest(&input).into();
    Fr::from_le_bytes_mod_order(&hash)
}

/// Compute Shamir share f(worker_index):
///   f(x) = r + a_1*x + ... + a_{t-1}*x^{t-1}  (mod Fr)
/// Returns the share as little-endian 32 bytes
pub fn compute_share(r_bytes: &[u8], epoch: u64, threshold: u64, worker_index: u64) -> [u8; 32] {
    let r = Fr::from_le_bytes_mod_order(r_bytes);
    let x = Fr::from(worker_index);
    let mut y = r;
    let mut x_pow = x;
    for k in 1..threshold {
        let ak = derive_coefficient(r_bytes, epoch, k as u32);
        y = y + ak * x_pow;
        x_pow = x_pow * x;
    }
    // Convert to LE bytes
    let bigint = y.into_bigint();
    let mut bytes = [0u8; 32];
    let limbs = bigint.0;
    for (i, limb) in limbs.iter().enumerate() {
        let le = limb.to_le_bytes();
        let offset = i * 8;
        if offset + 8 <= 32 {
            bytes[offset..offset + 8].copy_from_slice(&le);
        }
    }
    bytes
}
