// G1 KEM for VssSession.encrypted_shares: [R_compressed_48 || share_xor_sha3(S)]
// S = r * pk_recipient = dk_rec * R where R = r*G.

use anyhow::{anyhow, Result};
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::{PrimeField, UniformRand};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};

/// Deterministic BLS12-381 scalar used as this worker's VSS decryption key (matches registered pk).
pub fn derive_vss_dk(signing_key: &SigningKey) -> Fr {
    let mut h = Sha3_256::new();
    h.update(signing_key.to_bytes());
    h.update(b"ace-vss-dk-v1");
    let digest: [u8; 32] = h.finalize().into();
    Fr::from_le_bytes_mod_order(&digest)
}

pub fn encryption_pk_compressed(dk: &Fr) -> [u8; 48] {
    let g = G1Projective::generator() * dk;
    let mut out = [0u8; 48];
    g.into_affine()
        .serialize_compressed(&mut out[..])
        .expect("serialize G1");
    out
}

pub fn encrypt_share_80(share_le32: &[u8; 32], recipient_pk_compressed: &[u8; 48]) -> Result<Vec<u8>> {
    let pk = G1Affine::deserialize_compressed(&recipient_pk_compressed[..])
        .map_err(|e| anyhow!("invalid recipient encryption G1 pk: {:?}", e))?;
    let mut rng = OsRng;
    let r = Fr::rand(&mut rng);
    let r_g = G1Projective::generator() * r;
    let mut r_compressed = [0u8; 48];
    r_g.into_affine()
        .serialize_compressed(&mut r_compressed[..])
        .map_err(|e| anyhow!("serialize R: {:?}", e))?;
    let shared = G1Projective::from(pk) * r;
    let mut s_bytes = [0u8; 48];
    shared
        .into_affine()
        .serialize_compressed(&mut s_bytes[..])
        .map_err(|e| anyhow!("serialize shared: {:?}", e))?;
    let key: [u8; 32] = Sha3_256::digest(&s_bytes).into();
    let mut out = Vec::with_capacity(80);
    out.extend_from_slice(&r_compressed);
    for i in 0..32 {
        out.push(share_le32[i] ^ key[i]);
    }
    Ok(out)
}

/// XOR keystream from `sym_key` (SHA3-256 counter mode). Self-inverse: `xor_symmetric_stream(xor_symmetric_stream(p,k),k)==p`.
pub fn xor_symmetric_stream(data: &[u8], sym_key: &[u8; 32]) -> Vec<u8> {
    let mut out = data.to_vec();
    let mut ctr: u64 = 0;
    let mut pos = 0usize;
    while pos < out.len() {
        let mut h = Sha3_256::new();
        h.update(sym_key);
        h.update(ctr.to_le_bytes());
        let block = h.finalize();
        for (i, &kb) in block.iter().enumerate() {
            if pos + i < out.len() {
                out[pos + i] ^= kb;
            }
        }
        pos += 32;
        ctr += 1;
    }
    out
}

pub fn decrypt_share_80(ct: &[u8], dk: &Fr) -> Result<[u8; 32]> {
    if ct.len() != 80 {
        return Err(anyhow!("encrypted share must be 80 bytes"));
    }
    let r = G1Affine::deserialize_compressed(&ct[..48usize])
        .map_err(|e| anyhow!("deserialize R: {:?}", e))?;
    let shared = G1Projective::from(r) * dk;
    let mut s_bytes = [0u8; 48];
    shared
        .into_affine()
        .serialize_compressed(&mut s_bytes[..])
        .map_err(|e| anyhow!("serialize shared: {:?}", e))?;
    let key: [u8; 32] = Sha3_256::digest(&s_bytes).into();
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = ct[48 + i] ^ key[i];
    }
    Ok(out)
}
