// Synchronous VSS utilities for BLS12-381.
//
// Polynomial: f(x) = a_0 + a_1*x + ... + a_{d}*x^d  over Fr
// Pedersen-style commitment: C_k = G1_GENERATOR * a_k
// Verification: G1_GENERATOR * share_j == sum(C_k * j^k)

use anyhow::{anyhow, Result};
use ark_bls12_381::{Fr, G1Affine, G1Projective};
use ark_ec::AffineRepr;
use ark_ff::{Field, PrimeField, Zero, One};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};

// BLS12-381 G1 generator (compressed 48 bytes), matching ark-bls12-381's G1Affine::generator().
pub const G1_GENERATOR_BYTES: [u8; 48] = [
    0x97, 0xf1, 0xd3, 0xa7, 0x31, 0x97, 0xd7, 0x94, 0x26, 0x95, 0x63, 0x8c,
    0x4f, 0xa9, 0xac, 0x0f, 0xc3, 0x68, 0x8c, 0x4f, 0x97, 0x74, 0xb9, 0x05,
    0xa1, 0x4e, 0x3a, 0x3f, 0x17, 0x1b, 0xac, 0x58, 0x6c, 0x55, 0xe8, 0x3f,
    0xf9, 0x7a, 0x1a, 0xef, 0xfb, 0x3a, 0xf0, 0x0a, 0xdb, 0x22, 0xc6, 0xbb,
];

pub fn g1_generator() -> G1Affine {
    G1Affine::generator()
}

// ── Lagrange interpolation ────────────────────────────────────────────────────

/// Compute the Lagrange basis polynomial λ_my_index(0) over the given index set.
///
/// λ_i(0) = ∏_{j ∈ all_indices, j≠i}  (0 − j) / (i − j)
///         = ∏_{j≠i}  (−j) / (i − j)
///
/// All indices are 1-based worker indices (never 0).
pub fn lagrange_at_zero(my_index: u64, all_indices: &[u64]) -> Fr {
    let i = Fr::from(my_index);
    let mut num = Fr::one();
    let mut den = Fr::one();
    for &idx in all_indices {
        if idx == my_index {
            continue;
        }
        let j = Fr::from(idx);
        num *= Fr::zero() - j; // (0 - j) = -j
        den *= i - j;
    }
    num * den.inverse().expect("Lagrange denominator zero — duplicate indices?")
}

// ── Polynomial ───────────────────────────────────────────────────────────────

pub struct Polynomial {
    /// coeffs[0] = constant term (the dealer's secret contribution).
    pub coeffs: Vec<Fr>,
}

impl Polynomial {
    /// Generate a random polynomial of degree `degree` (degree+1 coefficients).
    pub fn random<R: rand::Rng + rand::CryptoRng>(degree: usize, rng: &mut R) -> Self {
        let coeffs = (0..=degree)
            .map(|_| {
                let mut bytes = [0u8; 32];
                rng.fill_bytes(&mut bytes);
                Fr::from_le_bytes_mod_order(&bytes)
            })
            .collect();
        Self { coeffs }
    }

    /// Evaluate the polynomial at x.
    pub fn eval(&self, x: u64) -> Fr {
        let x_fr = Fr::from(x);
        let mut result = Fr::zero();
        let mut x_pow = Fr::from(1u64);
        for coeff in &self.coeffs {
            result += *coeff * x_pow;
            x_pow *= x_fr;
        }
        result
    }

    /// Compute vector of G1 commitments: C_k = G1_GEN * coeffs[k].
    pub fn commitments(&self) -> Vec<G1Affine> {
        let g = g1_generator();
        self.coeffs
            .iter()
            .map(|c| {
                let proj: G1Projective = g * c;
                proj.into()
            })
            .collect()
    }

    /// The dealer's partial MPK: G1_GEN * coeffs[0].
    pub fn partial_mpk(&self) -> G1Affine {
        let g = g1_generator();
        let proj: G1Projective = g * self.coeffs[0];
        proj.into()
    }

    /// Serialize coefficients for `dealer_escrow` (4-byte little-endian count + 32-byte LE coeffs).
    pub fn serialize_for_escrow(&self) -> Vec<u8> {
        let mut v = Vec::new();
        let n = self.coeffs.len() as u32;
        v.extend_from_slice(&n.to_le_bytes());
        for c in &self.coeffs {
            v.extend_from_slice(&fr_to_le32(*c));
        }
        v
    }

    /// Deserialize [`Polynomial`] from [`serialize_for_escrow`] bytes.
    pub fn deserialize_from_escrow(data: &[u8]) -> Result<Self> {
        if data.len() < 4 {
            return Err(anyhow!("escrow too short for count"));
        }
        let n = u32::from_le_bytes(data[0..4].try_into().unwrap()) as usize;
        let need = 4usize.saturating_add(n.saturating_mul(32));
        if data.len() < need {
            return Err(anyhow!(
                "escrow length {} < expected {} for {} coeffs",
                data.len(),
                need,
                n
            ));
        }
        let mut coeffs = Vec::with_capacity(n);
        for i in 0..n {
            let s = 4 + i * 32;
            let chunk: [u8; 32] = data[s..s + 32]
                .try_into()
                .map_err(|_| anyhow!("coeff slice"))?;
            coeffs.push(fr_from_le32(&chunk));
        }
        Ok(Self { coeffs })
    }
}

// ── Share verification ────────────────────────────────────────────────────────

/// Verify G1_GEN * share == Σ commitments[k] * worker_index^k
pub fn verify_share(share: Fr, worker_index: u64, commitments: &[G1Affine]) -> bool {
    let g = g1_generator();
    let lhs: G1Affine = {
        let proj: G1Projective = g * share;
        proj.into()
    };

    let x = Fr::from(worker_index);
    let mut x_pow = Fr::from(1u64);
    let mut rhs = G1Projective::from(G1Affine::zero());
    for comm in commitments {
        rhs += G1Projective::from(*comm) * x_pow;
        x_pow *= x;
    }
    let rhs_affine: G1Affine = rhs.into();
    lhs == rhs_affine
}

// ── Serialization helpers ─────────────────────────────────────────────────────

pub fn fr_to_le32(fr: Fr) -> [u8; 32] {
    let bigint = fr.into_bigint();
    let mut bytes = [0u8; 32];
    for (i, limb) in bigint.0.iter().enumerate() {
        let offset = i * 8;
        if offset + 8 <= 32 {
            bytes[offset..offset + 8].copy_from_slice(&limb.to_le_bytes());
        }
    }
    bytes
}

pub fn fr_from_le32(bytes: &[u8]) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

pub fn g1_to_bytes48(point: G1Affine) -> [u8; 48] {
    let mut v = Vec::new();
    point.serialize_compressed(&mut v).expect("G1 serialize");
    v.try_into().expect("48 bytes")
}

pub fn g1_from_bytes48(bytes: &[u8; 48]) -> Option<G1Affine> {
    G1Affine::deserialize_compressed(bytes.as_ref()).ok()
}

// ── On-wire message ───────────────────────────────────────────────────────────

/// Message a dealer sends to a recipient worker.
#[derive(Serialize, Deserialize)]
pub struct DealMsg {
    pub dkg_id: u64,
    pub dealer_index: u64,
    /// Shamir share f(recipient_index) as LE-32 bytes (hex).
    pub share_hex: String,
    /// G1 commitments [C_0, C_1, ...] each as 48-byte hex (compressed).
    pub commitments_hex: Vec<String>,
}

impl DealMsg {
    pub fn build(
        dkg_id: u64,
        dealer_index: u64,
        poly: &Polynomial,
        recipient_index: u64,
    ) -> Self {
        let share = poly.eval(recipient_index);
        let comms = poly.commitments();
        DealMsg {
            dkg_id,
            dealer_index,
            share_hex: hex::encode(fr_to_le32(share)),
            commitments_hex: comms.iter().map(|c| hex::encode(g1_to_bytes48(*c))).collect(),
        }
    }

    pub fn parse_share(&self) -> Result<Fr> {
        let bytes = hex::decode(&self.share_hex)?;
        if bytes.len() != 32 {
            return Err(anyhow!("share must be 32 bytes"));
        }
        Ok(fr_from_le32(&bytes))
    }

    pub fn parse_commitments(&self) -> Result<Vec<G1Affine>> {
        let mut out = Vec::new();
        for hex_str in &self.commitments_hex {
            let b = hex::decode(hex_str)?;
            if b.len() != 48 {
                return Err(anyhow!("commitment must be 48 bytes"));
            }
            let arr: [u8; 48] = b.try_into().unwrap();
            let pt = g1_from_bytes48(&arr)
                .ok_or_else(|| anyhow!("invalid G1 commitment"))?;
            out.push(pt);
        }
        Ok(out)
    }
}

// ── Resharing wire message ────────────────────────────────────────────────────

/// Message an old committee member sends to a new committee member during DKR.
/// The old dealer generates g_i(x) with g_i(0) = s_i (their current share) and
/// sends g_i(recipient_new_index) along with Pedersen commitments.
#[derive(Serialize, Deserialize)]
pub struct ReshareMsg {
    pub epoch_change_id: u64,
    pub secret_id: u64,
    /// Dealer's 1-based index in the OLD committee (x-coordinate for Lagrange).
    pub dealer_old_index: u64,
    /// g_i(recipient_new_index) as LE-32 bytes (hex).
    pub share_hex: String,
    /// G1 commitments [C_0, C_1, ...] each as 48-byte hex (compressed).
    pub commitments_hex: Vec<String>,
}

impl ReshareMsg {
    pub fn build(
        epoch_change_id: u64,
        secret_id: u64,
        dealer_old_index: u64,
        poly: &Polynomial,
        recipient_new_index: u64,
    ) -> Self {
        let share = poly.eval(recipient_new_index);
        let comms = poly.commitments();
        ReshareMsg {
            epoch_change_id,
            secret_id,
            dealer_old_index,
            share_hex: hex::encode(fr_to_le32(share)),
            commitments_hex: comms.iter().map(|c| hex::encode(g1_to_bytes48(*c))).collect(),
        }
    }

    pub fn parse_share(&self) -> anyhow::Result<Fr> {
        let bytes = hex::decode(&self.share_hex)?;
        if bytes.len() != 32 {
            return Err(anyhow::anyhow!("share must be 32 bytes"));
        }
        Ok(fr_from_le32(&bytes))
    }

    pub fn parse_commitments(&self) -> anyhow::Result<Vec<G1Affine>> {
        let mut out = Vec::new();
        for hex_str in &self.commitments_hex {
            let b = hex::decode(hex_str)?;
            if b.len() != 48 {
                return Err(anyhow::anyhow!("commitment must be 48 bytes"));
            }
            let arr: [u8; 48] = b.try_into().unwrap();
            let pt = g1_from_bytes48(&arr)
                .ok_or_else(|| anyhow::anyhow!("invalid G1 commitment"))?;
            out.push(pt);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn g1_generator_bytes_match() {
        let g = g1_generator();
        let bytes = g1_to_bytes48(g);
        let expected = "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
        assert_eq!(hex::encode(bytes), expected, "G1 generator mismatch");
        assert_eq!(bytes, G1_GENERATOR_BYTES, "constant mismatch");
    }
}
