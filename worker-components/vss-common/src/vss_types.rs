// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! VSS types mirroring `ts-sdk/src/vss/index.ts` and `ts-sdk/src/vss/bls12381-fr.ts`.
//!
//! Outer types prepend a 1-byte scheme tag; inner struct fields use `bcs::to_bytes()`.

use serde::Serialize;

pub const SCHEME_BLS12381_G1: u8 = 0;

// ── SecretShare ───────────────────────────────────────────────────────────────

/// Wire (as PrivateShareMessage plaintext): [u8 scheme=0x00] [ULEB128(32)+32B y]
pub enum SecretShare {
    Bls12381Fr { y: [u8; 32] },
}

#[derive(Serialize)]
struct Bls12381FrSecretShareInner {
    y: Vec<u8>,
}

impl SecretShare {
    /// Returns `[u8 scheme][uleb128(32)][32B y]` — the PrivateShareMessage plaintext.
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            SecretShare::Bls12381Fr { y } => {
                let inner = Bls12381FrSecretShareInner { y: y.to_vec() };
                let mut out = vec![SCHEME_BLS12381_G1];
                out.extend(bcs::to_bytes(&inner).expect("bcs serialization failed"));
                out
            }
        }
    }
}

// ── PcsCommitment ─────────────────────────────────────────────────────────────

/// Wire body (no scheme byte): [ULEB128(n)] { [ULEB128(48)+48B G1] } × n
///
/// The scheme byte is written by DealerContribution0, not by PcsCommitment.
pub enum PcsCommitment {
    Bls12381Fr { v_values: Vec<[u8; 48]> },
}

#[derive(Serialize)]
struct Bls12381FrPcsCommitmentInner {
    v_values: Vec<Vec<u8>>,
}

impl PcsCommitment {
    /// Returns the body bytes without a scheme-byte prefix.
    /// The caller (dc0_bytes) prepends the scheme byte.
    pub fn body_bytes(&self) -> Vec<u8> {
        match self {
            PcsCommitment::Bls12381Fr { v_values } => {
                let inner = Bls12381FrPcsCommitmentInner {
                    v_values: v_values.iter().map(|v| v.to_vec()).collect(),
                };
                bcs::to_bytes(&inner).expect("bcs serialization failed")
            }
        }
    }

    pub fn scheme_byte(&self) -> u8 {
        match self {
            PcsCommitment::Bls12381Fr { .. } => SCHEME_BLS12381_G1,
        }
    }
}

// ── DealerState ───────────────────────────────────────────────────────────────

/// Wire: [u8 scheme=0x00] [LE64 n] [ULEB128(t)] { [ULEB128(32)+32B coef_p] } × t
pub enum DealerState {
    Bls12381Fr {
        n: u64,
        coefs_poly_p: Vec<[u8; 32]>,
    },
}

#[derive(Serialize)]
struct Bls12381FrDealerStateInner {
    n: u64,
    coefs_poly_p: Vec<Vec<u8>>,
}

impl DealerState {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            DealerState::Bls12381Fr { n, coefs_poly_p } => {
                let inner = Bls12381FrDealerStateInner {
                    n: *n,
                    coefs_poly_p: coefs_poly_p.iter().map(|v| v.to_vec()).collect(),
                };
                let mut out = vec![SCHEME_BLS12381_G1];
                out.extend(bcs::to_bytes(&inner).expect("bcs serialization failed"));
                out
            }
        }
    }
}

// ── PrivateShareMessage ───────────────────────────────────────────────────────

/// Plaintext of a per-recipient PKE ciphertext: just the SecretShare bytes.
pub fn private_share_message_bytes(share: &SecretShare) -> Vec<u8> {
    share.to_bytes()
}

// ── DealerContribution0 payload ───────────────────────────────────────────────

/// Build the wire-format payload for `on_dealer_contribution_0`.
/// Layout: ULEB128(t) || { [u8 scheme] ULEB128(48) 48B } × t || ULEB128(n) || Ciphertext × n || 0x01 || dealer_state_ct
///
/// Each G1 point is prefixed with a per-point scheme byte (matching Move's
/// `deserialize_public_point` which reads scheme then inner bytes).
pub fn dc0_bytes(
    commitment: &PcsCommitment,
    share_ciphertexts: &[crate::pke::Ciphertext],
    dealer_state_ct: &crate::pke::Ciphertext,
) -> Vec<u8> {
    let mut out = Vec::new();
    match commitment {
        PcsCommitment::Bls12381Fr { v_values } => {
            write_uleb128(&mut out, v_values.len() as u64);
            for v in v_values {
                out.push(SCHEME_BLS12381_G1); // per-point scheme byte
                write_uleb128(&mut out, 48);  // uleb128(48) = 0x30
                out.extend_from_slice(v);     // 48 bytes G1 compressed
            }
        }
    }
    write_uleb128(&mut out, share_ciphertexts.len() as u64);
    for ct in share_ciphertexts {
        out.extend(ct.to_bytes());
    }
    out.push(0x01u8); // Option::Some tag for dealer_state
    out.extend(dealer_state_ct.to_bytes());
    out
}

// ── DealerContribution1 payload ───────────────────────────────────────────────

/// Build the wire-format payload for `on_dealer_open`.
/// Layout: vector<Option<Element<Fr>>> — BCS [ULEB128(n)] { [u8 0] | [u8 1][ULEB128(32)][32B y] } × n
///
/// `shares_to_reveal[i]` = None if holder i acked (they already have their share),
///                         Some([u8;32]) = y_i bytes if holder i did not ack.
pub fn dc1_bytes(shares_to_reveal: &[Option<[u8; 32]>]) -> Vec<u8> {
    let mut out = Vec::new();
    write_uleb128(&mut out, shares_to_reveal.len() as u64);
    for opt in shares_to_reveal {
        match opt {
            None => out.push(0u8),
            Some(y_bytes) => {
                out.push(1u8);                // Option::Some tag
                out.push(SCHEME_BLS12381_G1); // scheme byte (Move reads this in deserialize_private_scalar)
                out.push(0x20u8);             // uleb128(32) = length prefix for 32-byte Fr scalar
                out.extend_from_slice(y_bytes);
            }
        }
    }
    out
}

// ── Feldman VSS verification ──────────────────────────────────────────────────

/// Verify that `plaintext` (a `SecretShare` wire encoding) satisfies the Feldman commitment.
///
/// `plaintext` format: `[0x00 scheme][0x20 ULEB128(32)][32B Fr scalar y]`
/// `holder_x`: 1-based evaluation point (= holder 0-based index + 1)
///
/// Checks: `y * base_point == sum(k=0..t-1, x^k * commitment.points[k])`
pub fn feldman_verify(
    plaintext: &[u8],
    base_point: &crate::session::BcsElement,
    commitment: &crate::session::BcsPcsCommitment,
    holder_x: u64,
) -> anyhow::Result<()> {
    use ark_bls12_381::{Fr, G1Affine, G1Projective};
    use ark_ec::CurveGroup;
    use ark_ff::{PrimeField, Zero};
    use ark_serialize::CanonicalDeserialize;

    if plaintext.len() < 34 {
        return Err(anyhow::anyhow!("plaintext too short for SecretShare"));
    }
    let y = &plaintext[2..34]; // skip [scheme byte][ULEB128(32) length prefix]
    let y_fr = Fr::from_le_bytes_mod_order(y);

    let base_bytes = match base_point {
        crate::session::BcsElement::Bls12381G1(p) => p.point.as_slice(),
    };
    let base_g1 = G1Affine::deserialize_compressed(base_bytes)
        .map_err(|e| anyhow::anyhow!("base_point deserialize: {}", e))?;
    let lhs: G1Affine = (base_g1 * y_fr).into_affine();

    let x = Fr::from(holder_x);
    let mut rhs = G1Projective::zero();
    let mut x_power = Fr::from(1u64);
    for elem in &commitment.points {
        let pt_bytes = match elem {
            crate::session::BcsElement::Bls12381G1(p) => p.point.as_slice(),
        };
        let pt = G1Affine::deserialize_compressed(pt_bytes)
            .map_err(|e| anyhow::anyhow!("commitment point deserialize: {}", e))?;
        rhs += pt * x_power;
        x_power *= x;
    }

    if lhs != rhs.into_affine() {
        return Err(anyhow::anyhow!("Feldman verification failed: share does not match commitment"));
    }
    Ok(())
}

// ── ULEB128 helper ────────────────────────────────────────────────────────────

pub fn write_uleb128(out: &mut Vec<u8>, mut v: u64) {
    loop {
        let byte = (v & 0x7f) as u8;
        v >>= 7;
        if v == 0 {
            out.push(byte);
            break;
        }
        out.push(byte | 0x80);
    }
}
