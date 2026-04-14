// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! VSS types mirroring `ts-sdk/src/vss/index.ts` and `ts-sdk/src/vss/bls12381-fr.ts`.
//!
//! Outer enums prepend a 1-byte scheme tag; inner struct fields use `bcs::to_bytes()`.

use serde::Serialize;

pub const SCHEME_BLS12381_FR: u8 = 0;

// ── SecretShare ───────────────────────────────────────────────────────────────

/// Wire: [u8 scheme=0x00] [ULEB128(32)+32B x] [ULEB128(32)+32B y]
pub enum SecretShare {
    Bls12381Fr { x: [u8; 32], y: [u8; 32] },
}

#[derive(Serialize)]
struct Bls12381FrSecretShareInner {
    x: Vec<u8>,
    y: Vec<u8>,
}

impl SecretShare {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            SecretShare::Bls12381Fr { x, y } => {
                let inner = Bls12381FrSecretShareInner { x: x.to_vec(), y: y.to_vec() };
                let mut out = vec![SCHEME_BLS12381_FR];
                out.extend(bcs::to_bytes(&inner).expect("bcs serialization failed"));
                out
            }
        }
    }
}

// ── PcsOpening ────────────────────────────────────────────────────────────────

/// Wire: [u8 scheme=0x00] [ULEB128(32)+32B p_eval] [ULEB128(32)+32B r_eval]
pub enum PcsOpening {
    Bls12381Fr { p_eval: [u8; 32], r_eval: [u8; 32] },
}

#[derive(Serialize)]
struct Bls12381FrPcsOpeningInner {
    p_eval: Vec<u8>,
    r_eval: Vec<u8>,
}

impl PcsOpening {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PcsOpening::Bls12381Fr { p_eval, r_eval } => {
                let inner = Bls12381FrPcsOpeningInner { p_eval: p_eval.to_vec(), r_eval: r_eval.to_vec() };
                let mut out = vec![SCHEME_BLS12381_FR];
                out.extend(bcs::to_bytes(&inner).expect("bcs serialization failed"));
                out
            }
        }
    }
}

// ── PcsCommitment ─────────────────────────────────────────────────────────────

/// Wire: [u8 scheme=0x00] [ULEB128(n)] { [ULEB128(48)+48B G1] } × n
pub enum PcsCommitment {
    Bls12381Fr { v_values: Vec<[u8; 48]> },
}

#[derive(Serialize)]
struct Bls12381FrPcsCommitmentInner {
    v_values: Vec<Vec<u8>>,
}

impl PcsCommitment {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PcsCommitment::Bls12381Fr { v_values } => {
                let inner = Bls12381FrPcsCommitmentInner {
                    v_values: v_values.iter().map(|v| v.to_vec()).collect(),
                };
                let mut out = vec![SCHEME_BLS12381_FR];
                out.extend(bcs::to_bytes(&inner).expect("bcs serialization failed"));
                out
            }
        }
    }
}

// ── PcsBatchOpening ───────────────────────────────────────────────────────────

/// Wire: [u8 scheme=0x00] [ULEB128(n)] { p_eval × n } [ULEB128(n)] { r_eval × n }
pub enum PcsBatchOpening {
    Bls12381Fr { p_evals: Vec<[u8; 32]>, r_evals: Vec<[u8; 32]> },
}

#[derive(Serialize)]
struct Bls12381FrPcsBatchOpeningInner {
    p_evals: Vec<Vec<u8>>,
    r_evals: Vec<Vec<u8>>,
}

impl PcsBatchOpening {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            PcsBatchOpening::Bls12381Fr { p_evals, r_evals } => {
                let inner = Bls12381FrPcsBatchOpeningInner {
                    p_evals: p_evals.iter().map(|v| v.to_vec()).collect(),
                    r_evals: r_evals.iter().map(|v| v.to_vec()).collect(),
                };
                let mut out = vec![SCHEME_BLS12381_FR];
                out.extend(bcs::to_bytes(&inner).expect("bcs serialization failed"));
                out
            }
        }
    }
}

// ── DealerState ───────────────────────────────────────────────────────────────

/// Wire: [u8 scheme=0x00] [LE64 n] [ULEB128(t)] { coef_p × t } [ULEB128(t)] { coef_r × t }
pub enum DealerState {
    Bls12381Fr {
        n: u64,
        coefs_poly_p: Vec<[u8; 32]>,
        coefs_poly_r: Vec<[u8; 32]>,
    },
}

#[derive(Serialize)]
struct Bls12381FrDealerStateInner {
    n: u64,
    coefs_poly_p: Vec<Vec<u8>>,
    coefs_poly_r: Vec<Vec<u8>>,
}

impl DealerState {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            DealerState::Bls12381Fr { n, coefs_poly_p, coefs_poly_r } => {
                let inner = Bls12381FrDealerStateInner {
                    n: *n,
                    coefs_poly_p: coefs_poly_p.iter().map(|v| v.to_vec()).collect(),
                    coefs_poly_r: coefs_poly_r.iter().map(|v| v.to_vec()).collect(),
                };
                let mut out = vec![SCHEME_BLS12381_FR];
                out.extend(bcs::to_bytes(&inner).expect("bcs serialization failed"));
                out
            }
        }
    }
}

// ── PrivateShareMessage ───────────────────────────────────────────────────────

/// Concatenated plaintext of a per-recipient PKE ciphertext: SecretShare || PcsOpening.
pub fn private_share_message_bytes(share: &SecretShare, opening: &PcsOpening) -> Vec<u8> {
    let mut out = share.to_bytes();
    out.extend(opening.to_bytes());
    out
}

// ── DealerContribution0 payload ───────────────────────────────────────────────

/// Build the wire-format payload for `on_dealer_contribution_0`.
/// Layout: PcsCommitment || ULEB128(n) || Ciphertext × n || 0x01 || dealer_state_Ciphertext
pub fn dc0_bytes(
    commitment: &PcsCommitment,
    share_ciphertexts: &[crate::pke::Ciphertext],
    dealer_state_ct: &crate::pke::Ciphertext,
) -> Vec<u8> {
    let mut out = commitment.to_bytes();
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
/// Layout: PcsBatchOpening (outer format with scheme byte)
pub fn dc1_bytes(batch_opening: &PcsBatchOpening) -> Vec<u8> {
    batch_opening.to_bytes()
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
