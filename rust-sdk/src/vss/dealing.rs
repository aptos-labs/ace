// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/vss/dealing.ts`: deterministic dealing helpers shared with the workers.
//! `eval_poly` / `lagrange_at_zero` live in [`crate::group::bls12381fr`] and are re-exported.

pub use crate::group::bls12381fr::{eval_poly, lagrange_at_zero};
use crate::group::bls12381fr::{fr_from_le_bytes_mod_order, fr_to_le_bytes, Fr};

use crate::error::{AceError, Result};
use crate::utils::sha3_512;

pub const SSS_WIRE_VERSION: u32 = 4;
pub const SSS_SEED_BYTES: usize = 32;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SplitConfig {
    pub n: u64,
    pub t: u64,
}

/// Derive the `t-1` non-constant polynomial coefficients from a 32-byte seed:
/// `Fr(SHA3-512("ace-sss-dealing-v2" || seed || u64le(n) || u64le(t) || u32le(i) || base))`.
pub fn derive_dealing_frs(
    cfg: SplitConfig,
    seed: &[u8],
    base_compressed: &[u8],
) -> Result<Vec<Fr>> {
    if cfg.n < 1 || cfg.t < 1 || cfg.n < cfg.t {
        return Err(AceError::crypto("deriveDealingFrs: require 1 <= t <= n"));
    }
    if seed.len() != SSS_SEED_BYTES {
        return Err(AceError::crypto("deriveDealingFrs: invalid seed length"));
    }
    let mut draws = Vec::with_capacity((cfg.t - 1) as usize);
    for i in 0..(cfg.t - 1) as u32 {
        let mut transcript = Vec::new();
        transcript.extend_from_slice(b"ace-sss-dealing-v2");
        transcript.extend_from_slice(seed);
        transcript.extend_from_slice(&cfg.n.to_le_bytes());
        transcript.extend_from_slice(&cfg.t.to_le_bytes());
        transcript.extend_from_slice(&i.to_le_bytes());
        transcript.extend_from_slice(base_compressed);
        draws.push(fr_from_le_bytes_mod_order(&sha3_512(&transcript)));
    }
    Ok(draws)
}

/// `frPointKey`: hex of the canonical 32-byte LE encoding (map key in TS).
pub fn fr_point_key(x: &Fr) -> String {
    hex::encode(fr_to_le_bytes(x))
}

pub fn x_in_allowed_set(x: &Fr, allowed: &[Fr]) -> bool {
    allowed.contains(x)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dealing_is_deterministic() {
        let cfg = SplitConfig { n: 3, t: 2 };
        let a = derive_dealing_frs(cfg, &[1u8; 32], &[9u8; 96]).unwrap();
        let b = derive_dealing_frs(cfg, &[1u8; 32], &[9u8; 96]).unwrap();
        assert_eq!(a, b);
        assert_eq!(a.len(), 1);
        assert_ne!(derive_dealing_frs(cfg, &[2u8; 32], &[9u8; 96]).unwrap(), a);
        assert!(derive_dealing_frs(SplitConfig { n: 1, t: 2 }, &[1u8; 32], &[]).is_err());
        assert!(derive_dealing_frs(cfg, &[1u8; 31], &[]).is_err());
    }
}
