// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Poseidon-BN254 hashing for keyless public-input derivation.
//!
//! Layered on top of [`poseidon_ark`] (arnaucube's reference Rust port of the
//! iden3/circomlib Poseidon parameters). Round constants match
//! `aptos_crypto::poseidon_bn254` and the ts-sdk's `poseidon-lite` — verified
//! by the `hash_scalars([1, 2]) = 7853200…3530` reference vector at the
//! bottom of this file.
//!
//! The byte-packing helpers (`pack_bytes_to_one_scalar`,
//! `pad_and_pack_bytes_to_scalars_*`, `pad_and_hash_*`) and their constants
//! are ported verbatim from `aptos_crypto::poseidon_bn254::keyless` so the
//! resulting Fr scalars are bit-identical.

use crate::errors::VerifyError;
use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use once_cell::sync::Lazy;
use poseidon_ark::Poseidon;

// poseidon-ark loads its constants on construction (~3 ms). Cache one
// instance for the process lifetime; it's stateless after init.
static POSEIDON: Lazy<Poseidon> = Lazy::new(Poseidon::new);

/// Max # of scalars `hash_scalars` accepts (one Poseidon instance per arity).
pub const MAX_NUM_INPUT_SCALARS: usize = 16;

/// One BN254 scalar holds 254 bits, but we only pack 31 bytes per scalar to
/// match the Circom keyless circuit. The 6 unused bits are deliberate.
pub const BYTES_PACKED_PER_SCALAR: usize = 31;

/// Max # of bytes that fit in `MAX_NUM_INPUT_SCALARS` scalars after packing.
pub const MAX_NUM_INPUT_BYTES: usize = MAX_NUM_INPUT_SCALARS * BYTES_PACKED_PER_SCALAR;

fn bail<T>(msg: impl Into<String>) -> Result<T, VerifyError> {
    Err(VerifyError::Internal(msg.into()))
}

/// Hashes 1..=`MAX_NUM_INPUT_SCALARS` BN254 scalars to a single Fr via
/// Poseidon. Round constants match `aptos_crypto::poseidon_bn254` and the
/// ts-sdk's `poseidon-lite`.
pub fn hash_scalars(inputs: Vec<Fr>) -> Result<Fr, VerifyError> {
    if inputs.is_empty() || inputs.len() > MAX_NUM_INPUT_SCALARS {
        return bail(format!(
            "Poseidon-BN254 needs 1..={} inputs, got {}",
            MAX_NUM_INPUT_SCALARS,
            inputs.len()
        ));
    }
    POSEIDON
        .hash(inputs)
        .map_err(|e| VerifyError::Internal(format!("Poseidon hash: {}", e)))
}

/// Packs $\le$ `BYTES_PACKED_PER_SCALAR` little-endian bytes into a single Fr.
pub fn pack_bytes_to_one_scalar(chunk: &[u8]) -> Result<Fr, VerifyError> {
    if chunk.len() > BYTES_PACKED_PER_SCALAR {
        return bail(format!(
            "pack_bytes_to_one_scalar: chunk size must be <= {}, got {}",
            BYTES_PACKED_PER_SCALAR,
            chunk.len()
        ));
    }
    Ok(Fr::from_le_bytes_mod_order(chunk))
}

/// Chunks `bytes` into 31-byte little-endian groups and packs each to one Fr.
/// The final chunk may be short; remaining bits are zero-padded.
pub fn pack_bytes_to_scalars(bytes: &[u8]) -> Result<Vec<Fr>, VerifyError> {
    if bytes.len() > MAX_NUM_INPUT_BYTES {
        return bail(format!(
            "pack_bytes_to_scalars: cannot hash more than {} bytes, got {}",
            MAX_NUM_INPUT_BYTES,
            bytes.len()
        ));
    }
    bytes
        .chunks(BYTES_PACKED_PER_SCALAR)
        .map(pack_bytes_to_one_scalar)
        .collect()
}

/// Right-pads `bytes` with zeros to `size`, then chunks-and-packs to Fr.
pub fn pad_and_pack_bytes_to_scalars_no_len(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<Vec<Fr>, VerifyError> {
    if max_bytes > MAX_NUM_INPUT_BYTES {
        return bail(format!(
            "pad_and_pack: max_bytes must be <= {}, got {}",
            MAX_NUM_INPUT_BYTES, max_bytes
        ));
    }
    if bytes.len() > max_bytes {
        return bail(format!(
            "pad_and_pack: input length {} > max_bytes {}",
            bytes.len(),
            max_bytes
        ));
    }
    let mut padded = bytes.to_vec();
    padded.resize(max_bytes, 0x00);
    pack_bytes_to_scalars(&padded)
}

/// Like [`pad_and_pack_bytes_to_scalars_no_len`] but also emits an extra
/// trailing scalar carrying `bytes.len()` (little-endian u64 packed). This
/// prevents collisions where `bytes` could legally end in zero bytes —
/// the original length is committed to the hash.
pub fn pad_and_pack_bytes_to_scalars_with_len(
    bytes: &[u8],
    max_bytes: usize,
) -> Result<Vec<Fr>, VerifyError> {
    let len_scalar = pack_bytes_to_one_scalar(&bytes.len().to_le_bytes())?;
    let mut scalars = pad_and_pack_bytes_to_scalars_no_len(bytes, max_bytes)?;
    scalars.push(len_scalar);
    Ok(scalars)
}

/// `pad_and_pack_bytes_to_scalars_with_len` + `hash_scalars`.
pub fn pad_and_hash_bytes_with_len(bytes: &[u8], max_bytes: usize) -> Result<Fr, VerifyError> {
    hash_scalars(pad_and_pack_bytes_to_scalars_with_len(bytes, max_bytes)?)
}

/// UTF-8 bytes of `str`, padded to `max_bytes` and hashed with the length
/// committed (collision-safe for strings that could legally end in `\0`).
pub fn pad_and_hash_string(s: &str, max_bytes: usize) -> Result<Fr, VerifyError> {
    pad_and_hash_bytes_with_len(s.as_bytes(), max_bytes)
}

/// 32-byte little-endian serialization of a BN254 scalar.
pub fn fr_to_bytes_le(fr: &Fr) -> [u8; 32] {
    fr.into_bigint()
        .to_bytes_le()
        .try_into()
        .expect("BN254 Fr serializes to exactly 32 bytes")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Reference vector shared by:
    ///   - `aptos_crypto::poseidon_bn254` (via neptune + iden3 constants)
    ///   - the TS SDK's `poseidon-lite`
    ///   - arnaucube/poseidon-ark
    /// If this drifts, every downstream consumer's PIH would diverge.
    #[test]
    fn poseidon_reference_vector_1_2() {
        let h = hash_scalars(vec![Fr::from(1u64), Fr::from(2u64)]).unwrap();
        assert_eq!(
            h.to_string(),
            "7853200120776062878684798364095072458815029376092732009249414926327459813530",
        );
    }
}
