// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/utils.ts`.

use sha3::Digest;

use crate::wire::Serializer;

pub fn rand_bytes(len: usize) -> Vec<u8> {
    use rand::RngCore;
    let mut out = vec![0u8; len];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

pub fn rand_u64() -> u64 {
    use rand::RngCore;
    rand::rngs::OsRng.next_u64()
}

pub fn xor_bytes(a: &[u8], b: &[u8]) -> Vec<u8> {
    assert_eq!(
        a.len(),
        b.len(),
        "Blinder and plaintext must be the same length"
    );
    a.iter().zip(b).map(|(x, y)| x ^ y).collect()
}

pub fn sha3_256(message: &[u8]) -> [u8; 32] {
    sha3::Sha3_256::digest(message).into()
}

pub fn sha3_512(message: &[u8]) -> [u8; 64] {
    sha3::Sha3_512::digest(message).into()
}

/// Block KDF: `SHA3-256(BCS(seed, dst, target_len as u64, block_idx as u64))` per 32-byte block.
/// Panics if `seed.len() < 32` (TS throws).
pub fn kdf(seed: &[u8], dst: &[u8], target_length: usize) -> Vec<u8> {
    assert!(seed.len() >= 32, "Seed must be at least 32 bytes");
    let mut out = Vec::with_capacity(target_length);
    let mut block_idx: u64 = 0;
    while out.len() < target_length {
        let mut s = Serializer::new();
        s.bytes(seed)
            .bytes(dst)
            .u64(target_length as u64)
            .u64(block_idx);
        let block = sha3_256(&s.into_bytes());
        let take = (target_length - out.len()).min(32);
        out.extend_from_slice(&block[..take]);
        block_idx += 1;
    }
    out
}

/// HMAC-SHA3-256 with a 64-byte block, exactly as TS builds it by hand (32-byte key zero-padded).
pub fn hmac_sha3_256(key: &[u8], message: &[u8]) -> [u8; 32] {
    assert_eq!(key.len(), 32, "Key must be 32 bytes");
    let mut k = [0u8; 64];
    k[..32].copy_from_slice(key);
    let ipad = [0x36u8; 64];
    let opad = [0x5cu8; 64];
    let mut inner = xor_bytes(&ipad, &k);
    inner.extend_from_slice(message);
    let mut outer = xor_bytes(&opad, &k);
    outer.extend_from_slice(&sha3_256(&inner));
    sha3_256(&outer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kdf_is_deterministic_and_sized() {
        let seed = [7u8; 32];
        let a = kdf(&seed, b"dst", 70);
        let b = kdf(&seed, b"dst", 70);
        assert_eq!(a, b);
        assert_eq!(a.len(), 70);
        assert_ne!(kdf(&seed, b"other", 70), a);
        // prefix property: first 32 bytes are block 0 regardless of target? No: target_len is
        // part of the preimage, so different lengths differ entirely.
        assert_ne!(&kdf(&seed, b"dst", 32)[..], &a[..32]);
    }
}
