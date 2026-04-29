// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Shared ACE encoding for the Solana proof-of-permission flow.
//!
//! # `full_request_bytes` layout
//!
//! ```text
//! keypairId       32 bytes  (raw AccountAddress)
//! epoch            8 bytes  (u64 little-endian)
//! ephemeralEncKey  BCS bytes: ULEB128(len) + len bytes
//! domain           BCS bytes: ULEB128(len) + len bytes
//! ```
//!
//! Hook programs call [`decode_blob_name`] to extract the domain.
//! Workers call [`build_full_request_bytes`] to reconstruct the expected bytes
//! for comparison against the instruction data in the proof transaction.

#[derive(Debug)]
pub enum AceError {
    TooShort,
    Overflow,
}

impl core::fmt::Display for AceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AceError::TooShort => write!(f, "full_request_bytes too short or malformed"),
            AceError::Overflow => write!(f, "ULEB128 overflow in full_request_bytes"),
        }
    }
}

/// Extract the domain (blob name) bytes from `full_request_bytes`.
///
/// Returns a slice into the original buffer — no allocation needed.
pub fn decode_blob_name(bytes: &[u8]) -> Result<&[u8], AceError> {
    // Skip keypairId (32 B) + epoch (8 B)
    let mut pos = 40usize;
    if bytes.len() < pos {
        return Err(AceError::TooShort);
    }
    // Skip ephemeralEncKey: ULEB128 length + that many bytes
    let (enc_key_len, n) = read_uleb128(bytes, pos)?;
    pos += n + enc_key_len;
    if bytes.len() < pos {
        return Err(AceError::TooShort);
    }
    // Read domain: ULEB128 length + raw bytes
    let (domain_len, n) = read_uleb128(bytes, pos)?;
    pos += n;
    if bytes.len() < pos + domain_len {
        return Err(AceError::TooShort);
    }
    Ok(&bytes[pos..pos + domain_len])
}

/// Serialize the `full_request_bytes` that must appear in the assert_access instruction data.
///
/// Used by workers to reconstruct the expected bytes for comparison against the proof transaction.
pub fn build_full_request_bytes(keypair_id: &[u8; 32], epoch: u64, enc_key_bytes: &[u8], domain: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(keypair_id);
    out.extend_from_slice(&epoch.to_le_bytes());
    write_bcs_bytes(&mut out, enc_key_bytes);
    write_bcs_bytes(&mut out, domain);
    out
}

fn write_bcs_bytes(out: &mut Vec<u8>, data: &[u8]) {
    write_uleb128(out, data.len() as u64);
    out.extend_from_slice(data);
}

fn write_uleb128(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let b = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(b);
            break;
        }
        out.push(b | 0x80);
    }
}

fn read_uleb128(bytes: &[u8], start: usize) -> Result<(usize, usize), AceError> {
    let mut result = 0usize;
    let mut shift = 0u32;
    let mut i = start;
    loop {
        if i >= bytes.len() {
            return Err(AceError::TooShort);
        }
        let b = bytes[i];
        i += 1;
        let chunk = (b & 0x7f) as usize;
        result |= chunk.checked_shl(shift).ok_or(AceError::Overflow)?;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(AceError::Overflow);
        }
    }
    Ok((result, i - start))
}
