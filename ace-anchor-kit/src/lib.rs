// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Shared ACE encoding for the Solana proof-of-permission flow.
//!
//! Hook programs call [`decode_blob_name`] to extract the domain.
//! Workers call [`build_full_request_bytes`] to reconstruct the expected bytes
//! for comparison against the instruction data in the proof transaction.

use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
struct FullRequestBytes {
    keypair_id: [u8; 32],
    epoch: u64,
    ephemeral_enc_key: Vec<u8>,
    domain: Vec<u8>,
}

/// Extract the domain (blob name) bytes from `full_request_bytes`.
pub fn decode_blob_name(bytes: &[u8]) -> Result<Vec<u8>, bcs::Error> {
    Ok(bcs::from_bytes::<FullRequestBytes>(bytes)?.domain)
}

/// Serialize the `full_request_bytes` that must appear in the assert_access instruction data.
///
/// Used by workers to reconstruct the expected bytes for comparison against the proof transaction.
pub fn build_full_request_bytes(keypair_id: &[u8; 32], epoch: u64, enc_key_bytes: &[u8], domain: &[u8]) -> Vec<u8> {
    bcs::to_bytes(&FullRequestBytes {
        keypair_id: *keypair_id,
        epoch,
        ephemeral_enc_key: enc_key_bytes.to_vec(),
        domain: domain.to_vec(),
    })
    .expect("BCS serialization is infallible for FullRequestBytes")
}
