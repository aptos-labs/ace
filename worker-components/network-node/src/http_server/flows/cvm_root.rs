// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::time::Instant;

use super::super::outcome::{Outcome, Reason, RequestContext};
use super::super::shares::keypair_id_str;
use super::super::state::AppState;
use super::timing::timed_vrf_preflight;
use super::vrf_share::derive_threshold_vrf_share_from_payload;
use crate::secrets::Snapshot;
use crate::verify::CvmRootVrfRequest;
use vss_common::pke::{self, EncryptionKey};
use vss_common::pke_hpke_x25519_chacha20poly1305 as hpke;

pub(crate) async fn handle_cvm_root_vrf(
    state: &AppState,
    snapshot: &Snapshot,
    req: CvmRootVrfRequest,
    ctx: &mut RequestContext,
) -> Outcome {
    let Some(policy) = state.cvm_root_policy.as_ref() else {
        return reject("attested CVM root flow is disabled");
    };
    if let Err(e) = policy.validate_payload(&req.payload) {
        return reject(&format!("unapproved CVM root input: {:#}", e));
    }
    let keypair_id = keypair_id_str(&req.payload.keypair_id);
    let entry = match timed_vrf_preflight(ctx, snapshot, &keypair_id, req.payload.epoch) {
        Ok(entry) => entry,
        Err(outcome) => return outcome,
    };
    let verify_start = Instant::now();
    let verification = policy.verify_attestation(&req).await;
    ctx.pfn_ms = Some(verify_start.elapsed().as_millis() as u64);
    if let Err(e) = verification {
        return reject(&format!("CVM attestation failed: {:#}", e));
    }
    if let Err(e) = policy.verify_registration(&req, &state.chain_rpc).await {
        return reject(&format!("CVM registration failed: {:#}", e));
    }
    let derive_start = Instant::now();
    let share = match derive_threshold_vrf_share_from_payload(&req.payload, &entry) {
        Ok(share) => share,
        Err(outcome) => return outcome,
    };
    let result = encrypt_cvm_root_response(&req.payload.response_enc_key, &share);
    ctx.extract_ms = Some(derive_start.elapsed().as_millis() as u64);
    result
}

fn encrypt_cvm_root_response(response_key: &EncryptionKey, share: &[u8]) -> Outcome {
    // The generic response helper assumes a valid HPKE public key and can
    // panic for low-order X25519 points. Reject a malformed attested key.
    let EncryptionKey::HpkeX25519ChaCha20Poly1305(key) = response_key else {
        return reject("CVM root response key must use X25519 HPKE");
    };
    match hpke::encrypt(key, share, b"") {
        Ok(ct) => match bcs::to_bytes(&pke::Ciphertext::HpkeX25519ChaCha20Poly1305(ct)) {
            Ok(bytes) => Outcome::Ok {
                share_hex: hex::encode(bytes),
            },
            Err(e) => Outcome::Rejected {
                reason: Reason::Internal,
                detail: Some(format!("encode CVM root response: {}", e)),
            },
        },
        Err(_) => reject("invalid CVM root response key"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_order_x25519_response_key_does_not_crash_worker() {
        let key =
            EncryptionKey::HpkeX25519ChaCha20Poly1305(hpke::EncryptionKey { pk: vec![0u8; 32] });
        assert!(matches!(
            encrypt_cvm_root_response(&key, b"share"),
            Outcome::Rejected { .. }
        ));
    }
}

fn reject(detail: &str) -> Outcome {
    Outcome::Rejected {
        reason: Reason::Forbidden,
        detail: Some(detail.to_string()),
    }
}
