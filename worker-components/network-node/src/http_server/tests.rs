// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use vss_common::group::SCHEME_BLS12381G2;
use vss_common::pke::{self, EncryptionKey};
use vss_common::pke_hpke_x25519_chacha20poly1305 as hpke;
use vss_common::sig;

use super::flows::handle_reconstruction;
use super::outcome::{Outcome, Reason, RequestContext};
use super::shares::extract_and_respond;
use super::tests_support::{app_state_with_reconstructor, dummy_response_enc_key, snapshot_with_share};
use crate::secret_usage;
use crate::secrets::ShareEntry;
use crate::verify::{ReconstructionRequest, ReconstructionRequestPayload, ReconstructionResponse};

#[test]
fn extract_rejects_vrf_only_share_for_tibe() {
    let keypair_id = "0xkp";
    let epoch = 7;
    let snapshot = snapshot_with_share(
        keypair_id,
        epoch,
        ShareEntry {
            scalar_le32: [1u8; 32],
            group_scheme: SCHEME_BLS12381G2,
            expected_usage: secret_usage::USAGE_BLS12381_THRESHOLD_VRF,
            eval_point: 2,
            note: "vrf only".to_string(),
        },
    );

    let outcome = extract_and_respond(
        &snapshot,
        keypair_id,
        epoch,
        b"identity",
        &dummy_response_enc_key(),
        crate::crypto::SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD,
    );

    let Outcome::Rejected {
        reason: Reason::BadRequest,
        detail,
    } = outcome
    else {
        panic!("expected BadRequest rejection for VRF-only share");
    };
    assert!(detail
        .unwrap_or_default()
        .contains("does not allow tibe_scheme"));
}

// ── Reconstruction flow ─────────────────────────────────────────────────────────

/// (reconstructor signing key, its sig::PublicKey)
fn reconstructor_keypair(seed: u8) -> (ed25519_dalek::SigningKey, sig::PublicKey) {
    let sk = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
    let pk = sig::PublicKey::from_ed25519_verifying_key(&sk.verifying_key());
    (sk, pk)
}

/// Ephemeral PKE keypair: returns the wrapped EncryptionKey and the wire-format dk bytes.
fn eph_pke_keypair() -> (EncryptionKey, Vec<u8>) {
    let (ek, dk) = hpke::keygen();
    let mut dk_bytes = vec![pke::SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305];
    dk_bytes.extend_from_slice(&dk.to_bytes());
    (EncryptionKey::HpkeX25519ChaCha20Poly1305(ek), dk_bytes)
}

fn signed_reconstruction_request(
    sk: &ed25519_dalek::SigningKey,
    keypair_id: [u8; 32],
    epoch: u64,
    eph_pke_ek: EncryptionKey,
) -> ReconstructionRequest {
    let payload = ReconstructionRequestPayload {
        chain_id: 4,
        ace_addr: [9u8; 32],
        keypair_id,
        epoch,
        eph_pke_ek,
    };
    let sig = vss_common::sig::sign_ed25519(sk, &bcs::to_bytes(&payload).unwrap());
    ReconstructionRequest { payload, sig }
}

/// Cross-language known answer: this MUST byte-match the TS
/// `ReconstructionRequestPayload.toBytes()` in ts-sdk/tests/admin-recovery.test.ts.
/// If either side drifts, the reconstructor signature stops verifying.
#[test]
fn reconstruction_payload_bcs_known_answer() {
    let eph_pke_ek = vss_common::pke::EncryptionKey::HpkeX25519ChaCha20Poly1305(
        hpke::EncryptionKey { pk: vec![0x07u8; 32] },
    );
    let payload = ReconstructionRequestPayload {
        chain_id: 4,
        ace_addr: [0x09u8; 32],
        keypair_id: [0xABu8; 32],
        epoch: 5,
        eph_pke_ek,
    };
    let expected = format!(
        "04{}{}0500000000000000{}",
        "09".repeat(32),   // ace_addr
        "ab".repeat(32),   // keypair_id
        format!("0120{}", "07".repeat(32)), // eph_pke_ek: scheme 01 || uleb 0x20 || 32×07
    );
    assert_eq!(hex::encode(bcs::to_bytes(&payload).unwrap()), expected);
}

#[tokio::test]
async fn reconstruction_serves_raw_share_to_valid_signature() {
    let (sk, pk) = reconstructor_keypair(3);
    let kp_bytes = [0xAB; 32];
    let epoch = 5;
    let scalar = [0x42u8; 32];

    let keypair_id = super::shares::keypair_id_str(&kp_bytes);
    let snapshot = snapshot_with_share(
        &keypair_id,
        epoch,
        ShareEntry {
            scalar_le32: scalar,
            group_scheme: SCHEME_BLS12381G2,
            expected_usage: secret_usage::USAGE_BFIBE_BLS12381_SHORTSIG_AEAD,
            eval_point: 3,
            note: "test".to_string(),
        },
    );

    let (eph_ek, eph_dk_bytes) = eph_pke_keypair();
    let req = signed_reconstruction_request(&sk, kp_bytes, epoch, eph_ek);

    let state = app_state_with_reconstructor(Some(pk), Some([9u8; 32]));
    let mut ctx = RequestContext::default();
    let outcome = handle_reconstruction(&state, &snapshot, req, &mut ctx).await;

    let Outcome::Ok { share_hex } = outcome else {
        panic!("expected Ok, got rejection");
    };
    let resp: ReconstructionResponse =
        bcs::from_bytes(&hex::decode(share_hex).unwrap()).unwrap();
    assert_eq!(resp.eval_point, 3);
    assert_eq!(resp.group_scheme, SCHEME_BLS12381G2);
    let plaintext = pke::pke_decrypt(&eph_dk_bytes, &resp.ct).unwrap();
    assert_eq!(plaintext, scalar.to_vec(), "decrypted share must equal the raw scalar");
}

#[tokio::test]
async fn reconstruction_rejects_wrong_signature() {
    let (_signer, pk) = reconstructor_keypair(3);
    let (attacker_sk, _) = reconstructor_keypair(9); // different key
    let kp_bytes = [0xAB; 32];
    let epoch = 5;

    let keypair_id = super::shares::keypair_id_str(&kp_bytes);
    let snapshot = snapshot_with_share(
        &keypair_id,
        epoch,
        ShareEntry {
            scalar_le32: [0x42u8; 32],
            group_scheme: SCHEME_BLS12381G2,
            expected_usage: secret_usage::USAGE_BFIBE_BLS12381_SHORTSIG_AEAD,
            eval_point: 3,
            note: "test".to_string(),
        },
    );
    let (eph_ek, _) = eph_pke_keypair();
    let req = signed_reconstruction_request(&attacker_sk, kp_bytes, epoch, eph_ek);

    let state = app_state_with_reconstructor(Some(pk), Some([9u8; 32])); // node trusts the honest key
    let mut ctx = RequestContext::default();
    let outcome = handle_reconstruction(&state, &snapshot, req, &mut ctx).await;

    assert!(
        matches!(outcome, Outcome::Rejected { reason: Reason::Forbidden, .. }),
        "wrong signature must be Forbidden"
    );
}

#[tokio::test]
async fn reconstruction_rejects_ace_addr_mismatch() {
    let (sk, pk) = reconstructor_keypair(3);
    let kp_bytes = [0xAB; 32];
    let epoch = 5;
    let keypair_id = super::shares::keypair_id_str(&kp_bytes);
    let snapshot = snapshot_with_share(
        &keypair_id,
        epoch,
        ShareEntry {
            scalar_le32: [0x42u8; 32],
            group_scheme: SCHEME_BLS12381G2,
            expected_usage: secret_usage::USAGE_BFIBE_BLS12381_SHORTSIG_AEAD,
            eval_point: 3,
            note: "test".to_string(),
        },
    );
    let (eph_ek, _) = eph_pke_keypair();
    // Request is validly signed and names ace_addr = [9u8;32]...
    let req = signed_reconstruction_request(&sk, kp_bytes, epoch, eph_ek);
    // ...but this node belongs to a different deployment.
    let state = app_state_with_reconstructor(Some(pk), Some([0xEE; 32]));
    let mut ctx = RequestContext::default();
    let outcome = handle_reconstruction(&state, &snapshot, req, &mut ctx).await;

    assert!(
        matches!(outcome, Outcome::Rejected { reason: Reason::Forbidden, .. }),
        "ace_addr mismatch must be Forbidden"
    );
}

#[tokio::test]
async fn reconstruction_disabled_when_no_reconstructor_pk() {
    let (sk, _pk) = reconstructor_keypair(3);
    let kp_bytes = [0xAB; 32];
    let epoch = 5;
    let keypair_id = super::shares::keypair_id_str(&kp_bytes);
    let snapshot = snapshot_with_share(
        &keypair_id,
        epoch,
        ShareEntry {
            scalar_le32: [0x42u8; 32],
            group_scheme: SCHEME_BLS12381G2,
            expected_usage: secret_usage::USAGE_BFIBE_BLS12381_SHORTSIG_AEAD,
            eval_point: 3,
            note: "test".to_string(),
        },
    );
    let (eph_ek, _) = eph_pke_keypair();
    let req = signed_reconstruction_request(&sk, kp_bytes, epoch, eph_ek);

    let state = app_state_with_reconstructor(None, None); // feature off
    let mut ctx = RequestContext::default();
    let outcome = handle_reconstruction(&state, &snapshot, req, &mut ctx).await;

    assert!(
        matches!(outcome, Outcome::Rejected { reason: Reason::NotFound, .. }),
        "disabled feature must be NotFound"
    );
}
