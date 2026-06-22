// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use vss_common::group::SCHEME_BLS12381G2;

use super::outcome::{Outcome, Reason};
use super::shares::extract_and_respond;
use super::tests_support::{dummy_response_enc_key, snapshot_with_share};
use crate::secret_usage;
use crate::secrets::ShareEntry;

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
