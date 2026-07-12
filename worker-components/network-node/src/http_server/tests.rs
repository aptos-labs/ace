// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use vss_common::group::SCHEME_BLS12381G2;

use super::outcome::{Outcome, Reason};
use super::shares::preflight_tibe_share;
use super::tests_support::{dummy_pcs_context, dummy_share_commitment};
use crate::secret_usage;
use crate::secrets::ShareEntry;

#[test]
fn preflight_rejects_vrf_only_share_for_tibe() {
    let keypair_id = "0xkp";
    let epoch = 7;
    let share = ShareEntry {
        scalar_le32: [1u8; 32],
        blinding_le32: [2u8; 32],
        group_scheme: SCHEME_BLS12381G2,
        pcs_context: dummy_pcs_context(),
        share_commitment: dummy_share_commitment(),
        expected_usage: secret_usage::USAGE_BLS12381_THRESHOLD_VRF,
        eval_point: 2,
        note: "vrf only".to_string(),
    };

    let outcome = preflight_tibe_share(
        &share,
        keypair_id,
        epoch,
        crate::crypto::SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD,
    )
    .expect_err("VRF-only share must not serve IBE");

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
