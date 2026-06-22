// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use vss_common::group::SCHEME_BLS12381G2;

use super::super::outcome::{Outcome, Reason};
use super::lookup::lookup_share_or_reject;
use crate::secret_usage;
use crate::secrets::{ShareEntry, Snapshot};

pub(crate) fn preflight_threshold_vrf_share(
    snapshot: &Snapshot,
    keypair_id: &str,
    epoch: u64,
) -> Result<ShareEntry, Outcome> {
    let entry = lookup_share_or_reject(snapshot, keypair_id, epoch)?;
    ensure_threshold_vrf_usage(&entry, keypair_id, epoch)?;
    ensure_threshold_vrf_group(&entry)?;
    Ok(entry)
}

fn ensure_threshold_vrf_usage(
    entry: &ShareEntry,
    keypair_id: &str,
    epoch: u64,
) -> Result<(), Outcome> {
    if secret_usage::allows_usage(
        entry.expected_usage,
        secret_usage::USAGE_BLS12381_THRESHOLD_VRF,
    ) {
        return Ok(());
    }
    Err(Outcome::Rejected {
        reason: Reason::BadRequest,
        detail: Some(format!(
            "keypair_id={} epoch={} usage mask {} does not allow threshold VRF",
            keypair_id, epoch, entry.expected_usage
        )),
    })
}

fn ensure_threshold_vrf_group(entry: &ShareEntry) -> Result<(), Outcome> {
    if entry.group_scheme == SCHEME_BLS12381G2 {
        return Ok(());
    }
    Err(Outcome::Rejected {
        reason: Reason::Internal,
        detail: Some(format!(
            "threshold VRF requires BLS12-381 G2 DKG shares, got group scheme {}",
            entry.group_scheme
        )),
    })
}
