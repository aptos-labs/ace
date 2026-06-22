// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use super::super::outcome::{Outcome, Reason};
use super::lookup::lookup_share_or_reject;
use crate::secret_usage;
use crate::secrets::{ShareEntry, Snapshot};

pub(crate) fn preflight_tibe_share(
    snapshot: &Snapshot,
    keypair_id: &str,
    epoch: u64,
    tibe_scheme: u8,
) -> Result<ShareEntry, Outcome> {
    let entry = lookup_share_or_reject(snapshot, keypair_id, epoch)?;
    ensure_tibe_group(&entry, tibe_scheme)?;
    ensure_tibe_usage(&entry, keypair_id, epoch, tibe_scheme)?;
    Ok(entry)
}

fn ensure_tibe_group(entry: &ShareEntry, tibe_scheme: u8) -> Result<(), Outcome> {
    match crate::crypto::group_scheme_for_tibe(tibe_scheme) {
        Ok(expected_group) if expected_group == entry.group_scheme => Ok(()),
        Ok(expected_group) => Err(bad_request(format!(
            "tibe_scheme {} requires group {}, but share's group is {}",
            tibe_scheme, expected_group, entry.group_scheme
        ))),
        Err(e) => Err(bad_request(format!(
            "unknown tibe_scheme {}: {:#}",
            tibe_scheme, e
        ))),
    }
}

fn ensure_tibe_usage(
    entry: &ShareEntry,
    keypair_id: &str,
    epoch: u64,
    tibe_scheme: u8,
) -> Result<(), Outcome> {
    let required_usage = secret_usage::usage_for_tibe_scheme(tibe_scheme)
        .map_err(|e| bad_request(format!("unknown tibe_scheme {}: {:#}", tibe_scheme, e)))?;
    if secret_usage::allows_usage(entry.expected_usage, required_usage) {
        return Ok(());
    }
    Err(bad_request(format!(
        "keypair_id={} epoch={} usage mask {} does not allow tibe_scheme {}",
        keypair_id, epoch, entry.expected_usage, tibe_scheme
    )))
}

fn bad_request(detail: String) -> Outcome {
    Outcome::Rejected {
        reason: Reason::BadRequest,
        detail: Some(detail),
    }
}
