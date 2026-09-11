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
    primitive: u8,
) -> Result<ShareEntry, Outcome> {
    let entry = lookup_share_or_reject(snapshot, keypair_id, epoch)?;
    ensure_tibe_group(&entry, primitive)?;
    ensure_tibe_usage(&entry, keypair_id, epoch, primitive)?;
    Ok(entry)
}

fn ensure_tibe_group(entry: &ShareEntry, primitive: u8) -> Result<(), Outcome> {
    match crate::crypto::group_scheme_for_primitive(primitive) {
        Ok(expected_group) if expected_group == entry.group_scheme => Ok(()),
        Ok(expected_group) => Err(bad_request(format!(
            "primitive {} requires group {}, but share's group is {}",
            primitive, expected_group, entry.group_scheme
        ))),
        Err(e) => Err(bad_request(format!(
            "unknown primitive {}: {:#}",
            primitive, e
        ))),
    }
}

fn ensure_tibe_usage(
    entry: &ShareEntry,
    keypair_id: &str,
    epoch: u64,
    primitive: u8,
) -> Result<(), Outcome> {
    let required_usage = secret_usage::usage_for_primitive(primitive)
        .map_err(|e| bad_request(format!("unknown primitive {}: {:#}", primitive, e)))?;
    if secret_usage::allows_usage(entry.expected_usage, required_usage) {
        return Ok(());
    }
    Err(bad_request(format!(
        "keypair_id={} epoch={} usage mask {} does not allow primitive {}",
        keypair_id, epoch, entry.expected_usage, primitive
    )))
}

fn bad_request(detail: String) -> Outcome {
    Outcome::Rejected {
        reason: Reason::BadRequest,
        detail: Some(detail),
    }
}
