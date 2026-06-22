// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use super::super::outcome::{Outcome, Reason};
use crate::secrets::{ShareEntry, Snapshot};

pub(crate) fn lookup_share_or_reject(
    snapshot: &Snapshot,
    keypair_id: &str,
    epoch: u64,
) -> Result<ShareEntry, Outcome> {
    snapshot
        .lookup(keypair_id, epoch)
        .ok_or_else(|| Outcome::Rejected {
            reason: Reason::NotFound,
            detail: Some(format!(
                "no share for keypair_id={} epoch={}",
                keypair_id, epoch
            )),
        })
}
