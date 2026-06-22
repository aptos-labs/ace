// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use super::super::outcome::{Outcome, Reason};
use crate::secrets::ShareEntry;
use crate::verify::ThresholdVrfRequest;

pub(crate) fn derive_threshold_vrf_share(
    req: &ThresholdVrfRequest,
    entry: &ShareEntry,
) -> Result<Vec<u8>, Outcome> {
    crate::crypto::partial_derive_threshold_vrf_share(
        &req.payload.keypair_id,
        &req.payload.contract_id,
        &req.payload.account_address,
        &req.payload.label,
        &entry.scalar_le32,
        entry.eval_point,
        entry.group_scheme,
    )
    .map_err(|e| Outcome::Rejected {
        reason: Reason::Internal,
        detail: Some(format!("partial_derive_threshold_vrf_share: {:#}", e)),
    })
}
