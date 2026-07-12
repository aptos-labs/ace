// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use super::super::outcome::{Outcome, Reason};
use super::super::shares::keypair_id_str;
use super::super::state::AppState;
use crate::secrets::ShareEntry;
use crate::verify::WorkerRequest;

pub(crate) async fn fetch_share(
    state: &AppState,
    request: &WorkerRequest,
) -> Result<ShareEntry, Outcome> {
    let (keypair_id, epoch) = requested_share(request);
    let keypair_id = keypair_id_str(keypair_id);
    state
        .provider
        .get_share(&keypair_id, epoch)
        .await
        .map_err(|e| Outcome::Rejected {
            reason: Reason::ServiceUnavailable,
            detail: Some(format!("secret share fetch failed: {e:#}")),
        })?
        .ok_or_else(|| Outcome::Rejected {
            reason: Reason::NotFound,
            detail: Some(format!(
                "no share for keypair_id={keypair_id} epoch={epoch}"
            )),
        })
}

fn requested_share(request: &WorkerRequest) -> (&[u8; 32], u64) {
    match request {
        WorkerRequest::DecryptionBasicFlow(req) => (&req.payload.keypair_id, req.payload.epoch),
        WorkerRequest::DecryptionCustomFlow(req) => (&req.keypair_id, req.epoch),
        WorkerRequest::ThresholdVrf(req) => (&req.payload.keypair_id, req.payload.epoch),
    }
}
