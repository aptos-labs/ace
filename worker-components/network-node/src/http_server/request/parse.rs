// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::time::Instant;

use vss_common::pke::pke_decrypt_bytes;

use super::super::outcome::{Outcome, Reason, RequestContext};
use super::super::state::AppState;
use crate::verify::{WorkerRequest, MAX_WORKER_REQUEST_PLAINTEXT_BYTES};

pub(crate) fn decrypt_and_parse_request(
    state: &AppState,
    ct_bytes: &[u8],
    ctx: &mut RequestContext,
) -> Result<WorkerRequest, Outcome> {
    let decrypt_start = Instant::now();
    let req_bytes = pke_decrypt_bytes(state.pke_dk_bytes.as_ref(), ct_bytes)
        .map_err(|e| bad_request(format!("pke decrypt failed: {:#}", e)))?;
    ctx.decrypt_ms = Some(decrypt_start.elapsed().as_millis() as u64);
    if req_bytes.len() > MAX_WORKER_REQUEST_PLAINTEXT_BYTES {
        return Err(bad_request(format!(
            "WorkerRequest plaintext length {} exceeds max {}",
            req_bytes.len(),
            MAX_WORKER_REQUEST_PLAINTEXT_BYTES
        )));
    }
    let request: WorkerRequest = bcs::from_bytes(&req_bytes)
        .map_err(|e| bad_request(format!("bcs decode WorkerRequest failed: {}", e)))?;
    request
        .validate_size_limits()
        .map_err(|e| bad_request(format!("WorkerRequest size limit exceeded: {e:#}")))?;
    Ok(request)
}

fn bad_request(detail: String) -> Outcome {
    Outcome::Rejected {
        reason: Reason::BadRequest,
        detail: Some(detail),
    }
}
