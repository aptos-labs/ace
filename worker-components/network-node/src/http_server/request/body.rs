// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use tokio::sync::OwnedSemaphorePermit;

use super::super::outcome::{Outcome, Reason};
use super::super::state::AppState;

const MAX_REQUEST_BODY_HEX_BYTES: usize = 1024 * 1024;

pub(crate) fn admit_request(state: &AppState) -> Result<OwnedSemaphorePermit, Outcome> {
    Arc::clone(&state.concurrency)
        .try_acquire_owned()
        .map_err(|_| Outcome::Rejected {
            reason: Reason::TooManyRequests,
            detail: None,
        })
}

pub(crate) fn decode_request_body(body: &[u8]) -> Result<Vec<u8>, Outcome> {
    if body.len() > MAX_REQUEST_BODY_HEX_BYTES {
        return Err(bad_request(format!(
            "request body hex length {} exceeds max {}",
            body.len(),
            MAX_REQUEST_BODY_HEX_BYTES
        )));
    }
    let body_str = std::str::from_utf8(body)
        .map_err(|_| bad_request("body is not valid utf-8".to_string()))?;
    hex::decode(body_str.trim()).map_err(|e| bad_request(format!("hex decode failed: {}", e)))
}

fn bad_request(detail: String) -> Outcome {
    Outcome::Rejected {
        reason: Reason::BadRequest,
        detail: Some(detail),
    }
}
