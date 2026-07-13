// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use tokio::sync::OwnedSemaphorePermit;

use super::super::outcome::{Outcome, Reason};
use super::super::state::AppState;

pub(crate) fn admit_request(state: &AppState) -> Result<OwnedSemaphorePermit, Outcome> {
    Arc::clone(&state.concurrency)
        .try_acquire_owned()
        .map_err(|_| Outcome::Rejected {
            reason: Reason::TooManyRequests,
            detail: None,
        })
}
