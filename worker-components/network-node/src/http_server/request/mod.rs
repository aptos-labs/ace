// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

mod body;
mod dispatch;
mod metadata;
mod parse;
mod share;

use std::time::Instant;

use axum::{body::Bytes, extract::State, http::StatusCode};

use super::outcome::{finish_response, new_handling_session_id, Outcome, RequestContext};
use super::state::AppState;

pub(crate) async fn handle_request(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<String, StatusCode> {
    let handling_session_id = new_handling_session_id();
    let start = Instant::now();
    let mut ctx = RequestContext::default();
    let outcome = handle_request_inner(&state, &body, &mut ctx).await;
    finish_response(handling_session_id, start, &ctx, outcome)
}

async fn handle_request_inner(state: &AppState, body: &[u8], ctx: &mut RequestContext) -> Outcome {
    let _permit = match body::admit_request(state) {
        Ok(permit) => permit,
        Err(outcome) => return outcome,
    };
    let ct_bytes = match body::decode_request_body(body) {
        Ok(bytes) => bytes,
        Err(outcome) => return outcome,
    };
    let request = match parse::decrypt_and_parse_request(state, &ct_bytes, ctx) {
        Ok(request) => request,
        Err(outcome) => return outcome,
    };
    metadata::record(ctx, &request);
    let share = match share::fetch_share(state, &request).await {
        Ok(share) => share,
        Err(outcome) => return outcome,
    };
    dispatch::dispatch_request(state, &share, request, ctx).await
}
