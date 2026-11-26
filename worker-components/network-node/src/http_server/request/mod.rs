// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

mod body;
mod dispatch;
mod metadata;
mod parse;

use std::time::Instant;

use axum::{body::Bytes, extract::State, http::StatusCode};

use super::outcome::{finish_response, new_handling_session_id, Outcome, RequestContext};
use super::state::AppState;
use crate::verify::WorkerRequest;

fn request_keypair_epoch(request: &WorkerRequest) -> (String, u64) {
    let (keypair, epoch) = match request {
        WorkerRequest::DecryptionBasicFlow(req) => (&req.payload.keypair_id, req.payload.epoch),
        WorkerRequest::DecryptionCustomFlow(req) => (&req.keypair_id, req.epoch),
        WorkerRequest::ThresholdVrf(req) => (&req.payload.keypair_id, req.payload.epoch),
        WorkerRequest::Reconstruction(req) => (&req.payload.keypair_id, req.payload.epoch),
    };
    (format!("0x{}", hex::encode(keypair)), epoch)
}

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
    let (keypair_id, epoch) = request_keypair_epoch(&request);
    let snapshot = match parse::fetch_snapshot(state, &keypair_id, epoch).await {
        Ok(snapshot) => snapshot,
        Err(outcome) => return outcome,
    };
    dispatch::dispatch_request(state, &snapshot, request, ctx).await
}
