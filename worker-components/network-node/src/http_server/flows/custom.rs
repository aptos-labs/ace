// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::time::Instant;

use super::super::outcome::{Outcome, RequestContext};
use super::super::shares::keypair_id_str;
use super::super::state::AppState;
use super::timing::{timed_tibe_preflight, timed_tibe_response};
use crate::secrets::Snapshot;
use crate::verify::{self, CustomFlowRequest};

pub(crate) async fn handle_custom_flow(
    state: &AppState,
    snapshot: &Snapshot,
    req: CustomFlowRequest,
    tibe_scheme: u8,
    ctx: &mut RequestContext,
) -> Outcome {
    let keypair_id = keypair_id_str(&req.keypair_id);
    let entry = match timed_tibe_preflight(ctx, snapshot, &keypair_id, req.epoch, tibe_scheme) {
        Ok(entry) => entry,
        Err(outcome) => return outcome,
    };
    let pfn_start = Instant::now();
    if let Err(e) = verify::verify_custom(&req, &state.chain_rpc).await {
        ctx.pfn_ms = Some(pfn_start.elapsed().as_millis() as u64);
        return super::forbidden(e);
    }
    ctx.pfn_ms = Some(pfn_start.elapsed().as_millis() as u64);
    let identity = verify::identity_bytes(&req.keypair_id, &req.contract_id, &req.label);
    timed_tibe_response(ctx, &entry, &identity, &req.enc_pk, tibe_scheme)
}
