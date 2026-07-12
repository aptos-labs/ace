// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::time::Instant;

use super::super::outcome::{Outcome, RequestContext};
use super::super::shares::keypair_id_str;
use super::super::state::AppState;
use super::forbidden;
use super::timing::{timed_tibe_preflight, timed_tibe_response};
use crate::secrets::ShareEntry;
use crate::verify::{self, BasicFlowRequest};

pub(crate) async fn handle_basic_flow(
    state: &AppState,
    share: &ShareEntry,
    req: BasicFlowRequest,
    tibe_scheme: u8,
    ctx: &mut RequestContext,
) -> Outcome {
    let keypair_id = keypair_id_str(&req.payload.keypair_id);
    if let Err(outcome) =
        timed_tibe_preflight(ctx, share, &keypair_id, req.payload.epoch, tibe_scheme)
    {
        return outcome;
    }
    let pfn_start = Instant::now();
    if let Err(e) = verify::verify_basic(&req, &state.chain_rpc).await {
        ctx.pfn_ms = Some(pfn_start.elapsed().as_millis() as u64);
        return forbidden(e);
    }
    ctx.pfn_ms = Some(pfn_start.elapsed().as_millis() as u64);
    let identity = verify::identity_bytes(
        &req.payload.keypair_id,
        &req.payload.contract_id,
        &req.payload.domain,
    );
    timed_tibe_response(
        ctx,
        share,
        &identity,
        &req.payload.ephemeral_enc_key,
        tibe_scheme,
    )
}
