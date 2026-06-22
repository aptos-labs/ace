// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::time::Instant;

use super::super::outcome::{Outcome, RequestContext};
use super::super::shares::{encrypt_response_bytes, keypair_id_str};
use super::super::state::AppState;
use super::forbidden;
use super::timing::timed_vrf_preflight;
use super::vrf_share::derive_threshold_vrf_share;
use crate::secrets::{ShareEntry, Snapshot};
use crate::verify::{self, ThresholdVrfRequest};

pub(crate) async fn handle_threshold_vrf(
    state: &AppState,
    snapshot: &Snapshot,
    req: ThresholdVrfRequest,
    ctx: &mut RequestContext,
) -> Outcome {
    let keypair_id = keypair_id_str(&req.payload.keypair_id);
    let entry = match timed_vrf_preflight(ctx, snapshot, &keypair_id, req.payload.epoch) {
        Ok(entry) => entry,
        Err(outcome) => return outcome,
    };
    let pfn_start = Instant::now();
    if let Err(e) = verify::verify_threshold_vrf(&req, &state.chain_rpc).await {
        ctx.pfn_ms = Some(pfn_start.elapsed().as_millis() as u64);
        return forbidden(e);
    }
    ctx.pfn_ms = Some(pfn_start.elapsed().as_millis() as u64);
    timed_vrf_response(ctx, &req, &entry)
}

fn timed_vrf_response(
    ctx: &mut RequestContext,
    req: &ThresholdVrfRequest,
    entry: &ShareEntry,
) -> Outcome {
    let start = Instant::now();
    let share = match derive_threshold_vrf_share(req, entry) {
        Ok(share) => share,
        Err(outcome) => {
            ctx.extract_ms = Some(start.elapsed().as_millis() as u64);
            return outcome;
        }
    };
    let outcome = encrypt_response_bytes(&req.payload.response_enc_key, &share);
    ctx.extract_ms = Some(start.elapsed().as_millis() as u64);
    outcome
}
