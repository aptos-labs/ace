// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use crate::secrets::ShareEntry;
use crate::verify::{
    BasicFlowRequest, CustomFlowRequest, DecryptionCustomFlowRequest, WorkerRequest,
};

use super::super::flows;
use super::super::outcome::{Outcome, RequestContext};
use super::super::state::AppState;

pub(crate) async fn dispatch_request(
    state: &AppState,
    share: &ShareEntry,
    request: WorkerRequest,
    ctx: &mut RequestContext,
) -> Outcome {
    match request {
        WorkerRequest::DecryptionBasicFlow(req) => {
            let tibe_scheme = req.tibe_scheme;
            flows::handle_basic_flow(
                state,
                share,
                BasicFlowRequest {
                    payload: req.payload,
                    proof: req.proof,
                },
                tibe_scheme,
                ctx,
            )
            .await
        }
        WorkerRequest::DecryptionCustomFlow(req) => {
            dispatch_custom(state, share, req, ctx).await
        }
        WorkerRequest::ThresholdVrf(req) => {
            flows::handle_threshold_vrf(state, share, req, ctx).await
        }
    }
}

async fn dispatch_custom(
    state: &AppState,
    share: &ShareEntry,
    req: DecryptionCustomFlowRequest,
    ctx: &mut RequestContext,
) -> Outcome {
    let tibe_scheme = req.tibe_scheme;
    let request = CustomFlowRequest {
        keypair_id: req.keypair_id,
        epoch: req.epoch,
        contract_id: req.contract_id,
        label: req.label,
        enc_pk: req.enc_pk,
        proof: req.proof,
    };
    flows::handle_custom_flow(state, share, request, tibe_scheme, ctx).await
}
