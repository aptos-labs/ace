// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use vss_common::pke::EncryptionKey;

use super::super::outcome::{Flow, RequestContext};
use crate::verify::{
    DecryptionBasicFlowRequest, DecryptionCustomFlowRequest, ThresholdVrfRequest, WorkerRequest,
};

pub(crate) fn record(ctx: &mut RequestContext, request: &WorkerRequest) {
    match request {
        WorkerRequest::DecryptionBasicFlow(req) => record_basic(ctx, req),
        WorkerRequest::DecryptionCustomFlow(req) => record_custom(ctx, req),
        WorkerRequest::ThresholdVrf(req) => record_vrf(ctx, req),
    }
}

fn record_basic(ctx: &mut RequestContext, req: &DecryptionBasicFlowRequest) {
    ctx.flow = Some(Flow::Basic);
    ctx.keypair_short = Some(short_hex(&req.payload.keypair_id));
    ctx.epoch = Some(req.payload.epoch);
    ctx.enc_pk_hex = enc_pk_to_hex(&req.payload.ephemeral_enc_key);
}

fn record_custom(ctx: &mut RequestContext, req: &DecryptionCustomFlowRequest) {
    ctx.flow = Some(Flow::Custom);
    ctx.keypair_short = Some(short_hex(&req.keypair_id));
    ctx.epoch = Some(req.epoch);
    ctx.enc_pk_hex = enc_pk_to_hex(&req.enc_pk);
}

fn record_vrf(ctx: &mut RequestContext, req: &ThresholdVrfRequest) {
    ctx.flow = Some(Flow::ThresholdVrf);
    ctx.keypair_short = Some(short_hex(&req.payload.keypair_id));
    ctx.epoch = Some(req.payload.epoch);
    ctx.enc_pk_hex = enc_pk_to_hex(&req.payload.response_enc_key);
}

fn enc_pk_to_hex(ek: &EncryptionKey) -> Option<String> {
    bcs::to_bytes(ek).ok().map(hex::encode)
}

fn short_hex(keypair_id: &[u8; 32]) -> String {
    hex::encode(&keypair_id[..4])
}
