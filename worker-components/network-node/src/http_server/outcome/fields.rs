// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use serde_json::json;

use super::RequestContext;

pub(crate) fn add_optional_fields(log: &mut serde_json::Value, ctx: &RequestContext) {
    if let Some(kp) = ctx.keypair_short.as_deref() {
        log["keypair"] = json!(kp);
    }
    if let Some(e) = ctx.epoch {
        log["epoch"] = json!(e);
    }
    if let Some(pk) = ctx.enc_pk_hex.as_deref() {
        log["enc_pk"] = json!(pk);
    }
    if let Some(v) = ctx.decrypt_ms {
        log["decrypt_ms"] = json!(v);
    }
    if let Some(v) = ctx.pfn_ms {
        log["pfn_ms"] = json!(v);
    }
    if let Some(v) = ctx.extract_ms {
        log["extract_ms"] = json!(v);
    }
}
