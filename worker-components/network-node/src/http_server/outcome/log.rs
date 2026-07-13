// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::time::Instant;

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;
use vss_common::pke;

use super::{fields::add_optional_fields, Flow, Outcome, RequestContext};
use crate::now_utc_iso;

pub(crate) fn new_handling_session_id() -> String {
    Uuid::new_v4().to_string()
}

pub(crate) fn finish_response(
    handling_session_id: String,
    start: Instant,
    ctx: &RequestContext,
    outcome: Outcome,
) -> Result<pke::Ciphertext, StatusCode> {
    let mut log = base_log(handling_session_id, start, ctx);
    match outcome {
        Outcome::Ok { ciphertext } => {
            log["result"] = json!("ok");
            log["share_bytes"] = json!(bcs::to_bytes(&ciphertext)
                .map(|bytes| bytes.len())
                .unwrap_or_default());
            eprintln!("{}", log);
            Ok(ciphertext)
        }
        Outcome::Rejected { reason, detail } => {
            log["result"] = json!(reason.result_label());
            log["reason"] = json!(reason.label());
            if let Some(d) = detail {
                log["detail"] = json!(d);
            }
            eprintln!("{}", log);
            Err(reason.status())
        }
    }
}

fn base_log(id: String, start: Instant, ctx: &RequestContext) -> serde_json::Value {
    let mut log = json!({
        "ts": now_utc_iso(),
        "kind": "ACE_REQUEST_HANDLING_SUMMARY",
        "handling_session_id": id,
        "flow": ctx.flow.unwrap_or(Flow::Unknown).label(),
        "elapsed_ms": start.elapsed().as_millis() as u64,
    });
    add_optional_fields(&mut log, ctx);
    log
}
