// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::time::Instant;

use axum::http::StatusCode;
use serde_json::json;
use uuid::Uuid;

use super::{fields::add_optional_fields, Flow, Outcome, Reason, RequestContext};
use crate::now_utc_iso;

const REQUEST_HANDLING_SUMMARY_EVENT: &str = "ACE_REQUEST_HANDLING_SUMMARY";

pub(crate) fn new_handling_session_id() -> String {
    Uuid::new_v4().to_string()
}

pub(crate) fn finish_response(
    handling_session_id: String,
    start: Instant,
    ctx: &RequestContext,
    outcome: Outcome,
) -> Result<String, StatusCode> {
    let mut log = base_log(handling_session_id, start, ctx);
    match outcome {
        Outcome::Ok { share_hex } => {
            log["result"] = json!("ok");
            log["share_bytes"] = json!(share_hex.len() / 2);
            eprintln!("{}", log);
            Ok(share_hex)
        }
        Outcome::Rejected { reason, detail } => {
            log["result"] = json!(reason.result_label());
            log["reason"] = json!(reason.label());
            if matches!(reason, Reason::Internal) {
                log["level"] = json!("error");
            }
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
        "level": "info",
        "message": REQUEST_HANDLING_SUMMARY_EVENT,
        "event_name": REQUEST_HANDLING_SUMMARY_EVENT,
        "handling_session_id": id,
        "flow": ctx.flow.unwrap_or(Flow::Unknown).label(),
        "elapsed_ms": start.elapsed().as_millis() as u64,
    });
    add_optional_fields(&mut log, ctx);
    log
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn summary_log_uses_humio_friendly_fields() {
        let ctx = RequestContext {
            flow: Some(Flow::Custom),
            keypair_short: Some("50ca2eb8".to_string()),
            ..Default::default()
        };

        let log = base_log("test-session".to_string(), Instant::now(), &ctx);

        assert_eq!(log["message"], REQUEST_HANDLING_SUMMARY_EVENT);
        assert_eq!(log["event_name"], REQUEST_HANDLING_SUMMARY_EVENT);
        assert_eq!(log["level"], "info");
        assert_eq!(log["handling_session_id"], "test-session");
        assert_eq!(log["flow"], "custom");
        assert_eq!(log["keypair"], "50ca2eb8");
        assert!(log.get("kind").is_none());
    }
}
