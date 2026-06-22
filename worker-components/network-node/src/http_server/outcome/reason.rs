// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use axum::http::StatusCode;

#[derive(Copy, Clone)]
pub(crate) enum Reason {
    BadRequest,
    Forbidden,
    NotFound,
    ServiceUnavailable,
    TooManyRequests,
    Internal,
}

impl Reason {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Reason::BadRequest => "bad_request",
            Reason::Forbidden => "forbidden",
            Reason::NotFound => "not_found",
            Reason::ServiceUnavailable => "service_unavailable",
            Reason::TooManyRequests => "too_many_requests",
            Reason::Internal => "internal",
        }
    }

    pub(crate) fn status(self) -> StatusCode {
        match self {
            Reason::BadRequest => StatusCode::BAD_REQUEST,
            Reason::Forbidden => StatusCode::FORBIDDEN,
            Reason::NotFound => StatusCode::NOT_FOUND,
            Reason::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE,
            Reason::TooManyRequests => StatusCode::TOO_MANY_REQUESTS,
            Reason::Internal => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    pub(crate) fn result_label(self) -> &'static str {
        match self {
            Reason::Internal => "error",
            _ => "rejected",
        }
    }
}
