// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Worker request handler registered into the process-wide node HTTP server.
//!
//! The outer HTTP server lives in `node-msg-gateway` and accepts BCS
//! [`vss_common::node_wire::NodeRequest`] bodies. This module owns only the
//! application-layer worker request handling once the top-level request has
//! been dispatched.
//!
//! Every request emits one JSON-formatted log line tagged with
//! `kind=ACE_REQUEST_HANDLING_SUMMARY`.

mod flows;
mod outcome;
mod request;
mod shares;
mod state;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_support;

pub use self::state::AppState;
