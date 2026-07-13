// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Supervisor for one worker.
//!
//! Three deployment modes:
//!
//! * `Monolith` (default, backwards-compatible): one process does **both** secret
//!   maintenance (URH share reconstruction, `network::touch`, epoch-change-cur/nxt)
//!   and user request handling (`POST /` on `port`).
//! * `Maintainer`: secret maintenance only. Same URH/touch/epoch-change loop as
//!   monolith, but without the user request server. No user-request
//!   verification; no per-chain RPC config needed.
//! * `Handler`: user request handling only. No state polling, no URH, no chain
//!   account key. It reads reconstructed shares from the shared VSS DB using a
//!   background sync loop and serves `POST /`.
//!
//! The split lets the maintainer remain a `min/max=1` singleton (it owns the
//! on-chain DKR ordering invariant) while handlers scale out horizontally
//! behind a load balancer.

mod config;
pub mod crypto;
mod http_server;
mod onchain;
mod reconstruction;
mod runtime;
mod secret_usage;
pub mod secrets;
pub mod verify;

pub use config::{ChainRpcConfig, RunConfig, RuntimeMode};
pub use runtime::run;

/// ISO 8601 UTC timestamp with millisecond precision, e.g. `2026-04-30T16:53:26.877Z`.
pub fn now_utc_iso() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let sec = d.as_secs();
    let ms = d.subsec_millis();
    let days = sec / 86400;
    let t = sec % 86400;
    let (h, m, s) = (t / 3600, (t % 3600) / 60, t % 60);
    let z = days as i64 + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let mon = if mp < 10 { mp + 3 } else { mp - 9 };
    let yr = yoe as i64 + era * 400 + if mon <= 2 { 1 } else { 0 };
    format!("{yr:04}-{mon:02}-{day:02}T{h:02}:{m:02}:{s:02}.{ms:03}Z")
}

/// Log a line to stderr with a UTC timestamp prefix.
#[macro_export]
macro_rules! wlog {
    ($($arg:tt)*) => { eprintln!("[{}] {}", $crate::now_utc_iso(), format_args!($($arg)*)) };
}
