// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

mod basic;
mod custom;
mod timing;
mod vrf;
mod vrf_share;

use super::outcome::{Outcome, Reason};

pub(crate) use basic::handle_basic_flow;
pub(crate) use custom::handle_custom_flow;
pub(crate) use vrf::handle_threshold_vrf;

fn forbidden(e: anyhow::Error) -> Outcome {
    Outcome::Rejected {
        reason: Reason::Forbidden,
        detail: Some(format!("{:#}", e)),
    }
}
