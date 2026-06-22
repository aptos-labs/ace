// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use super::Reason;

pub(crate) enum Outcome {
    Ok {
        share_hex: String,
    },
    Rejected {
        reason: Reason,
        detail: Option<String>,
    },
}
