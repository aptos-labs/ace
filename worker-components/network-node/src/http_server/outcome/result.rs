// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use super::Reason;
use vss_common::pke;

pub(crate) enum Outcome {
    Ok {
        ciphertext: pke::Ciphertext,
    },
    Rejected {
        reason: Reason,
        detail: Option<String>,
    },
}
