// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! BCS message bodies for off-chain VSS node-to-node requests.

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareRequest {
    pub session_addr: String,
    pub holder_index: u64,
}
