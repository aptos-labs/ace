// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use crate::node::state_view::{addr_bytes_to_string, BcsStateViewV0};

pub(super) type ActiveSecretSessions = HashMap<String, (u64, String)>;

pub(super) fn from_state_view(state: &BcsStateViewV0, in_cur_nodes: bool) -> ActiveSecretSessions {
    if !in_cur_nodes {
        return HashMap::new();
    }
    state
        .secrets
        .iter()
        .map(|s| {
            (
                addr_bytes_to_string(&s.current_session),
                (s.expected_usage, s.note.clone()),
            )
        })
        .collect()
}
