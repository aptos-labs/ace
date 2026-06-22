// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use super::ActiveSecretSessions;
use crate::node::tasks::TaskMap;
use crate::wlog;

pub(super) fn stop_reconstructions(
    reconstructions: &mut TaskMap,
    active_sessions: &ActiveSecretSessions,
) {
    for k in reconstructions
        .keys()
        .filter(|k| !active_sessions.contains_key(*k))
        .cloned()
        .collect::<Vec<_>>()
    {
        if let Some(tx) = reconstructions.remove(&k) {
            let _ = tx.send(());
            wlog!(
                "network-node: stopped share reconstruction for session={}",
                k
            );
        }
    }
}
