// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use super::task::ShareTask;
use crate::secrets::ShareEntry;
use crate::wlog;

pub(super) async fn register_share(
    task: &ShareTask,
    scalar_le32: [u8; 32],
    keypair_id: String,
    group_scheme: u8,
) {
    task.shares.write().await.insert(
        (keypair_id.clone(), task.epoch),
        ShareEntry {
            scalar_le32,
            group_scheme,
            expected_usage: task.expected_usage,
            eval_point: task.eval_point,
            note: task.note.clone(),
        },
    );
    wlog!(
        "network-node: [active-secret-sessions] registered keypair_id={} epoch={} group_scheme={} expected_usage={} eval_point={}",
        keypair_id, task.epoch, group_scheme, task.expected_usage, task.eval_point
    );
}

pub(super) fn schedule_eviction(task: &ShareTask, keypair_id: String) {
    let deadline = Instant::now() + Duration::from_secs(30);
    task.expiry_queue
        .lock()
        .unwrap()
        .push((deadline, keypair_id.clone(), task.epoch));
    wlog!(
        "network-node: [active-secret-sessions] scheduled eviction keypair_id={} epoch={} in 30s",
        keypair_id,
        task.epoch
    );
}
