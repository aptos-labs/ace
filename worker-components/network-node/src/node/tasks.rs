// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;

use tokio::sync::oneshot;

pub(crate) type TaskMap = HashMap<String, oneshot::Sender<()>>;

pub(crate) fn stop_tasks(tasks: &mut TaskMap) {
    for (_, tx) in tasks.drain() {
        let _ = tx.send(());
    }
}
