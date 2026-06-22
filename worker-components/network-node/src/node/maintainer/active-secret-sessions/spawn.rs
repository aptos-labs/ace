// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use tokio::sync::oneshot;

use super::super::state::MaintainerState;
use super::task::ShareTask;
use super::task_run;
use crate::node::state_view::BcsStateViewV0;
use crate::node::tasks::TaskMap;
use crate::wlog;

pub(super) fn start_reconstruction(
    maintainer: &MaintainerState,
    state: &BcsStateViewV0,
    session_addr: &str,
    expected_usage: u64,
    note: &str,
    eval_point: u64,
    reconstructions: &mut TaskMap,
) {
    let (tx, rx) = oneshot::channel::<()>();
    reconstructions.insert(session_addr.to_string(), tx);
    let task = ShareTask::new(
        maintainer,
        state,
        session_addr,
        expected_usage,
        note,
        eval_point,
    );
    tokio::spawn(async move { task_run::run(task, rx).await });
    wlog!(
        "network-node: started share reconstruction for session={}",
        session_addr
    );
}
