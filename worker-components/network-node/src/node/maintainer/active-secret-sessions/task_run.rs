// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use tokio::sync::oneshot;

use super::share;
use super::task::ShareTask;
use crate::wlog;

pub(super) async fn run(task: ShareTask, rx: oneshot::Receiver<()>) {
    match vss_common::reconstruct_share(
        &task.rpc,
        &task.ace,
        &task.secret,
        &task.account_addr,
        &task.pke_dk,
    )
    .await
    {
        Ok((scalar_le32, keypair_id, group_scheme)) => {
            share::register_share(&task, scalar_le32, keypair_id.clone(), group_scheme).await;
            let _ = rx.await;
            share::schedule_eviction(&task, keypair_id);
        }
        Err(e) => {
            wlog!(
                "network-node: [active-secret-sessions] reconstruct_share failed for {}: {:#}",
                task.secret,
                e
            );
        }
    }
}
