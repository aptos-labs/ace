// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use super::state::MaintainerState;
use crate::wlog;

pub(crate) fn spawn_cleanup(maintainer: &MaintainerState) {
    let shares = maintainer.shares.clone();
    let expiry_queue = maintainer.expiry_queue.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(5));
        loop {
            ticker.tick().await;
            let expired = {
                let mut q = expiry_queue.lock().unwrap();
                let (done, pending): (Vec<_>, Vec<_>) =
                    q.drain(..).partition(|(t, _, _)| *t <= Instant::now());
                *q = pending;
                done.into_iter().map(|(_, k, e)| (k, e)).collect::<Vec<_>>()
            };
            let mut w = shares.write().await;
            for (keypair_id, epoch) in expired {
                if w.remove(&(keypair_id.clone(), epoch)).is_some() {
                    wlog!(
                        "network-node: [cleanup] evicted keypair_id={} epoch={}",
                        keypair_id,
                        epoch
                    );
                }
            }
        }
    });
}
