// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use tokio::sync::oneshot;

use super::super::state::MaintainerState;
use crate::node::tasks::TaskMap;
use crate::wlog;

pub(super) fn start_task(maintainer: &MaintainerState, session: &str, tasks: &mut TaskMap) {
    let (tx, rx) = oneshot::channel::<()>();
    tasks.insert(session.to_string(), tx);
    let cfg = epoch_change_cur::RunConfig {
        rpc_url: maintainer.epoch_change.rpc_url.clone(),
        rpc_api_key: maintainer.epoch_change.rpc_api_key.clone(),
        rpc_gas_key: maintainer.epoch_change.rpc_gas_key.clone(),
        ace_contract: maintainer.ace.clone(),
        epoch_change_session: session.to_string(),
        account_addr: maintainer.account_addr.clone(),
        account_sk_hex: maintainer.epoch_change.account_sk_hex.clone(),
        pke_dk_hex: maintainer.epoch_change.pke_dk_hex.clone(),
    };
    tokio::spawn(async move {
        if let Err(e) = epoch_change_cur::run(cfg, rx).await {
            wlog!("network-node: epoch-change-cur error: {:#}", e);
        }
    });
    wlog!(
        "network-node: started epoch-change-cur for session={}",
        session
    );
}
