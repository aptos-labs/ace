// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::RwLock;

use super::super::state::MaintainerState;
use crate::node::state_view::BcsStateViewV0;
use crate::secrets::ShareEntry;

pub(super) struct ShareTask {
    pub(super) rpc: vss_common::AptosRpc,
    pub(super) ace: String,
    pub(super) secret: String,
    pub(super) account_addr: String,
    pub(super) pke_dk: Vec<u8>,
    pub(super) shares: Arc<RwLock<HashMap<(String, u64), ShareEntry>>>,
    pub(super) expiry_queue: Arc<Mutex<Vec<(Instant, String, u64)>>>,
    pub(super) epoch: u64,
    pub(super) expected_usage: u64,
    pub(super) note: String,
    pub(super) eval_point: u64,
}

impl ShareTask {
    pub(super) fn new(
        maintainer: &MaintainerState,
        state: &BcsStateViewV0,
        secret: &str,
        expected_usage: u64,
        note: &str,
        eval_point: u64,
    ) -> Self {
        Self {
            rpc: maintainer.rpc.clone(),
            ace: maintainer.ace.clone(),
            secret: secret.to_string(),
            account_addr: maintainer.account_addr.clone(),
            pke_dk: (*maintainer.pke_dk_bytes).clone(),
            shares: maintainer.shares.clone(),
            expiry_queue: maintainer.expiry_queue.clone(),
            epoch: state.epoch,
            expected_usage,
            note: note.to_string(),
            eval_point,
        }
    }
}
