// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use tokio::sync::RwLock;
use vss_common::AptosRpc;

use super::epoch_config::EpochChangeConfig;
use crate::secrets::{LocalSecrets, ShareEntry};

pub(crate) struct MaintainerState {
    pub(crate) rpc: AptosRpc,
    pub(crate) sk: ed25519_dalek::SigningKey,
    pub(crate) vk: ed25519_dalek::VerifyingKey,
    pub(crate) account_addr: String,
    pub(crate) ace: String,
    pub(crate) pke_dk_bytes: Arc<Vec<u8>>,
    pub(crate) epoch_change: EpochChangeConfig,
    pub(crate) shares: Arc<RwLock<HashMap<(String, u64), ShareEntry>>>,
    pub(crate) expiry_queue: Arc<Mutex<Vec<(Instant, String, u64)>>>,
    pub(crate) local: LocalSecrets,
}
