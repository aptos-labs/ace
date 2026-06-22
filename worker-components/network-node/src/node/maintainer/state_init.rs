// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use anyhow::Result;
use tokio::sync::RwLock;
use vss_common::{normalize_account_addr, parse_ed25519_signing_key_hex, AptosRpc};

use super::super::handler::decode_hex_key;
use super::super::MaintainerConfig;
use super::epoch_config::EpochChangeConfig;
use super::state::MaintainerState;
use crate::secrets::LocalSecrets;
use crate::wlog;

impl MaintainerState {
    pub(crate) fn new(config: MaintainerConfig) -> Result<Self> {
        let rpc = AptosRpc::new_with_gas_key(
            config.ace_deployment_api.clone(),
            config.ace_deployment_apikey.clone(),
            config.ace_deployment_gaskey.clone(),
        );
        let sk = parse_ed25519_signing_key_hex(&config.account_sk_hex)?;
        let vk = sk.verifying_key();
        let account_addr = normalize_account_addr(&config.account_addr);
        let ace = normalize_account_addr(&config.ace_deployment_addr);
        let shares = Arc::new(RwLock::new(HashMap::new()));
        wlog!(
            "network-node: starting (account={} ace={})",
            account_addr,
            ace
        );
        Ok(Self {
            rpc,
            sk,
            vk,
            account_addr,
            ace,
            pke_dk_bytes: Arc::new(decode_hex_key(&config.pke_dk)?),
            epoch_change: EpochChangeConfig::from(&config),
            local: LocalSecrets {
                shares: shares.clone(),
            },
            shares,
            expiry_queue: Arc::new(Mutex::new(Vec::new())),
        })
    }
}
