// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use super::super::MaintainerConfig;

pub(crate) struct EpochChangeConfig {
    pub(crate) rpc_url: String,
    pub(crate) rpc_api_key: Option<String>,
    pub(crate) rpc_gas_key: Option<String>,
    pub(crate) account_sk_hex: String,
    pub(crate) pke_dk_hex: String,
}

impl EpochChangeConfig {
    pub(crate) fn from(config: &MaintainerConfig) -> Self {
        Self {
            rpc_url: config.ace_deployment_api.clone(),
            rpc_api_key: config.ace_deployment_apikey.clone(),
            rpc_gas_key: config.ace_deployment_gaskey.clone(),
            account_sk_hex: config.account_sk_hex.clone(),
            pke_dk_hex: config.pke_dk.clone(),
        }
    }
}
