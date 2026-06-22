// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use super::ChainRpcConfig;

/// Deployment mode. See crate-level docs.
pub enum Mode {
    Monolith {
        maintainer: MaintainerConfig,
        handler: Option<HandlerLocalConfig>,
    },
    Maintainer {
        maintainer: MaintainerConfig,
        port: u16,
    },
    Handler {
        maintainer_url: String,
        pke_dk: String,
        port: u16,
        chain_rpc: ChainRpcConfig,
        max_concurrent: Option<usize>,
    },
}

pub struct MaintainerConfig {
    pub ace_deployment_api: String,
    pub ace_deployment_apikey: Option<String>,
    pub ace_deployment_gaskey: Option<String>,
    pub ace_deployment_addr: String,
    pub account_addr: String,
    pub account_sk_hex: String,
    pub pke_dk: String,
}

pub struct HandlerLocalConfig {
    pub port: u16,
    pub chain_rpc: ChainRpcConfig,
    pub max_concurrent: Option<usize>,
}
