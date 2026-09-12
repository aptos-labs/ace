// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/_internal/deployment.ts`.

use crate::address::AccountAddress;

/// Where an ACE deployment lives: a fullnode REST endpoint (`.../v1`) and the ACE contract
/// address, optionally an API key (sent as `Authorization: Bearer`) and a discovery service URL.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct AceDeployment {
    pub api_endpoint: String,
    pub contract_addr: AccountAddress,
    pub api_key: Option<String>,
    pub discovery_url: Option<String>,
}

impl AceDeployment {
    pub fn new(api_endpoint: impl Into<String>, contract_addr: AccountAddress) -> Self {
        Self {
            api_endpoint: api_endpoint.into(),
            contract_addr,
            api_key: None,
            discovery_url: None,
        }
    }
    pub fn with_api_key(mut self, api_key: Option<String>) -> Self {
        self.api_key = api_key;
        self
    }
    pub fn with_discovery_url(mut self, discovery_url: Option<String>) -> Self {
        self.discovery_url = discovery_url;
        self
    }
}
