// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use vss_common::AptosRpc;

/// Pre-built RPC clients for all supported chains.
pub struct ChainRpcConfig {
    pub aptos_mainnet: AptosRpc,
    pub aptos_testnet: AptosRpc,
    pub aptos_localnet: AptosRpc,
    pub aptos_shelby_private_beta: Option<AptosRpc>,
    pub solana_mainnet_beta: String,
    pub solana_testnet: String,
    pub solana_devnet: String,
    pub solana_client: reqwest::Client,
}

impl ChainRpcConfig {
    pub fn aptos_rpc_for_chain_id(&self, chain_id: u8) -> Result<&AptosRpc> {
        match chain_id {
            1 => Ok(&self.aptos_mainnet),
            2 => Ok(&self.aptos_testnet),
            4 => Ok(&self.aptos_localnet),
            139 => self.aptos_shelby_private_beta.as_ref().ok_or_else(|| {
                anyhow!(
                    "no Aptos RPC configured for chain_id 139 (shelby-private-beta); \
                     set --aptos-shelby-private-beta-api"
                )
            }),
            _ => Err(anyhow!("no Aptos RPC configured for chain_id {}", chain_id)),
        }
    }

    pub fn solana_rpc_for_chain_name(&self, name: &str) -> Result<String> {
        Ok(match name {
            "localnet" | "localhost" => "http://127.0.0.1:8899".to_string(),
            "devnet" => self.solana_devnet.clone(),
            "testnet" => self.solana_testnet.clone(),
            "mainnet-beta" => self.solana_mainnet_beta.clone(),
            other => return Err(anyhow!("verify_solana: unsupported chain name '{}'", other)),
        })
    }
}
