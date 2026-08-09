// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, sync::Arc};

use tokio::sync::Semaphore;
use vss_common::pke::EncryptionKey;
use vss_common::pke_hpke_x25519_chacha20poly1305 as hpke;
use vss_common::sig;
use vss_common::AptosRpc;

use super::state::AppState;
use super::status::{NodeStatus, PublicNodeConfig};
use crate::secrets::{LocalSecrets, SecretsProvider, ShareEntry, Snapshot};
use crate::ChainRpcConfig;

pub(crate) fn dummy_response_enc_key() -> EncryptionKey {
    EncryptionKey::HpkeX25519ChaCha20Poly1305(hpke::EncryptionKey { pk: vec![0u8; 32] })
}

fn dummy_rpc(label: &str) -> AptosRpc {
    AptosRpc::new(format!("https://{}.example/v1", label))
}

fn dummy_chain_rpc() -> ChainRpcConfig {
    ChainRpcConfig {
        aptos_mainnet: dummy_rpc("mainnet"),
        aptos_testnet: dummy_rpc("testnet"),
        aptos_localnet: dummy_rpc("localnet"),
        aptos_shelbynet: dummy_rpc("shelbynet"),
        aptos_shelby_private_beta: Some(dummy_rpc("shelby")),
        solana_mainnet_beta: "https://solana-mainnet.example".to_string(),
        solana_testnet: "https://solana-testnet.example".to_string(),
        solana_devnet: "https://solana-devnet.example".to_string(),
        solana_client: reqwest::Client::new(),
    }
}

/// Build an `AppState` for handler tests, with an optional reconstructor public key
/// and optional ACE address (for the reconstruction domain check).
/// `provider`/`chain_rpc`/`status`/`pke_dk_bytes` are dummies — the reconstruction
/// flow takes its `Snapshot` as a separate argument and does not touch them.
pub(crate) fn app_state_with_reconstructor(
    reconstructor_pk: Option<sig::PublicKey>,
    ace_addr: Option<[u8; 32]>,
    chain_id: Option<u8>,
) -> AppState {
    AppState {
        provider: Arc::new(SecretsProvider::Local(LocalSecrets {
            shares: Arc::new(tokio::sync::RwLock::new(HashMap::new())),
        })),
        chain_rpc: Arc::new(dummy_chain_rpc()),
        concurrency: Arc::new(Semaphore::new(1)),
        pke_dk_bytes: Arc::new(Vec::new()),
        status: Arc::new(NodeStatus::new(PublicNodeConfig::new("test"), Vec::new())),
        reconstructor_pk: reconstructor_pk.map(Arc::new),
        ace_addr,
        chain_id,
    }
}

pub(crate) fn snapshot_with_share(keypair_id: &str, epoch: u64, entry: ShareEntry) -> Snapshot {
    let mut entries = HashMap::new();
    entries.insert((keypair_id.to_string(), epoch), entry);
    Snapshot {
        entries: Arc::new(entries),
    }
}
