// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;

use tokio::sync::Semaphore;

use super::status::NodeStatus;
use crate::secrets::{LocalSecrets, SecretsProvider};
use crate::ChainRpcConfig;

/// Shared state for the user-facing request handler.
#[derive(Clone)]
pub struct AppState {
    pub provider: Arc<SecretsProvider>,
    pub chain_rpc: Arc<ChainRpcConfig>,
    pub concurrency: Arc<Semaphore>,
    pub pke_dk_bytes: Arc<Vec<u8>>,
    pub status: Arc<NodeStatus>,
    /// Disaster-recovery reconstructor public key. `Some` iff the node was started
    /// with `--reconstructor-pk`; when `None`, all `WorkerRequest::Reconstruction`
    /// requests are rejected (feature off).
    pub reconstructor_pk: Option<Arc<vss_common::sig::PublicKey>>,
    /// This node's ACE contract address, used to reject reconstruction requests
    /// whose signed `ace_addr` names a different deployment (cross-domain replay).
    /// `None` ⇒ the node doesn't know its ACE address (e.g. handler-only mode
    /// without `--ace-deployment-addr`), so it relies on signature-only domain
    /// separation (the reconstructor key is per-deployment).
    pub ace_addr: Option<[u8; 32]>,
    /// This node's ACE chain id, fetched from the ACE fullnode at startup. Used
    /// alongside `ace_addr` for the reconstruction domain check. `None` ⇒ the
    /// chain id couldn't be determined, so that half of the check is skipped.
    pub chain_id: Option<u8>,
}

#[derive(Clone)]
pub struct SecretsServerState {
    pub local: LocalSecrets,
    pub status: Arc<NodeStatus>,
}
