// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! HTTP server that handles `POST /` requests for threshold-IBE partial key extraction.
//!
//! Request body: hex-encoded PKE ciphertext encrypted to this node's registered
//! key. The plaintext is a BCS [`crate::verify::WorkerRequest`].
//! Response body: hex-encoded PKE ciphertext encrypted to the client's key. The
//! plaintext is a BCS `tibe.IdentityDecryptionKeyShare` for decryption flows,
//! or a BCS `ThresholdVrfShare` for tVRF.
//!
//! Every request emits one JSON-formatted log line tagged with
//! `message=ACE_REQUEST_HANDLING_SUMMARY` and
//! `event_name=ACE_REQUEST_HANDLING_SUMMARY`.

mod flows;
mod outcome;
mod request;
mod serve;
mod shares;
mod state;
mod status;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_support;

pub use self::serve::{
    run_secrets_admin_server, run_secrets_server, run_user_admin_server, run_user_server,
};
pub use self::state::{AppState, SecretsServerState};
pub use self::status::{
    chain_rpc_dependency_targets, DependencyTarget, NodeStatus, PublicNodeConfig,
    PublicServerConfig,
};
