// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Aptos-facing half of the SDK (TS: `_internal/{deployment,aptos,discovery,common}.ts`,
//! `known-deployments.ts`, `ibe-for-aptos*`, `vrf-for-aptos`). Pure types live here
//! unconditionally; network calls need the `aptos` feature.

#[cfg(feature = "aptos")]
pub mod client;
pub mod common;
pub mod deployment;
pub mod discovery;
pub mod known_deployments;

#[cfg(feature = "aptos")]
pub use client::{
    chain_reader, ChainReader, DiscoveryChainReader, FullnodeChainReader, FullnodeClient,
};
pub use common::*;
pub use deployment::AceDeployment;
pub use discovery::{DiscoveryViewV0, NodeInfo, SessionPks};
pub use known_deployments::{known_deployment, KnownDeployment, KNOWN_DEPLOYMENT_IDS};
