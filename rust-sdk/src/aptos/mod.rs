// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Aptos-facing half of the SDK (TS: `_internal/{deployment,aptos,discovery,common}.ts`,
//! `known-deployments.ts`, `ibe-for-aptos*`, `vrf-for-aptos`). Pure types live here
//! unconditionally; network calls need the `aptos` feature.

pub mod deployment;
pub mod known_deployments;

pub use deployment::AceDeployment;
pub use known_deployments::{known_deployment, KnownDeployment, KNOWN_DEPLOYMENT_IDS};
