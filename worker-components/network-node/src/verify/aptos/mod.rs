// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Aptos-side proof-of-permission verification.
//!
//! Owns the wire types and helpers shared between the scheme paths:
//!   - [`ed25519`] — legacy Ed25519 sig over the pretty message
//!   - [`keyless`] — ZK keyless signature
//!   - [`federated_keyless`] — ZK keyless signature with dapp-managed JWKs
//!   - [`any`] — modern `AnyPublicKey` / `AnySignature` (SingleKey scheme)
//!   - [`multi_ed25519`] — legacy K-of-N `MultiEd25519` (raw Ed25519 only)
//!   - [`multi_key`] — K-of-N `MultiKey` / `MultiKeyAuthenticator`

mod account;
mod binding;
mod cache;
mod constants;
mod custom;
mod dispatch;
mod hooks;
mod jwks;
mod message;
mod proof;
mod proof_serde;

// The top-level dispatcher now uses `verify_aptos_account_proof` so both
// decryption and tVRF can share one account-proof path before app-hook checks.
// Keep the older account-specific verifier modules in-tree for now.
#[allow(dead_code)]
pub mod any;
#[allow(dead_code)]
pub mod ed25519;
#[allow(dead_code)]
pub mod federated_keyless;
#[allow(dead_code)]
pub mod keyless;
#[allow(dead_code)]
pub mod multi_ed25519;
#[allow(dead_code)]
pub mod multi_key;

pub use proof::{
    AptosContractId, AptosProofOfPermission, AptosPublicKeyMaterial, AptosSignatureMaterial,
};

pub(super) use binding::AptosPayloadBinding;
pub(super) use custom::verify_custom_aptos;
pub(super) use dispatch::{verify_aptos, verify_threshold_vrf_aptos};
use hooks::check_basic_ace_hook;
use jwks::find_rsa_jwk_in_jwks_resource;
use message::is_valid_hex;
