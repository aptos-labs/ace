// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Off-chain verification of an Aptos keyless signature over an arbitrary
//! message.
//!
//! The wire types here are BCS-compatible with `aptos_types::keyless::*` and
//! `aptos_keyless_verify::*` (the in-progress standalone crate in aptos-core).
//! BCS-compat is the contract: a [`KeylessPublicKey`] / [`KeylessSignature`]
//! produced by the Aptos TS SDK and BCS-serialized round-trips into these
//! types and vice-versa.
//!
//! ## Public surface
//!
//! - [`verify_signature`] — the single entry point. Verifies a `KeylessSignature`
//!   over `message` under `pk`, using on-chain inputs the caller fetches
//!   (the RSA JWK, the Groth16 verifying key, the keyless `Configuration`).
//! - [`KeylessPublicKey::account_authentication_key`] — the 32-byte auth key
//!   on chain when this `KeylessPublicKey` is used as a single-key account.
//!
//! ## What is and is NOT checked
//!
//! Verified:
//!   1. EPK expiry (`signature.exp_date_secs > now_unix_secs`).
//!   2. `cert.exp_horizon_secs <= config.max_exp_horizon_secs`.
//!   3. The JWT header's `kid` matches `jwk.kid`.
//!   4. Groth16 proof verifies under `groth16_vk`. The public-input hash is
//!      currently sourced from a caller-supplied callback / hard-coded
//!      fixture; full on-the-fly computation requires Poseidon-BN254 (TODO,
//!      see [`public_inputs_hash`]).
//!   5. Ephemeral Ed25519 (or WebAuthn — TODO) signature over `message` under
//!      `signature.ephemeral_pubkey`.
//!
//! Deferred to a follow-up (loudly TODO in source):
//!   * OpenID-mode (non-ZK) — only ZK mode is currently supported.
//!   * JWT RSA signature verification.
//!   * Training-wheels signature on the proof.
//!   * Override-aud handling.
//!   * Full Poseidon-BN254 public-input hash computation.
//!
//! Cross-reference: `aptos_keyless_verify::verify_signature` in aptos-core,
//! and the production verifier in `aptos_types::keyless`.

pub mod auth_key;
pub mod circuit;
pub mod errors;
pub mod groth16;
pub mod jwk;
pub mod public_inputs_hash;
pub mod poseidon;
pub mod types;
pub mod verify;

pub use public_inputs_hash::get_public_inputs_hash;

pub use auth_key::{federated_keyless_account_authentication_key, keyless_account_authentication_key};
pub use errors::VerifyError;
pub use groth16::Groth16VerificationKey;
pub use jwk::RsaJwk;
pub use types::{
    Configuration, EphemeralCertificate, EphemeralPublicKey, EphemeralSignature,
    FederatedKeylessPublicKey, Groth16Proof, IdCommitment, KeylessPublicKey, KeylessSignature,
    ZeroKnowledgeSig, ZkProof,
};
pub use verify::verify_signature;
