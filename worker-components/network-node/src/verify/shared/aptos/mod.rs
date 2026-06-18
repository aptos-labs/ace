// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

mod account;
mod account_any;
mod account_any_account;
mod account_any_local;
mod account_any_local_secp256k1;
mod account_deferred;
mod account_federated_keyless;
mod account_keyless;
mod account_multi_ed25519;
mod account_multi_key;
mod account_multi_key_deferred;
mod account_single;
mod account_webauthn;
mod account_webauthn_challenge;
mod account_webauthn_prehash;
pub(crate) mod any;
mod binding;
mod cache;
pub(crate) mod constants;
mod federated_keyless;
pub(crate) mod hooks;
mod jwks;
mod keyless;
pub(crate) mod message;
pub(crate) mod multi_ed25519;
pub(crate) mod multi_key;
mod proof;
mod proof_serde;

pub(crate) use account::verify_account_proof;
pub(crate) use binding::AptosPayloadBinding;
pub(crate) use constants::{APTOS_CUSTOM_DECRYPTION_HOOK, APTOS_DECRYPTION_HOOK, APTOS_VRF_HOOK};
pub(crate) use hooks::check_ace_request_hook;
pub(crate) use message::extract_request_origin;
pub use proof::{
    AptosContractId, AptosProofOfPermission, AptosPublicKeyMaterial, AptosSignatureMaterial,
};
