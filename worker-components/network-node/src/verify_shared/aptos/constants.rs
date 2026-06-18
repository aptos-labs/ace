// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

pub(crate) const APTOS_DECRYPTION_HOOK: &str = "on_ace_decryption_request";
pub(crate) const APTOS_VRF_HOOK: &str = "on_ace_vrf_request";
pub(crate) const APTOS_CUSTOM_DECRYPTION_HOOK: &str = "on_ace_decryption_request_custom_flow";

// pk_scheme / sig_scheme constants — keep in lockstep with `_internal/aptos.ts`.
pub(super) const PK_SCHEME_ED25519_WIRE: u8 = 0;
pub(super) const PK_SCHEME_ANY_WIRE: u8 = 1;
pub(super) const PK_SCHEME_MULTI_ED25519_WIRE: u8 = 2;
pub(super) const PK_SCHEME_MULTI_KEY_WIRE: u8 = 3;
pub(super) const PK_SCHEME_KEYLESS_WIRE: u8 = 4;
pub(super) const PK_SCHEME_FEDERATED_KEYLESS_WIRE: u8 = 5;
pub(super) const SIG_SCHEME_ED25519_WIRE: u8 = 0;
pub(super) const SIG_SCHEME_ANY_WIRE: u8 = 1;
pub(super) const SIG_SCHEME_MULTI_ED25519_WIRE: u8 = 2;
pub(super) const SIG_SCHEME_MULTI_KEY_WIRE: u8 = 3;
pub(super) const SIG_SCHEME_KEYLESS_WIRE: u8 = 4;

pub(super) const KEYLESS_RESOURCE_CACHE_TTL: Duration = Duration::from_secs(3);
