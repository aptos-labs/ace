// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

pub(crate) const APTOS_DECRYPTION_HOOK: &str = "on_ace_decryption_request";
pub(crate) const APTOS_CUSTOM_DECRYPTION_HOOK: &str = "on_ace_decryption_request_custom_flow";
pub(crate) const APTOS_VRF_HOOK: &str = "on_ace_vrf_request";

pub(super) const KEYLESS_RESOURCE_CACHE_TTL: Duration = Duration::from_secs(3);
