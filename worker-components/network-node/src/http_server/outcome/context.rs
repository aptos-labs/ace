// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use super::Flow;

#[derive(Default)]
pub(crate) struct RequestContext {
    pub(crate) flow: Option<Flow>,
    pub(crate) keypair_short: Option<String>,
    pub(crate) epoch: Option<u64>,
    pub(crate) enc_pk_hex: Option<String>,
    pub(crate) decrypt_ms: Option<u64>,
    pub(crate) pfn_ms: Option<u64>,
    pub(crate) extract_ms: Option<u64>,
}
