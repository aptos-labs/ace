// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use vss_common::normalize_account_addr;

pub(crate) fn keypair_id_str(keypair_id: &[u8; 32]) -> String {
    normalize_account_addr(&format!("0x{}", hex::encode(keypair_id)))
}
