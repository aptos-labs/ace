// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use vss_common::pke::EncryptionKey;

use super::super::outcome::Outcome;
use super::{derive_tibe_share_and_respond, preflight_tibe_share};

pub(crate) fn extract_and_respond(
    snapshot: &crate::secrets::Snapshot,
    keypair_id: &str,
    epoch: u64,
    identity: &[u8],
    response_enc_key: &EncryptionKey,
    tibe_scheme: u8,
) -> Outcome {
    let entry = match preflight_tibe_share(snapshot, keypair_id, epoch, tibe_scheme) {
        Ok(entry) => entry,
        Err(outcome) => return outcome,
    };
    derive_tibe_share_and_respond(&entry, identity, response_enc_key, tibe_scheme)
}
