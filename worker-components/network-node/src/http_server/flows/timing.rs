// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::time::Instant;

use super::super::outcome::{Outcome, RequestContext};
use super::super::shares::{
    derive_tibe_share_and_respond, preflight_threshold_vrf_share, preflight_tibe_share,
};
use crate::secrets::ShareEntry;

pub(crate) fn timed_tibe_preflight(
    ctx: &mut RequestContext,
    share: &ShareEntry,
    keypair_id: &str,
    epoch: u64,
    tibe_scheme: u8,
) -> Result<(), Outcome> {
    let start = Instant::now();
    let result = preflight_tibe_share(share, keypair_id, epoch, tibe_scheme);
    if result.is_err() {
        ctx.extract_ms = Some(start.elapsed().as_millis() as u64);
    }
    result
}

pub(crate) fn timed_vrf_preflight(
    ctx: &mut RequestContext,
    share: &ShareEntry,
    keypair_id: &str,
    epoch: u64,
) -> Result<(), Outcome> {
    let start = Instant::now();
    let result = preflight_threshold_vrf_share(share, keypair_id, epoch);
    if result.is_err() {
        ctx.extract_ms = Some(start.elapsed().as_millis() as u64);
    }
    result
}

pub(crate) fn timed_tibe_response(
    ctx: &mut RequestContext,
    entry: &ShareEntry,
    identity: &[u8],
    response_enc_key: &vss_common::pke::EncryptionKey,
    tibe_scheme: u8,
) -> Outcome {
    let start = Instant::now();
    let outcome = derive_tibe_share_and_respond(entry, identity, response_enc_key, tibe_scheme);
    ctx.extract_ms = Some(start.elapsed().as_millis() as u64);
    outcome
}
