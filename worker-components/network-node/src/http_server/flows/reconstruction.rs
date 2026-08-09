// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Disaster-recovery reconstruction flow.
//!
//! A node started with `--reconstructor-pk` answers a `WorkerRequest::Reconstruction`
//! by returning its **raw Shamir scalar share** (encrypted to the requester's
//! ephemeral PKE key) — *not* a per-identity IDK share, and *without* consulting
//! the on-chain ACE hook. Authorization is a single signature by the configured
//! reconstructor key. A quorum (≥ t) of these shares lets the reconstructor
//! Lagrange-recover the master secret, so every served request is a
//! confidentiality-relevant event and is logged loudly.
//!
//! Like every `WorkerRequest`, the request itself arrives PKE-encrypted to this
//! node's `pke_ek` and is decrypted with the node's `pke_dk` upstream in
//! `request/parse.rs::decrypt_and_parse_request` before dispatch — so by the time
//! `handle_reconstruction` runs, `req` is already the decrypted, BCS-decoded body.

use super::super::outcome::{Outcome, Reason, RequestContext};
use super::super::shares::{encrypt_response_bytes, keypair_id_str};
use super::super::state::AppState;
use crate::secrets::Snapshot;
use crate::verify::{ReconstructionRequest, ReconstructionResponse};
use crate::wlog;

pub(crate) async fn handle_reconstruction(
    state: &AppState,
    snapshot: &Snapshot,
    req: ReconstructionRequest,
    _ctx: &mut RequestContext,
) -> Outcome {
    let keypair_short = hex::encode(&req.payload.keypair_id[..4]);
    let epoch = req.payload.epoch;

    // 1. Feature gate. No `--reconstructor-pk` ⇒ pretend the route doesn't exist.
    let Some(reconstructor_pk) = state.reconstructor_pk.as_ref() else {
        wlog!(
            "RECONSTRUCTION rejected: feature disabled (no --reconstructor-pk); keypair={} epoch={}",
            keypair_short, epoch
        );
        return Outcome::Rejected {
            reason: Reason::NotFound,
            detail: Some("reconstruction not enabled on this node".to_string()),
        };
    };

    // 2. Verify the reconstructor signature over BCS(payload).
    let signed = match bcs::to_bytes(&req.payload) {
        Ok(b) => b,
        Err(e) => {
            return Outcome::Rejected {
                reason: Reason::BadRequest,
                detail: Some(format!("bcs encode ReconstructionRequestPayload: {}", e)),
            }
        }
    };
    match reconstructor_pk.verify(&signed, &req.sig) {
        Ok(true) => {}
        Ok(false) => {
            wlog!(
                "RECONSTRUCTION rejected: bad signature; keypair={} epoch={}",
                keypair_short, epoch
            );
            return Outcome::Rejected {
                reason: Reason::Forbidden,
                detail: Some("reconstructor signature verification failed".to_string()),
            };
        }
        Err(e) => {
            wlog!(
                "RECONSTRUCTION rejected: signature check error ({:#}); keypair={} epoch={}",
                e, keypair_short, epoch
            );
            return Outcome::Rejected {
                reason: Reason::Forbidden,
                detail: Some(format!("reconstructor signature check error: {:#}", e)),
            };
        }
    }

    // 3. Domain check: reject a request whose signed `(chain_id, ace_addr)` names a
    //    different deployment (defense-in-depth over the per-deployment reconstructor
    //    key). `chain_id` is fetched from the ACE fullnode at startup; `ace_addr` is
    //    the node's configured ACE address. `None` ⇒ that half of the check is
    //    skipped (couldn't be determined), leaving signature-only separation.
    if let Some(expected) = state.chain_id {
        if req.payload.chain_id != expected {
            wlog!(
                "RECONSTRUCTION rejected: chain_id mismatch (payload chain_id={} != node chain_id={}); keypair={} epoch={}",
                req.payload.chain_id, expected, keypair_short, epoch
            );
            return Outcome::Rejected {
                reason: Reason::Forbidden,
                detail: Some("reconstruction request chain_id does not match this deployment".to_string()),
            };
        }
    }
    if let Some(expected) = state.ace_addr {
        if req.payload.ace_addr != expected {
            wlog!(
                "RECONSTRUCTION rejected: ace_addr mismatch (payload names a different deployment); keypair={} epoch={}",
                keypair_short, epoch
            );
            return Outcome::Rejected {
                reason: Reason::Forbidden,
                detail: Some("reconstruction request ace_addr does not match this deployment".to_string()),
            };
        }
    }

    // 4. Look up the raw scalar share for (keypair_id, epoch). No ACE-hook check.
    let keypair_id = keypair_id_str(&req.payload.keypair_id);
    let entry = match snapshot.lookup(&keypair_id, epoch) {
        Some(e) => e,
        None => {
            wlog!(
                "RECONSTRUCTION rejected: no share; keypair={} epoch={}",
                keypair_short, epoch
            );
            return Outcome::Rejected {
                reason: Reason::NotFound,
                detail: Some(format!(
                    "no share for keypair_id={} epoch={}",
                    keypair_id, epoch
                )),
            };
        }
    };

    // 5. BCS-encode the whole response and PKE-encrypt it (as one blob) to the
    //    requester's ephemeral key — so eval_point/group_scheme aren't in the clear
    //    either. The HTTP body is a bare `pke::Ciphertext`, same shape as the
    //    decryption flow's response.
    let resp = ReconstructionResponse {
        eval_point: entry.eval_point,
        group_scheme: entry.group_scheme,
        scalar_le32: entry.scalar_le32,
    };
    let resp_bytes = match bcs::to_bytes(&resp) {
        Ok(b) => b,
        Err(e) => {
            return Outcome::Rejected {
                reason: Reason::Internal,
                detail: Some(format!("bcs encode ReconstructionResponse: {}", e)),
            }
        }
    };

    // 6. Loud audit log: a raw share left this node.
    wlog!(
        "RECONSTRUCTION SERVED: raw scalar share released; keypair={} epoch={} eval_point={} group_scheme={}",
        keypair_short, epoch, entry.eval_point, entry.group_scheme
    );

    encrypt_response_bytes(&req.payload.eph_pke_ek, &resp_bytes)
}
