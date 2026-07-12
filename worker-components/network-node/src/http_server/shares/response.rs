// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use vss_common::crypto::pke_encrypt;
use vss_common::pke::EncryptionKey;

use super::super::outcome::{Outcome, Reason};
use crate::secrets::ShareEntry;

pub(crate) fn derive_tibe_share_and_respond(
    entry: &ShareEntry,
    identity: &[u8],
    response_enc_key: &EncryptionKey,
    tibe_scheme: u8,
) -> Outcome {
    let share_bytes = match crate::crypto::partial_extract_idk_share(
        tibe_scheme,
        identity,
        &entry.scalar_le32,
        entry.eval_point,
    ) {
        Ok(bytes) => bytes,
        Err(e) => return internal(format!("partial_extract_idk_share: {:#}", e)),
    };
    encrypt_response_bytes(response_enc_key, &share_bytes)
}

pub(crate) fn encrypt_response_bytes(
    response_enc_key: &EncryptionKey,
    share_bytes: &[u8],
) -> Outcome {
    let resp_ct = pke_encrypt(response_enc_key, share_bytes);
    match bcs::to_bytes(&resp_ct) {
        Ok(b) => Outcome::Ok {
            share_hex: hex::encode(b),
        },
        Err(e) => internal(format!("bcs encode response: {}", e)),
    }
}

fn internal(detail: String) -> Outcome {
    Outcome::Rejected {
        reason: Reason::Internal,
        detail: Some(detail),
    }
}
