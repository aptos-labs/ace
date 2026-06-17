// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};

use super::super::{DecryptionRequestPayload, ThresholdVrfRequestPayload};

pub(in crate::verify) trait AptosPayloadBinding: serde::Serialize {
    fn to_webauthn_challenge(&self) -> Result<[u8; 32]>;

    /// The hex string the dapp asks the wallet to sign as the AIP-62 `message`
    /// field — `"0x" || hex(BCS(payload))`. The worker reconstructs this from
    /// its own copy of the payload and checks that it appears as a substring of
    /// the wallet's `fullMessage`. Hex is injection-safe (`[0-9a-f]`) and gives
    /// byte-equality on the binding without any of the canonicalization
    /// headaches the old multi-line pretty-text approach had.
    fn to_signed_message_hex(&self) -> Result<String> {
        let bytes = bcs::to_bytes(self).map_err(|e| anyhow!("BCS encode payload: {}", e))?;
        Ok(format!("0x{}", hex::encode(&bytes)))
    }
}

impl AptosPayloadBinding for DecryptionRequestPayload {
    fn to_webauthn_challenge(&self) -> Result<[u8; 32]> {
        DecryptionRequestPayload::to_webauthn_challenge(self)
    }
}

impl AptosPayloadBinding for ThresholdVrfRequestPayload {
    fn to_webauthn_challenge(&self) -> Result<[u8; 32]> {
        ThresholdVrfRequestPayload::to_webauthn_challenge(self)
    }
}
