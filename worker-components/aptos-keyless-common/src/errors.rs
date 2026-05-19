// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("BCS decode failed: {0}")]
    Decode(String),

    #[error("ephemeral signature verification failed: {0}")]
    EphemeralSig(String),

    #[error("Groth16 proof verification failed: {0}")]
    Groth16(String),

    #[error("JWT kid mismatch: header={header_kid:?}, jwk={jwk_kid:?}")]
    KidMismatch { header_kid: String, jwk_kid: String },

    #[error("ephemeral public key expired (exp_date_secs={exp}, now={now})")]
    EpkExpired { exp: u64, now: u64 },

    #[error("exp_horizon_secs ({given}) exceeds configuration limit ({max})")]
    ExpHorizonTooLarge { given: u64, max: u64 },

    #[error("unsupported: {0}")]
    Unsupported(&'static str),

    #[error("invalid public input hash: {0}")]
    PublicInputsHash(String),

    #[error("internal: {0}")]
    Internal(String),
}
