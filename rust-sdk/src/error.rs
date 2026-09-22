// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Error type shared by every module. Mirrors `ts-sdk/src/result.ts`: where TS returns
//! `Result<T>` (or `Promise<Result<T>>`) this crate returns `Result<T, AceError>`.

#[derive(Debug, thiserror::Error)]
pub enum AceError {
    /// Malformed bytes / hex / BCS.
    #[error("wire: {0}")]
    Wire(String),
    /// A cryptographic operation failed (bad point, invalid scalar, AEAD tag mismatch, ...).
    #[error("crypto: {0}")]
    Crypto(String),
    /// A proof or share failed verification.
    #[error("verify: {0}")]
    Verify(String),
    #[error("insufficient shares: need {need}, got {got}")]
    InsufficientShares { need: usize, got: usize },
    #[error("unsupported scheme {0}")]
    UnsupportedScheme(u8),
    #[error("http {status}: {body}")]
    Http { status: u16, body: String },
    /// On-chain state / fullnode view problems.
    #[error("chain: {0}")]
    Chain(String),
    #[error("signer: {0}")]
    Signer(String),
    #[error("timeout")]
    Timeout,
    #[error("{0}")]
    Other(String),
}

pub type Result<T> = core::result::Result<T, AceError>;

impl AceError {
    pub fn wire(msg: impl Into<String>) -> Self {
        AceError::Wire(msg.into())
    }
    pub fn crypto(msg: impl Into<String>) -> Self {
        AceError::Crypto(msg.into())
    }
}

impl From<bcs::Error> for AceError {
    fn from(e: bcs::Error) -> Self {
        AceError::Wire(format!("bcs: {e}"))
    }
}

impl From<hex::FromHexError> for AceError {
    fn from(e: hex::FromHexError) -> Self {
        AceError::Wire(format!("hex: {e}"))
    }
}
