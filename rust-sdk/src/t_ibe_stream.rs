//! Mirrors ts-sdk/src/t-ibe-stream/index.ts
//!
//! Streaming (segmented AEAD) threshold IBE built on the BLS12-381 short-signature scheme.

pub use crate::t_ibe::bfibe_bls12381_shortsig_aead_stream::*;

/// On-chain primitive id of the streaming scheme.
pub const SCHEME_BFIBE_BLS12381_SHORTSIG_AEADSTREAM: u8 = 3;
