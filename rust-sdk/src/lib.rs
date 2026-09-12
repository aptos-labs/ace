// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! ACE Rust SDK. Module layout mirrors `ts-sdk/src` one-to-one; each module documents the TS
//! file it corresponds to.

pub mod address;
pub mod error;
pub mod group;
pub mod pedersen_polynomial_commitment;
pub mod pke;
pub mod sig;
pub mod sigma_dlog_linear;
pub mod utils;
pub mod vss;
pub mod wire;

pub use address::AccountAddress;
pub use error::{AceError, Result};
pub use wire::Wire;
