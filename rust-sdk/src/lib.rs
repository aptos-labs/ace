// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! ACE Rust SDK. Module layout mirrors `ts-sdk/src` one-to-one; each module documents the TS
//! file it corresponds to.

pub mod error;
pub mod group;
pub mod sig;
pub mod utils;
pub mod wire;

pub use error::{AceError, Result};
pub use wire::Wire;
