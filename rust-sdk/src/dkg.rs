// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/dkg/index.ts`: the on-chain DKG `Session` view (deserialize-only in TS).
//! `PublicPoint` there is the scheme-tagged `group::Element`.

use serde::{Deserialize, Serialize};

use crate::address::AccountAddress;
use crate::group::Element;
use crate::impl_bcs_wire;

pub const SCHEME_0: u8 = 0;
pub const SCHEME_1: u8 = 1;
const STATE_DONE: u8 = 3;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Session {
    pub caller: AccountAddress,
    pub workers: Vec<AccountAddress>,
    pub threshold: u64,
    pub base_point: Element,
    pub expected_usage: u64,
    pub note: String,
    pub state: u8,
    pub vss_sessions: Vec<AccountAddress>,
    pub done_flags: Vec<bool>,
    pub result_pk: Option<Element>,
    pub share_pks: Vec<Element>,
}

impl Session {
    pub fn is_completed(&self) -> bool {
        self.state == STATE_DONE
    }
}
impl_bcs_wire!(Session);
