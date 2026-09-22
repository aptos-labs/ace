// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/dkr/index.ts`: the on-chain DKR (resharing) `Session` view. TS reads and
//! discards `src_share_pks` / `lagrange_coeffs_at_zero`; they are kept here as plain fields.

use serde::{Deserialize, Serialize};

use crate::address::AccountAddress;
use crate::group::{Element, Scalar};
use crate::impl_bcs_wire;

const STATE_DONE: u8 = 4;

#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct Session {
    pub caller: AccountAddress,
    pub public_base_element: Element,
    pub secretly_scaled_element: Element,
    pub original_session: AccountAddress,
    pub previous_session: AccountAddress,
    pub expected_usage: u64,
    pub note: String,
    pub current_nodes: Vec<AccountAddress>,
    pub current_threshold: u64,
    pub new_nodes: Vec<AccountAddress>,
    pub new_threshold: u64,
    pub state_code: u8,
    pub src_share_pks: Vec<Element>,
    pub vss_sessions: Vec<AccountAddress>,
    pub vss_contribution_flags: Vec<bool>,
    pub lagrange_coeffs_at_zero: Vec<Scalar>,
    pub share_pks: Vec<Element>,
}

impl Session {
    pub fn is_completed(&self) -> bool {
        self.state_code == STATE_DONE
    }
}
impl_bcs_wire!(Session);

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::bls12381g2;
    use crate::wire::Wire;

    #[test]
    fn roundtrip() {
        let g = Element::Bls12381G2(bls12381g2::generator());
        let s = Session {
            caller: AccountAddress::ONE,
            public_base_element: g,
            secretly_scaled_element: g,
            original_session: AccountAddress::ONE,
            previous_session: AccountAddress::ONE,
            expected_usage: 2,
            note: String::new(),
            current_nodes: vec![AccountAddress::ONE],
            current_threshold: 1,
            new_nodes: vec![],
            new_threshold: 1,
            state_code: 4,
            src_share_pks: vec![g],
            vss_sessions: vec![],
            vss_contribution_flags: vec![true],
            lagrange_coeffs_at_zero: vec![Scalar::Bls12381G2(bls12381g2::sample())],
            share_pks: vec![g],
        };
        assert!(s.is_completed());
        assert_eq!(Session::from_bytes(&s.to_bytes()).unwrap(), s);
    }
}
