// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors the pure part of `ts-sdk/src/_internal/discovery.ts`: the decoded
//! `ace::network::DiscoveryViewV0` served by the discovery service (`/bcs`). Fetching lives in
//! [`super::client`] (feature `aptos`).

use std::collections::HashMap;

use crate::address::AccountAddress;
use crate::error::{AceError, Result};
use crate::group::Element;
use crate::network::State as NetworkState;
use crate::pke;
use crate::wire::{from_bytes_exact, Deserializer};

/// Public keys of one DKG/DKR session: the base point, per-node share pks, and (DKG only) the
/// result pk.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct SessionPks {
    pub base_point: Element,
    pub share_pks: Vec<Element>,
    pub result_pk: Option<Element>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NodeInfo {
    pub endpoint: Option<String>,
    pub enc_key: pke::EncryptionKey,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct DiscoveryViewV0 {
    pub state: NetworkState,
    pub nodes: HashMap<AccountAddress, NodeInfo>,
    pub sessions: HashMap<AccountAddress, SessionPks>,
}

impl DiscoveryViewV0 {
    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let state = NetworkState::deserialize(d)?;
        let n = d.vec_len()?;
        let mut nodes = HashMap::with_capacity(n);
        for _ in 0..n {
            let addr = AccountAddress::deserialize(d)?;
            let endpoint = match d.u8()? {
                0 => None,
                1 => Some(d.str()?),
                t => {
                    return Err(AceError::wire(format!(
                        "DiscoveryViewV0: node endpoint option tag must be 0 or 1, got {t}"
                    )))
                }
            };
            let enc_key = pke::EncryptionKey::deserialize(d)?;
            nodes.insert(addr, NodeInfo { endpoint, enc_key });
        }
        let n = d.vec_len()?;
        let mut sessions = HashMap::with_capacity(n);
        for _ in 0..n {
            let addr = AccountAddress::deserialize(d)?;
            let base_point = Element::deserialize(d)?;
            let result_pk = Element::deserialize(d)?;
            let m = d.vec_len()?;
            let mut share_pks = Vec::with_capacity(m);
            for _ in 0..m {
                share_pks.push(Element::deserialize(d)?);
            }
            sessions.insert(
                addr,
                SessionPks {
                    base_point,
                    share_pks,
                    result_pk: Some(result_pk),
                },
            );
        }
        Ok(Self {
            state,
            nodes,
            sessions,
        })
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        from_bytes_exact(bytes, Self::deserialize)
    }
}

/// Human-readable shape mirroring `DiscoveryReadableV0` / the discovery server's `/json`.
impl DiscoveryViewV0 {
    pub fn session(&self, addr: &AccountAddress) -> Option<&SessionPks> {
        self.sessions.get(addr)
    }
    pub fn node(&self, addr: &AccountAddress) -> Option<&NodeInfo> {
        self.nodes.get(addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::bls12381g2;
    use crate::wire::{Serializer, Wire};

    #[test]
    fn roundtrip_hand_built() {
        let g = Element::Bls12381G2(bls12381g2::generator());
        let st = NetworkState {
            epoch: 1,
            epoch_start_time_micros: 2,
            epoch_duration_micros: 3,
            cur_nodes: vec![AccountAddress::ONE],
            cur_threshold: 1,
            secrets: vec![],
            proposals: vec![],
            epoch_change_info: None,
        };
        let dk = pke::keygen(pke::DEFAULT_SCHEME).unwrap();
        let ek = pke::derive_encryption_key(&dk);
        let mut s = Serializer::new();
        st.serialize(&mut s);
        s.uleb128(1);
        AccountAddress::ONE.serialize(&mut s);
        s.u8(1).str("https://node");
        ek.serialize(&mut s);
        s.uleb128(1);
        AccountAddress::ONE.serialize(&mut s);
        g.serialize(&mut s);
        g.serialize(&mut s);
        s.uleb128(2);
        g.serialize(&mut s);
        g.serialize(&mut s);
        let bytes = s.into_bytes();
        let v = DiscoveryViewV0::from_bytes(&bytes).unwrap();
        assert_eq!(v.state, st);
        assert_eq!(
            v.node(&AccountAddress::ONE).unwrap().endpoint.as_deref(),
            Some("https://node")
        );
        assert_eq!(v.node(&AccountAddress::ONE).unwrap().enc_key, ek);
        let sess = v.session(&AccountAddress::ONE).unwrap();
        assert_eq!(sess.share_pks.len(), 2);
        assert_eq!(sess.result_pk, Some(g));
        assert!(DiscoveryViewV0::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let _ = ek.to_bytes();
    }
}
