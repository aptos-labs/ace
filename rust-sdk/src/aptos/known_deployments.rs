// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Mirrors `ts-sdk/src/known-deployments.ts`. Keep the three SDKs in sync when editing.

use super::deployment::AceDeployment;
use crate::address::AccountAddress;

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct KnownDeployment {
    pub id: &'static str,
    pub chain_id: u8,
    pub ace_deployment: AceDeployment,
    pub ibe_keypair_id: AccountAddress,
    pub vrf_keypair_id: AccountAddress,
    /// Keypair id for the streaming + seekable BFIBE-shortsig-aead-stream secret (primitive 3),
    /// where the deployment has generated one. `None` for older deployments that predate it.
    pub stream_ibe_keypair_id: Option<AccountAddress>,
}

impl KnownDeployment {
    pub fn with_api_key(mut self, api_key: Option<String>) -> Self {
        self.ace_deployment.api_key = api_key;
        self
    }
}

fn addr(s: &str) -> AccountAddress {
    AccountAddress::from_str_relaxed(s).expect("static address")
}

#[allow(clippy::too_many_arguments)]
fn dep(
    id: &'static str,
    chain_id: u8,
    api: &str,
    contract: &str,
    discovery: Option<&str>,
    ibe: &str,
    vrf: &str,
    stream_ibe: Option<&str>,
) -> KnownDeployment {
    KnownDeployment {
        id,
        chain_id,
        ace_deployment: AceDeployment::new(api, addr(contract))
            .with_discovery_url(discovery.map(str::to_string)),
        ibe_keypair_id: addr(ibe),
        vrf_keypair_id: addr(vrf),
        stream_ibe_keypair_id: stream_ibe.map(addr),
    }
}

pub const KNOWN_DEPLOYMENT_IDS: &[&str] =
    &["preview20260610", "shelby-beta-usce1", "shelbynet-20260923"];

/// Look up a known deployment by id (same ids as `knownDeployments` in TS / Python).
pub fn known_deployment(id: &str) -> Option<KnownDeployment> {
    Some(match id {
        "preview20260610" => dep(
            "preview20260610",
            2,
            "https://api.testnet.aptoslabs.com/v1",
            "0x19ca96aabae3230c67f35b64b004c0f7480f51d81648f416a39c960de119b251",
            None,
            "0xbb83c1eb79580d9e23639fa28373047f64d2c8bd3526590d2d886cf91fb5a307",
            "0x3ca79722e34031f87ef5be65890d2c12d742390a641d9b1f0333155eda67dd9d",
            None,
        ),
        "shelby-beta-usce1" => dep(
            "shelby-beta-usce1",
            125,
            "https://api.beta.shelby.xyz/v1",
            "0x086f9a291d3d28140413505f6224d10e07cb6d6d08ab5933f62ff1b685830408",
            Some("https://ace.shelby-beta.aptoslabs.com/discovery"),
            "0x50ca2eb86412416256522777770b9846ced2b0185db1d301f233d5f47215f4c3",
            "0xf47b51b8c648a3dd53a1c0ec5d38e2b861f0b6d4c3181f0b84b0d535e274a98d",
            None,
        ),
        // Redeployed 2026-09-23 after the shelbynet chain wipe (chain_id 118 -> 119, see the
        // "shelbynet-20260731" removal).
        "shelbynet-20260923" => dep(
            "shelbynet-20260923",
            119,
            "https://api.shelbynet.shelby.xyz/v1",
            "0x63b64cbbf60950e39dea70a88d6d84ef3457efd7430337a5d71864a790fbdeba",
            Some("https://ace-discovery-646682240579.us-central1.run.app"),
            "0xba96d96b639ebd8e8b651b9ea001da5b8cb07c85a2c4bd088b753d3f8d4ffdfe",
            "0xd71f85f53eed44d1d8ea4ac978fc0d2c4c326208097692964d3cdd48d1367114",
            Some("0x4855d5c9e2cf26365e2d3bb75bebe71cadb388adfdfe7ecd0e4cc96de5980be2"),
        ),
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn all_ids_resolve() {
        for id in super::KNOWN_DEPLOYMENT_IDS {
            let d = super::known_deployment(id).unwrap();
            assert_eq!(d.id, *id);
            assert!(d.ace_deployment.api_endpoint.ends_with("/v1"));
        }
        assert!(super::known_deployment("nope").is_none());
    }
}
