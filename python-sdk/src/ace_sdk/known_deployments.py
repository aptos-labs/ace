# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Known ACE deployments, mirroring ts-sdk/src/known-deployments.ts."""

from __future__ import annotations

from dataclasses import dataclass

from aptos_sdk.account_address import AccountAddress

from ace_sdk._internal.deployment import AceDeployment


@dataclass(frozen=True)
class KnownDeployment:
    chain_id: int
    ace_deployment: AceDeployment
    ibe_keypair_id: AccountAddress
    vrf_keypair_id: AccountAddress

    def with_api_key(self, api_key: str | None = None) -> "KnownDeployment":
        return KnownDeployment(
            chain_id=self.chain_id,
            ace_deployment=self.ace_deployment.with_api_key(api_key),
            ibe_keypair_id=self.ibe_keypair_id,
            vrf_keypair_id=self.vrf_keypair_id,
        )

    def with_client_config(self, client_config: dict | None = None) -> "KnownDeployment":
        return KnownDeployment(
            chain_id=self.chain_id,
            ace_deployment=self.ace_deployment.with_client_config(client_config),
            ibe_keypair_id=self.ibe_keypair_id,
            vrf_keypair_id=self.vrf_keypair_id,
        )


def _addr(value: str) -> AccountAddress:
    return AccountAddress.from_str(value)


known_deployments: dict[str, KnownDeployment] = {
    "preview20260610": KnownDeployment(
        chain_id=2,
        ace_deployment=AceDeployment(
            api_endpoint="https://api.testnet.aptoslabs.com/v1",
            contract_addr=_addr(
                "0x19ca96aabae3230c67f35b64b004c0f7480f51d81648f416a39c960de119b251"
            ),
        ),
        ibe_keypair_id=_addr(
            "0xbb83c1eb79580d9e23639fa28373047f64d2c8bd3526590d2d886cf91fb5a307"
        ),
        vrf_keypair_id=_addr(
            "0x3ca79722e34031f87ef5be65890d2c12d742390a641d9b1f0333155eda67dd9d"
        ),
    ),
    "shelby-beta-usce1": KnownDeployment(
        chain_id=125,
        ace_deployment=AceDeployment(
            api_endpoint="https://api.beta.shelby.xyz/v1",
            contract_addr=_addr(
                "0x086f9a291d3d28140413505f6224d10e07cb6d6d08ab5933f62ff1b685830408"
            ),
            discovery_url="https://ace.shelby-beta.aptoslabs.com/discovery",
        ),
        ibe_keypair_id=_addr(
            "0x50ca2eb86412416256522777770b9846ced2b0185db1d301f233d5f47215f4c3"
        ),
        vrf_keypair_id=_addr(
            "0xf47b51b8c648a3dd53a1c0ec5d38e2b861f0b6d4c3181f0b84b0d535e274a98d"
        ),
    ),
    "shelbynet-20260731": KnownDeployment(
        chain_id=118,
        ace_deployment=AceDeployment(
            api_endpoint="https://api.shelbynet.shelby.xyz/v1",
            contract_addr=_addr(
                "0x2a800d06b231476e045e874b5319409f80aa4449d7cabcdc68d2e0b5a66ee43d"
            ),
            discovery_url="https://ace-discovery-646682240579.us-central1.run.app",
        ),
        ibe_keypair_id=_addr(
            "0xa36e6db16b015c6c2c9a376afe3075b11031ee0df393c226e7d599f615759a17"
        ),
        vrf_keypair_id=_addr(
            "0xa36e6db16b015c6c2c9a376afe3075b11031ee0df393c226e7d599f615759a17"
        ),
    ),
}

preview20260610 = known_deployments["preview20260610"]
shelby_beta_usce1 = known_deployments["shelby-beta-usce1"]
shelbynet_20260731 = known_deployments["shelbynet-20260731"]

__all__ = [
    "KnownDeployment",
    "known_deployments",
    "preview20260610",
    "shelby_beta_usce1",
    "shelbynet_20260731",
]
