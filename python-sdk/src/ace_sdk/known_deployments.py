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
    # Keypair id for the streaming + seekable BFIBE-shortsig-aead-stream secret (primitive 3),
    # where the deployment has generated one. None for older deployments that predate it.
    stream_ibe_keypair_id: AccountAddress | None = None

    def with_api_key(self, api_key: str | None = None) -> "KnownDeployment":
        return KnownDeployment(
            chain_id=self.chain_id,
            ace_deployment=self.ace_deployment.with_api_key(api_key),
            ibe_keypair_id=self.ibe_keypair_id,
            vrf_keypair_id=self.vrf_keypair_id,
            stream_ibe_keypair_id=self.stream_ibe_keypair_id,
        )

    def with_client_config(self, client_config: dict | None = None) -> "KnownDeployment":
        return KnownDeployment(
            chain_id=self.chain_id,
            ace_deployment=self.ace_deployment.with_client_config(client_config),
            ibe_keypair_id=self.ibe_keypair_id,
            vrf_keypair_id=self.vrf_keypair_id,
            stream_ibe_keypair_id=self.stream_ibe_keypair_id,
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
    # Redeployed 2026-09-23 after the shelbynet chain wipe (chain_id 118 -> 119, replacing the
    # removed "shelbynet-20260731"). No discovery service is deployed for this one yet.
    "shelbynet-20260923": KnownDeployment(
        chain_id=119,
        ace_deployment=AceDeployment(
            api_endpoint="https://api.shelbynet.shelby.xyz/v1",
            contract_addr=_addr(
                "0x63b64cbbf60950e39dea70a88d6d84ef3457efd7430337a5d71864a790fbdeba"
            ),
        ),
        ibe_keypair_id=_addr(
            "0xba96d96b639ebd8e8b651b9ea001da5b8cb07c85a2c4bd088b753d3f8d4ffdfe"
        ),
        vrf_keypair_id=_addr(
            "0xd71f85f53eed44d1d8ea4ac978fc0d2c4c326208097692964d3cdd48d1367114"
        ),
        stream_ibe_keypair_id=_addr(
            "0x4855d5c9e2cf26365e2d3bb75bebe71cadb388adfdfe7ecd0e4cc96de5980be2"
        ),
    ),
}

preview20260610 = known_deployments["preview20260610"]
shelby_beta_usce1 = known_deployments["shelby-beta-usce1"]
shelbynet_20260923 = known_deployments["shelbynet-20260923"]

__all__ = [
    "KnownDeployment",
    "known_deployments",
    "preview20260610",
    "shelby_beta_usce1",
    "shelbynet_20260923",
]
