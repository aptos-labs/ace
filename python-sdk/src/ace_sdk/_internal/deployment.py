# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Mirrors src/_internal/deployment.ts."""

from __future__ import annotations

from typing import Any

from aptos_sdk.account_address import AccountAddress


class AceDeployment:
    def __init__(
        self,
        api_endpoint: str,
        contract_addr: AccountAddress,
        api_key: str | None = None,
        client_config: dict[str, Any] | None = None,
        discovery_url: str | None = None,
    ) -> None:
        self.api_endpoint = api_endpoint
        self.contract_addr = contract_addr
        self.api_key = api_key
        self.client_config = client_config
        self.discovery_url = discovery_url

    def with_api_key(self, api_key: str | None = None) -> "AceDeployment":
        return AceDeployment(
            api_endpoint=self.api_endpoint,
            contract_addr=self.contract_addr,
            api_key=api_key,
            client_config=self.client_config,
            discovery_url=self.discovery_url,
        )

    def with_client_config(
        self, client_config: dict[str, Any] | None = None
    ) -> "AceDeployment":
        return AceDeployment(
            api_endpoint=self.api_endpoint,
            contract_addr=self.contract_addr,
            api_key=self.api_key,
            client_config=client_config,
            discovery_url=self.discovery_url,
        )
