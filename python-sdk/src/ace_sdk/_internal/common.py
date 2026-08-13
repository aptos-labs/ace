# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Shared ACE wire types and chain readers, mirroring ts-sdk/src/_internal/common.ts."""

from __future__ import annotations

import asyncio
import json
from dataclasses import dataclass
from typing import Any

from aptos_sdk.account_address import AccountAddress
from aptos_sdk.async_client import ClientConfig, RestClient

import ace_sdk.dkg as dkg
import ace_sdk.dkr as dkr
import ace_sdk.pke as pke
import ace_sdk.t_ibe as t_ibe
from ace_sdk._internal.deployment import AceDeployment
from ace_sdk._internal.discovery import DiscoveryChainReader, SessionPks
from ace_sdk.bcs import (
    Deserializer,
    Serializer,
    deserialize_account_address,
    serialize_account_address,
)
from ace_sdk.result import Result


def _hex_string_to_bytes(hex_str: str) -> bytes:
    h = hex_str.strip()
    if h.startswith("0x") or h.startswith("0X"):
        h = h[2:]
    return bytes.fromhex(h)


class AptosContractID:
    def __init__(self, chain_id: int, module_addr: AccountAddress, module_name: str) -> None:
        self.chain_id = chain_id
        self.module_addr = module_addr
        self.module_name = module_name

    @staticmethod
    def dummy() -> "AptosContractID":
        return AptosContractID(0, AccountAddress.from_str("0x1"), "module3")

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["AptosContractID"]:
        def task(_extra: dict) -> "AptosContractID":
            chain_id = deserializer.deserialize_u8()
            module_addr = deserialize_account_address(deserializer)
            module_name = deserializer.deserialize_str()
            return AptosContractID(chain_id, module_addr, module_name)

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u8(self.chain_id)
        serialize_account_address(serializer, self.module_addr)
        serializer.serialize_str(self.module_name)


class ContractID:
    SCHEME_APTOS = 0

    def __init__(self, scheme: int, inner: AptosContractID) -> None:
        self.scheme = scheme
        self.inner = inner

    @staticmethod
    def new_aptos(chain_id: int, module_addr: AccountAddress, module_name: str) -> "ContractID":
        return ContractID(ContractID.SCHEME_APTOS, AptosContractID(chain_id, module_addr, module_name))

    @staticmethod
    def dummy() -> "ContractID":
        return ContractID(ContractID.SCHEME_APTOS, AptosContractID.dummy())

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["ContractID"]:
        def task(_extra: dict) -> "ContractID":
            scheme = deserializer.deserialize_u8()
            if scheme == ContractID.SCHEME_APTOS:
                inner = AptosContractID.deserialize(deserializer).unwrap_or_throw(
                    ValueError("ACE.ContractID.deserialize failed in aptos case")
                )
                return ContractID(ContractID.SCHEME_APTOS, inner)
            raise ValueError("ACE.ContractID.deserialize failed with unknown scheme")

        return Result.capture(task)

    @staticmethod
    def from_bytes(data: bytes) -> Result["ContractID"]:
        def task(_extra: dict) -> "ContractID":
            deserializer = Deserializer(data)
            result = ContractID.deserialize(deserializer).unwrap_or_throw(
                ValueError("ACE.ContractID.from_bytes failed with deserialization error")
            )
            if deserializer.remaining() != 0:
                raise ValueError("ACE.ContractID.from_bytes failed with trailing bytes")
            return result

        return Result.capture(task)

    @staticmethod
    def from_hex(hex_str: str) -> Result["ContractID"]:
        def task(_extra: dict) -> "ContractID":
            return ContractID.from_bytes(_hex_string_to_bytes(hex_str)).unwrap_or_throw(
                ValueError("ACE.ContractID.from_hex failed with from_bytes error")
            )

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u8(self.scheme)
        if self.scheme == ContractID.SCHEME_APTOS:
            self.inner.serialize(serializer)
        else:
            raise ValueError(f"ACE.ContractID.serialize failed with unknown scheme {self.scheme}")

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()


class FullDecryptionDomain:
    def __init__(self, keypair_id: AccountAddress, contract_id: ContractID, label: bytes) -> None:
        self.keypair_id = keypair_id
        self.contract_id = contract_id
        self.label = label

    @staticmethod
    def dummy() -> "FullDecryptionDomain":
        return FullDecryptionDomain(
            keypair_id=AccountAddress.from_str("0x0"),
            contract_id=ContractID.dummy(),
            label=b"",
        )

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["FullDecryptionDomain"]:
        def task(_extra: dict) -> "FullDecryptionDomain":
            keypair_id = deserialize_account_address(deserializer)
            contract_id = ContractID.deserialize(deserializer).unwrap_or_throw(
                ValueError(
                    "ACE.FullDecryptionDomain.deserialize failed with ContractID deserialization error"
                )
            )
            label = deserializer.deserialize_bytes()
            return FullDecryptionDomain(keypair_id, contract_id, label)

        return Result.capture(task)

    @staticmethod
    def from_bytes(data: bytes) -> Result["FullDecryptionDomain"]:
        def task(_extra: dict) -> "FullDecryptionDomain":
            deserializer = Deserializer(data)
            result = FullDecryptionDomain.deserialize(deserializer).unwrap_or_throw(
                ValueError(
                    "ACE.FullDecryptionDomain.from_bytes failed with deserialization error"
                )
            )
            if deserializer.remaining() != 0:
                raise ValueError("ACE.FullDecryptionDomain.from_bytes failed with trailing bytes")
            return result

        return Result.capture(task)

    @staticmethod
    def from_hex(hex_str: str) -> Result["FullDecryptionDomain"]:
        def task(_extra: dict) -> "FullDecryptionDomain":
            return FullDecryptionDomain.from_bytes(_hex_string_to_bytes(hex_str)).unwrap_or_throw(
                ValueError("ACE.FullDecryptionDomain.from_hex failed with from_bytes error")
            )

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        serialize_account_address(serializer, self.keypair_id)
        self.contract_id.serialize(serializer)
        serializer.serialize_bytes(self.label)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()


@dataclass(frozen=True)
class _FullnodeChainReader:
    ace_deployment: AceDeployment

    async def _view_async(self, function: str, arguments: list[str]) -> list[Any]:
        client_config = self.ace_deployment.client_config or {}
        client = RestClient(
            self.ace_deployment.api_endpoint,
            ClientConfig(
                api_key=self.ace_deployment.api_key,
                http2=bool(client_config.get("http2", True)),
            ),
        )
        try:
            content = await client.view(
                f"{_addr_key(self.ace_deployment.contract_addr)}::{function}",
                [],
                arguments,
            )
            return json.loads(content)
        finally:
            await client.close()

    def _view(self, function: str, arguments: list[str]) -> list[Any]:
        return asyncio.run(self._view_async(function, arguments))

    def network_state(self):
        from ace_sdk.network import State

        state_hex = self._view("network::state_view_v0_bcs", [])[0]
        return State.from_bytes(_hex_string_to_bytes(state_hex)).unwrap_or_throw(
            ValueError("ACE: parse network state")
        )

    def session(self, addr: str, is_dkg: bool = True) -> SessionPks:
        hex_str = self._view("dkg::get_session_bcs" if is_dkg else "dkr::get_session_bcs", [addr])[0]
        data = _hex_string_to_bytes(hex_str)
        if is_dkg:
            session = dkg.Session.from_bytes(data).unwrap_or_throw(ValueError("ACE: parse DKG session"))
            return SessionPks(
                base_point=session.base_point,
                share_pks=session.share_pks,
                result_pk=session.result_pk,
            )
        session = dkr.Session.from_bytes(data).unwrap_or_throw(ValueError("ACE: parse DKR session"))
        return SessionPks(
            base_point=session.public_base_element,
            share_pks=session.share_pks,
            result_pk=None,
        )

    def worker_endpoint(self, addr: str) -> str:
        return str(self._view("worker_config::get_endpoint", [addr])[0])

    def worker_enc_key(self, addr: str) -> pke.EncryptionKey:
        ek_hex = self._view("worker_config::get_pke_enc_key_bcs", [addr])[0]
        return pke.EncryptionKey.from_bytes(_hex_string_to_bytes(ek_hex)).unwrap_or_throw(
            ValueError(f"ACE: parse pke enc key for {addr}")
        )


def _addr_key(addr: str | AccountAddress) -> str:
    if isinstance(addr, str):
        account_addr = AccountAddress.from_str(addr)
    else:
        account_addr = addr
    return "0x" + account_addr.address.hex()


def get_chain_reader(ace_deployment: AceDeployment):
    if not ace_deployment.api_key and ace_deployment.discovery_url:
        return DiscoveryChainReader(ace_deployment.discovery_url)
    return _FullnodeChainReader(ace_deployment)


def fetch_tibe_public_key(
    ace_deployment: AceDeployment,
    keypair_id: AccountAddress,
    tibe_scheme: int | None = None,
    context: str = "fetch_tibe_public_key",
) -> Result[t_ibe.MasterPublicKey]:
    def task(_extra: dict) -> t_ibe.MasterPublicKey:
        scheme = (
            t_ibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
            if tibe_scheme is None
            else tibe_scheme
        )
        session = get_chain_reader(ace_deployment).session(_addr_key(keypair_id), True)
        if session.result_pk is None:
            raise ValueError(f"{context}: DKG session has no resultPk")
        return t_ibe.MasterPublicKey.from_group_elements(
            scheme, session.base_point, session.result_pk
        ).unwrap_or_throw(ValueError(f"{context}: build MasterPublicKey"))

    return Result.capture(task)


__all__ = [
    "AptosContractID",
    "ContractID",
    "FullDecryptionDomain",
    "fetch_tibe_public_key",
    "get_chain_reader",
]
