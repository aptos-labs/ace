# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Discovery snapshot decoder, mirroring ts-sdk/src/_internal/discovery.ts."""

from __future__ import annotations

import json
from dataclasses import dataclass
from urllib.request import urlopen

from aptos_sdk.account_address import AccountAddress

from ace_sdk import pke
from ace_sdk.bcs import Deserializer, deserialize_account_address
from ace_sdk.group import Element
from ace_sdk.network import State


@dataclass(frozen=True)
class SessionPks:
    base_point: Element
    share_pks: list[Element]
    result_pk: Element | None = None


def _addr_key(addr: str | AccountAddress) -> str:
    if isinstance(addr, str):
        account_addr = AccountAddress.from_str(addr)
    else:
        account_addr = addr
    return "0x" + account_addr.address.hex()


class DiscoveryViewV0:
    def __init__(
        self,
        state: State,
        nodes: dict[str, dict[str, str | pke.EncryptionKey]],
        sessions: dict[str, SessionPks],
    ) -> None:
        self.state = state
        self.nodes = nodes
        self.sessions = sessions

    def to_readable(self) -> dict:
        nodes = []
        for addr in self.state.cur_nodes:
            key = _addr_key(addr)
            node = self.nodes.get(key)
            nodes.append(
                {
                    "address": key,
                    "endpoint": node.get("endpoint") if node else None,
                    "pkeEncKey": node["enc_key"].to_hex() if node else None,
                }
            )

        keypairs = []
        for secret in self.state.secrets:
            keypair_id = _addr_key(secret.keypair_id)
            current_session = _addr_key(secret.current_session)
            cur = self.sessions.get(current_session)
            origin = self.sessions.get(keypair_id)
            keypairs.append(
                {
                    "keypairId": keypair_id,
                    "currentSession": current_session,
                    "scheme": secret.scheme,
                    "note": secret.note,
                    "masterPublicKey": origin.result_pk.to_hex()
                    if origin and origin.result_pk
                    else None,
                    "basePoint": cur.base_point.to_hex() if cur else None,
                    "sharePks": [share_pk.to_hex() for share_pk in cur.share_pks]
                    if cur
                    else [],
                }
            )

        return {
            "epoch": self.state.epoch,
            "epochChanging": self.state.is_epoch_changing(),
            "threshold": self.state.cur_threshold,
            "epochStartTimeMicros": str(self.state.epoch_start_time_micros),
            "epochDurationMicros": str(self.state.epoch_duration_micros),
            "nodes": nodes,
            "keypairs": keypairs,
        }

    @staticmethod
    def from_bytes(data: bytes) -> "DiscoveryViewV0":
        deserializer = Deserializer(data)
        state = State.deserialize(deserializer).unwrap_or_throw(
            ValueError("DiscoveryViewV0: parse state_view")
        )

        nodes: dict[str, dict[str, str | pke.EncryptionKey]] = {}
        nodes_len = deserializer.deserialize_uleb128_as_u32()
        for _ in range(nodes_len):
            addr = _addr_key(deserialize_account_address(deserializer))
            tag = deserializer.deserialize_u8()
            endpoint: str | None = None
            if tag == 1:
                endpoint = deserializer.deserialize_str()
            elif tag != 0:
                raise ValueError(
                    f"DiscoveryViewV0: node endpoint option tag must be 0 or 1, got {tag}"
                )
            enc_key = pke.EncryptionKey.deserialize(deserializer).unwrap_or_throw(
                ValueError(f"DiscoveryViewV0: parse enc_key for {addr}")
            )
            node: dict[str, str | pke.EncryptionKey] = {"enc_key": enc_key}
            if endpoint is not None:
                node["endpoint"] = endpoint
            nodes[addr] = node

        sessions: dict[str, SessionPks] = {}
        sessions_len = deserializer.deserialize_uleb128_as_u32()
        for _ in range(sessions_len):
            addr = _addr_key(deserialize_account_address(deserializer))
            base_point = Element.deserialize(deserializer).unwrap_or_throw(
                ValueError(f"DiscoveryViewV0: parse base_point for {addr}")
            )
            result_pk = Element.deserialize(deserializer).unwrap_or_throw(
                ValueError(f"DiscoveryViewV0: parse result_pk for {addr}")
            )
            share_pks_len = deserializer.deserialize_uleb128_as_u32()
            share_pks = []
            for j in range(share_pks_len):
                share_pks.append(
                    Element.deserialize(deserializer).unwrap_or_throw(
                        ValueError(f"DiscoveryViewV0: parse share_pks[{j}] for {addr}")
                    )
                )
            sessions[addr] = SessionPks(base_point=base_point, share_pks=share_pks, result_pk=result_pk)

        if deserializer.remaining() != 0:
            raise ValueError("DiscoveryViewV0: trailing bytes")
        return DiscoveryViewV0(state, nodes, sessions)


def _hex_to_bytes(hex_str: str) -> bytes:
    h = hex_str.strip()
    if h.startswith("0x") or h.startswith("0X"):
        h = h[2:]
    return bytes.fromhex(h)


def fetch_discovery_view(discovery_url: str) -> DiscoveryViewV0:
    url = discovery_url.rstrip("/") + "/bcs"
    with urlopen(url) as response:
        status = getattr(response, "status", 200)
        if status < 200 or status >= 300:
            raise RuntimeError(f"ACE discovery: GET {url} -> HTTP {status}")
        body = response.read().decode("utf-8").strip()
    if body.startswith("{"):
        obj = json.loads(body)
        body = obj.get("discoveryViewV0Bcs")
        if not body:
            raise ValueError("ACE discovery: response JSON missing 'discoveryViewV0Bcs'")
    return DiscoveryViewV0.from_bytes(_hex_to_bytes(body))


class DiscoveryChainReader:
    def __init__(self, discovery_url: str) -> None:
        self.discovery_url = discovery_url
        self._snapshot: DiscoveryViewV0 | None = None

    def _view0(self) -> DiscoveryViewV0:
        if self._snapshot is None:
            self._snapshot = fetch_discovery_view(self.discovery_url)
        return self._snapshot

    def network_state(self) -> State:
        return self._view0().state

    def session(self, addr: str, is_dkg: bool | None = None) -> SessionPks:
        del is_dkg
        key = _addr_key(addr)
        session = self._view0().sessions.get(key)
        if session is None:
            raise ValueError(f"ACE discovery: session {key} not in snapshot")
        return session

    def worker_endpoint(self, addr: str) -> str:
        key = _addr_key(addr)
        node = self._view0().nodes.get(key)
        if node is None:
            raise ValueError(f"ACE discovery: node {key} not in snapshot")
        endpoint = node.get("endpoint")
        if endpoint is None:
            raise ValueError(f"ACE discovery: node {key} has no registered endpoint")
        return endpoint

    def worker_enc_key(self, addr: str) -> pke.EncryptionKey:
        key = _addr_key(addr)
        node = self._view0().nodes.get(key)
        if node is None:
            raise ValueError(f"ACE discovery: node {key} not in snapshot")
        return node["enc_key"]  # type: ignore[return-value]


__all__ = [
    "DiscoveryChainReader",
    "DiscoveryViewV0",
    "SessionPks",
    "fetch_discovery_view",
]
