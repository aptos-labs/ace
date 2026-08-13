# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


class BytesResponse:
    status = 200

    def __init__(self, body: bytes) -> None:
        self._body = body

    def __enter__(self) -> "BytesResponse":
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> bool:
        return False

    def read(self) -> bytes:
        return self._body


@dataclass(frozen=True)
class SingleNodeReader:
    node: Any
    node_enc_key: Any
    session_pks: Any
    network_state_value: Any | None = None

    def network_state(self) -> Any:
        if self.network_state_value is None:
            raise AssertionError("network_state was not configured")
        return self.network_state_value

    def session(self, addr: str, is_dkg: bool = True) -> Any:
        assert addr == "0x" + self.session_pks.keypair_id.address.hex()
        assert is_dkg is True
        return self.session_pks.value

    def worker_endpoint(self, addr: str) -> str:
        assert addr == "0x" + self.node.address.hex()
        return "https://node.example/"

    def worker_enc_key(self, addr: str) -> Any:
        assert addr == "0x" + self.node.address.hex()
        return self.node_enc_key


@dataclass(frozen=True)
class SessionPksFixture:
    keypair_id: Any
    value: Any


@dataclass(frozen=True)
class AdminRecoveryReader:
    nodes: list[Any]
    node_enc_key: Any
    network_state_value: Any

    def network_state(self) -> Any:
        return self.network_state_value

    def worker_endpoint(self, addr: str) -> str:
        return f"https://node-{addr[-1]}.example/"

    def worker_enc_key(self, addr: str) -> Any:
        del addr
        return self.node_enc_key
