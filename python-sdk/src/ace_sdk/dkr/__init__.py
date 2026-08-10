# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""
Mirrors src/dkr/index.ts.

Distributed key resharing: reshares an existing DKG-produced secret key
across a (possibly different) committee/threshold without ever
reconstructing the secret key in the clear.
"""

from __future__ import annotations

from aptos_sdk.account_address import AccountAddress

from ace_sdk.bcs import Deserializer, deserialize_account_address
from ace_sdk.group import Element, Scalar
from ace_sdk.result import Result
from ace_sdk.vss._scheme_types import PublicPoint

_STATE_DONE = 4


class Session:
    def __init__(
        self,
        caller: AccountAddress,
        public_base_element: PublicPoint,
        secretly_scaled_element: PublicPoint,
        original_session: AccountAddress,
        previous_session: AccountAddress,
        expected_usage: int,
        note: str,
        current_nodes: list[AccountAddress],
        current_threshold: int,
        new_nodes: list[AccountAddress],
        new_threshold: int,
        state_code: int,
        vss_sessions: list[AccountAddress],
        vss_contribution_flags: list[bool],
        share_pks: list[PublicPoint],
    ) -> None:
        self.caller = caller
        self.public_base_element = public_base_element
        self.secretly_scaled_element = secretly_scaled_element
        self.original_session = original_session
        self.previous_session = previous_session
        self.expected_usage = expected_usage
        self.note = note
        self.current_nodes = current_nodes
        self.current_threshold = current_threshold
        self.new_nodes = new_nodes
        self.new_threshold = new_threshold
        self.state_code = state_code
        self.vss_sessions = vss_sessions
        self.vss_contribution_flags = vss_contribution_flags
        self.share_pks = share_pks

    def is_completed(self) -> bool:
        return self.state_code == _STATE_DONE

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["Session"]:
        def task(_extra: dict) -> "Session":
            caller = deserialize_account_address(deserializer)

            public_base_element = PublicPoint.deserialize(deserializer).unwrap_or_throw(
                ValueError("publicBaseElement deserialize failed")
            )

            secretly_scaled_element = PublicPoint.deserialize(deserializer).unwrap_or_throw(
                ValueError("secretlyScaledElement deserialize failed")
            )

            original_session = deserialize_account_address(deserializer)
            previous_session = deserialize_account_address(deserializer)
            expected_usage = deserializer.deserialize_u64()
            note = deserializer.deserialize_str()

            current_nodes_len = deserializer.deserialize_uleb128_as_u32()
            current_nodes: list[AccountAddress] = []
            for _ in range(current_nodes_len):
                current_nodes.append(deserialize_account_address(deserializer))

            current_threshold = deserializer.deserialize_u64()

            new_nodes_len = deserializer.deserialize_uleb128_as_u32()
            new_nodes: list[AccountAddress] = []
            for _ in range(new_nodes_len):
                new_nodes.append(deserialize_account_address(deserializer))

            new_threshold = deserializer.deserialize_u64()

            state_code = deserializer.deserialize_u8()

            # src_share_pks: internal field for lazy VSS creation; read and discard.
            src_share_pks_len = deserializer.deserialize_uleb128_as_u32()
            for i in range(src_share_pks_len):
                PublicPoint.deserialize(deserializer).unwrap_or_throw(
                    ValueError(f"srcSharePks[{i}] deserialize failed")
                )

            vss_len = deserializer.deserialize_uleb128_as_u32()
            vss_sessions: list[AccountAddress] = []
            for _ in range(vss_len):
                vss_sessions.append(deserialize_account_address(deserializer))

            flags_len = deserializer.deserialize_uleb128_as_u32()
            vss_contribution_flags: list[bool] = []
            for _ in range(flags_len):
                vss_contribution_flags.append(deserializer.deserialize_bool())

            lagrange_len = deserializer.deserialize_uleb128_as_u32()
            for i in range(lagrange_len):
                Scalar.deserialize(deserializer).unwrap_or_throw(
                    ValueError(f"lagrangeCoeffsAtZero[{i}] deserialize failed")
                )

            share_pks_len = deserializer.deserialize_uleb128_as_u32()
            share_pks: list[PublicPoint] = []
            for i in range(share_pks_len):
                share_pks.append(
                    PublicPoint.deserialize(deserializer).unwrap_or_throw(
                        ValueError(f"sharePks[{i}] deserialize failed")
                    )
                )

            return Session(
                caller,
                public_base_element,
                secretly_scaled_element,
                original_session,
                previous_session,
                expected_usage,
                note,
                current_nodes,
                current_threshold,
                new_nodes,
                new_threshold,
                state_code,
                vss_sessions,
                vss_contribution_flags,
                share_pks,
            )

        return Result.capture(task)

    @staticmethod
    def from_bytes(data: bytes) -> Result["Session"]:
        def task(_extra: dict) -> "Session":
            deserializer = Deserializer(data)
            obj = Session.deserialize(deserializer).unwrap_or_throw(
                ValueError("deserialize failed")
            )
            if deserializer.remaining() != 0:
                raise ValueError("trailing bytes")
            return obj

        return Result.capture(task)
