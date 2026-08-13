# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""
Mirrors src/dkg/index.ts.

Distributedly generate a key-pair for OTP-HMAC Boneh-Franklin BLS12-381:
Each worker uses VSS-bls12381-fr to deal a sub-secret to the committee;
once t+1 VSS is done, the secret `s` should be finalized as the sum of the
t+1 sub-secrets. A base point is then publicly sampled (probably in the
contract), then `s`*base is the public key.
"""

from __future__ import annotations

from aptos_sdk.account_address import AccountAddress

from ace_sdk.bcs import Deserializer, deserialize_account_address
from ace_sdk.result import Result
from ace_sdk.vss._scheme_types import PublicPoint

# Distributedly generate a key-pair for OTP-HMAC Boneh-Franklin BLS12-381 (short public key).
SCHEME_0 = 0

# Distributedly generate a key-pair for OTP-HMAC Boneh-Franklin BLS12-381 (short identity key).
SCHEME_1 = 1

_STATE_DONE = 3


class Session:
    def __init__(
        self,
        caller: AccountAddress,
        workers: list[AccountAddress],
        threshold: int,
        base_point: PublicPoint,
        expected_usage: int,
        note: str,
        state: int,
        vss_sessions: list[AccountAddress],
        done_flags: list[bool],
        result_pk: PublicPoint | None,
        share_pks: list[PublicPoint],
    ) -> None:
        self.caller = caller
        self.workers = workers
        self.threshold = threshold
        self.base_point = base_point
        self.expected_usage = expected_usage
        self.note = note
        self.state = state
        self.vss_sessions = vss_sessions
        self.done_flags = done_flags
        self.result_pk = result_pk
        self.share_pks = share_pks

    def is_completed(self) -> bool:
        return self.state == _STATE_DONE

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["Session"]:
        def task(_extra: dict) -> "Session":
            caller = deserialize_account_address(deserializer)

            workers_len = deserializer.deserialize_uleb128_as_u32()
            workers: list[AccountAddress] = []
            for _ in range(workers_len):
                workers.append(deserialize_account_address(deserializer))

            threshold = deserializer.deserialize_u64()

            base_point = PublicPoint.deserialize(deserializer).unwrap_or_throw(
                ValueError("basePoint deserialize failed")
            )

            expected_usage = deserializer.deserialize_u64()
            note = deserializer.deserialize_str()

            state = deserializer.deserialize_u8()

            vss_len = deserializer.deserialize_uleb128_as_u32()
            vss_sessions: list[AccountAddress] = []
            for _ in range(vss_len):
                vss_sessions.append(deserialize_account_address(deserializer))

            done_flags_len = deserializer.deserialize_uleb128_as_u32()
            done_flags: list[bool] = []
            for _ in range(done_flags_len):
                done_flags.append(deserializer.deserialize_bool())

            # result_pk: Option<PublicPoint> -- encoded as vector<PublicPoint> of length 0 or 1
            result_pk_tag = deserializer.deserialize_u8()
            result_pk: PublicPoint | None = None
            if result_pk_tag == 1:
                result_pk = PublicPoint.deserialize(deserializer).unwrap_or_throw(
                    ValueError("resultPk deserialize failed")
                )
            elif result_pk_tag != 0:
                raise ValueError(f"resultPk option tag must be 0 or 1, got {result_pk_tag}")

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
                workers,
                threshold,
                base_point,
                expected_usage,
                note,
                state,
                vss_sessions,
                done_flags,
                result_pk,
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


class PrivateKey:
    def __init__(self, scheme: int, inner) -> None:
        self.scheme = scheme
        self.inner = inner


class PublicKey:
    def __init__(self, scheme: int, inner) -> None:
        self.scheme = scheme
        self.inner = inner
