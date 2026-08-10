# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Network state view decoders, mirroring ts-sdk/src/network/index.ts."""

from __future__ import annotations

from dataclasses import dataclass

from aptos_sdk.account_address import AccountAddress

from ace_sdk.bcs import Deserializer, deserialize_account_address
from ace_sdk.result import Result

PRIMITIVE_BFIBE_BLS12381_SHORTPK_OTP_HMAC = 0
PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEAD = 1
PRIMITIVE_BLS12381_THRESHOLD_VRF = 2

USAGE_BFIBE_BLS12381_SHORTPK_OTP_HMAC = 1
USAGE_BFIBE_BLS12381_SHORTSIG_AEAD = 2
USAGE_BLS12381_THRESHOLD_VRF = 4

_SCHEME_NAMES = {
    0: "BLS12-381 G1 / BFIBE-shortpk-otp-hmac (legacy)",
    1: "BLS12-381 G2 / BFIBE-shortsig-aead (default)",
}


def usage_for_primitive(primitive: int) -> int:
    if primitive == PRIMITIVE_BFIBE_BLS12381_SHORTPK_OTP_HMAC:
        return USAGE_BFIBE_BLS12381_SHORTPK_OTP_HMAC
    if primitive == PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEAD:
        return USAGE_BFIBE_BLS12381_SHORTSIG_AEAD
    if primitive == PRIMITIVE_BLS12381_THRESHOLD_VRF:
        return USAGE_BLS12381_THRESHOLD_VRF
    raise ValueError(f"unsupported ACE primitive {primitive}")


def scheme_name(scheme: int) -> str:
    return _SCHEME_NAMES.get(scheme, f"unknown scheme {scheme}")


@dataclass(frozen=True)
class SecretInfo:
    current_session: AccountAddress
    keypair_id: AccountAddress
    scheme: int
    expected_usage: int
    note: str

    def scheme_name(self) -> str:
        return scheme_name(self.scheme)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "SecretInfo":
        current_session = deserialize_account_address(deserializer)
        keypair_id = deserialize_account_address(deserializer)
        scheme = deserializer.deserialize_u8()
        expected_usage = deserializer.deserialize_u64()
        note = deserializer.deserialize_str()
        return SecretInfo(current_session, keypair_id, scheme, expected_usage, note)


@dataclass(frozen=True)
class SecretRequest:
    expected_usage: int
    note: str = ""

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "SecretRequest":
        expected_usage = deserializer.deserialize_u64()
        note = deserializer.deserialize_str()
        return SecretRequest(expected_usage, note)


@dataclass(frozen=True)
class ProposedEpochConfig:
    nodes: list[AccountAddress]
    threshold: int
    epoch_duration_micros: int
    secrets_to_retain: list[AccountAddress]
    new_secrets: list[SecretRequest]
    description: str
    target_epoch: int

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "ProposedEpochConfig":
        nodes_len = deserializer.deserialize_uleb128_as_u32()
        nodes = [deserialize_account_address(deserializer) for _ in range(nodes_len)]
        threshold = deserializer.deserialize_u64()
        epoch_duration_micros = deserializer.deserialize_u64()

        retain_len = deserializer.deserialize_uleb128_as_u32()
        secrets_to_retain = [
            deserialize_account_address(deserializer) for _ in range(retain_len)
        ]

        new_secrets_len = deserializer.deserialize_uleb128_as_u32()
        new_secrets = [SecretRequest.deserialize(deserializer) for _ in range(new_secrets_len)]

        description = deserializer.deserialize_str()
        target_epoch = deserializer.deserialize_u64()

        return ProposedEpochConfig(
            nodes=nodes,
            threshold=threshold,
            epoch_duration_micros=epoch_duration_micros,
            secrets_to_retain=secrets_to_retain,
            new_secrets=new_secrets,
            description=description,
            target_epoch=target_epoch,
        )


@dataclass(frozen=True)
class ProposalView:
    proposal: ProposedEpochConfig
    voting_session: AccountAddress
    votes: list[bool]
    voting_passed: bool

    def vote_count(self) -> int:
        return sum(1 for vote in self.votes if vote)

    def has_voted(self, node_addr: str, cur_nodes: list[AccountAddress]) -> bool:
        try:
            idx = next(i for i, node in enumerate(cur_nodes) if str(node) == node_addr)
        except StopIteration:
            return False
        return self.votes[idx] is True

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "ProposalView":
        proposal = ProposedEpochConfig.deserialize(deserializer)
        voting_session = deserialize_account_address(deserializer)

        votes_len = deserializer.deserialize_uleb128_as_u32()
        votes = [deserializer.deserialize_bool() for _ in range(votes_len)]
        voting_passed = deserializer.deserialize_bool()

        return ProposalView(proposal, voting_session, votes, voting_passed)


@dataclass(frozen=True)
class EpochChangeView:
    triggering_proposal_idx: int | None
    session_addr: AccountAddress
    nxt_nodes: list[AccountAddress]
    nxt_threshold: int

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "EpochChangeView":
        idx_tag = deserializer.deserialize_u8()
        if idx_tag == 0:
            triggering_proposal_idx = None
        elif idx_tag == 1:
            triggering_proposal_idx = deserializer.deserialize_u64()
        else:
            raise ValueError(f"triggering_proposal_idx option tag must be 0 or 1, got {idx_tag}")

        session_addr = deserialize_account_address(deserializer)

        nodes_len = deserializer.deserialize_uleb128_as_u32()
        nxt_nodes = [deserialize_account_address(deserializer) for _ in range(nodes_len)]
        nxt_threshold = deserializer.deserialize_u64()

        return EpochChangeView(triggering_proposal_idx, session_addr, nxt_nodes, nxt_threshold)


@dataclass(frozen=True)
class State:
    epoch: int
    epoch_start_time_micros: int
    epoch_duration_micros: int
    cur_nodes: list[AccountAddress]
    cur_threshold: int
    secrets: list[SecretInfo]
    proposals: list[ProposalView | None]
    epoch_change_info: EpochChangeView | None

    def is_epoch_changing(self) -> bool:
        return self.epoch_change_info is not None

    def active_proposals(self) -> list[ProposalView]:
        return [proposal for proposal in self.proposals if proposal is not None]

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["State"]:
        def task(_extra: dict) -> "State":
            epoch = deserializer.deserialize_u64()
            epoch_start_time_micros = deserializer.deserialize_u64()
            epoch_duration_micros = deserializer.deserialize_u64()

            nodes_len = deserializer.deserialize_uleb128_as_u32()
            cur_nodes = [deserialize_account_address(deserializer) for _ in range(nodes_len)]

            cur_threshold = deserializer.deserialize_u64()

            secrets_len = deserializer.deserialize_uleb128_as_u32()
            secrets = [SecretInfo.deserialize(deserializer) for _ in range(secrets_len)]

            proposals_len = deserializer.deserialize_uleb128_as_u32()
            proposals: list[ProposalView | None] = []
            for i in range(proposals_len):
                tag = deserializer.deserialize_u8()
                if tag == 0:
                    proposals.append(None)
                elif tag == 1:
                    proposals.append(ProposalView.deserialize(deserializer))
                else:
                    raise ValueError(f"proposals[{i}] option tag must be 0 or 1, got {tag}")

            ec_tag = deserializer.deserialize_u8()
            if ec_tag == 0:
                epoch_change_info = None
            elif ec_tag == 1:
                epoch_change_info = EpochChangeView.deserialize(deserializer)
            else:
                raise ValueError(f"epoch_change_info option tag must be 0 or 1, got {ec_tag}")

            return State(
                epoch=epoch,
                epoch_start_time_micros=epoch_start_time_micros,
                epoch_duration_micros=epoch_duration_micros,
                cur_nodes=cur_nodes,
                cur_threshold=cur_threshold,
                secrets=secrets,
                proposals=proposals,
                epoch_change_info=epoch_change_info,
            )

        return Result.capture(task)

    @staticmethod
    def from_bytes(data: bytes) -> Result["State"]:
        def task(_extra: dict) -> "State":
            deserializer = Deserializer(data)
            state = State.deserialize(deserializer).unwrap_or_throw(
                ValueError("State.from_bytes failed with deserialization error")
            )
            if deserializer.remaining() != 0:
                raise ValueError("State.from_bytes failed with trailing bytes")
            return state

        return Result.capture(task)


__all__ = [
    "EpochChangeView",
    "PRIMITIVE_BFIBE_BLS12381_SHORTPK_OTP_HMAC",
    "PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEAD",
    "PRIMITIVE_BLS12381_THRESHOLD_VRF",
    "ProposalView",
    "ProposedEpochConfig",
    "SecretInfo",
    "SecretRequest",
    "State",
    "USAGE_BFIBE_BLS12381_SHORTPK_OTP_HMAC",
    "USAGE_BFIBE_BLS12381_SHORTSIG_AEAD",
    "USAGE_BLS12381_THRESHOLD_VRF",
    "scheme_name",
    "usage_for_primitive",
]
