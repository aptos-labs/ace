# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""
Scheme-dispatching VSS wrapper types (SecretShare, DealerState,
DealerContribution0/1, Session). Mirrors src/vss/index.ts.
"""

from __future__ import annotations

from ace_sdk import pke
from ace_sdk.bcs import (
    Deserializer,
    Serializer,
    deserialize_account_address,
    serialize_account_address,
)
from ace_sdk.group import SCHEME_BLS12381G1, SCHEME_BLS12381G2, Element, Scalar
from ace_sdk.group import bls12381g1 as bls12381_g1
from ace_sdk.group import bls12381g2 as bls12381_g2
from ace_sdk.pedersen_polynomial_commitment import (
    Commitment as PcsCommitment,
)
from ace_sdk.pedersen_polynomial_commitment import (
    DegreeCheckState as PcsDegreeCheckState,
)
from ace_sdk.pedersen_polynomial_commitment import (
    Opening as PcsOpening,
)
from ace_sdk.pedersen_polynomial_commitment import (
    PublicParams as PcsPublicParams,
)
from ace_sdk.result import Result
from ace_sdk.sigma_dlog_linear import Proof as SigmaDlogLinearProof

# Re-exports mirroring `export { Scalar as PrivateScalar, ... } from "../group"`.
PrivateScalar = Scalar
PublicPoint = Element

__all__ = [
    "PrivateScalar",
    "PublicPoint",
    "SCHEME_BLS12381G1",
    "SCHEME_BLS12381G2",
    "PcsCommitment",
    "PcsDegreeCheckState",
    "PcsOpening",
    "PcsPublicParams",
    "SigmaDlogLinearProof",
    "sample",
    "sample_bls12381_g1",
    "sample_bls12381_g2",
    "reconstruct",
    "SecretShare",
    "PrivateShareMessage",
    "DealerState",
    "DealerContribution0",
    "DealerContribution1",
    "Session",
]


# == module-level functions ===================================================


def sample(scheme: int) -> Scalar:
    if scheme == SCHEME_BLS12381G1:
        secret = bls12381_g1.sample()
        return Scalar(SCHEME_BLS12381G1, secret)
    if scheme == SCHEME_BLS12381G2:
        secret = bls12381_g2.sample()
        return Scalar(SCHEME_BLS12381G2, secret)
    raise ValueError(f"sample: unsupported scheme {scheme}")


def sample_bls12381_g1() -> Scalar:
    return sample(SCHEME_BLS12381G1)


def sample_bls12381_g2() -> Scalar:
    return sample(SCHEME_BLS12381G2)


def reconstruct(indexed_shares: list[tuple[int, "SecretShare"]]) -> Result[Scalar]:
    def task(_extra: dict) -> Scalar:
        if len(indexed_shares) < 1:
            raise ValueError("reconstruct: no shares")
        scheme = indexed_shares[0][1].scheme
        for _, share in indexed_shares:
            if share.scheme != scheme:
                raise ValueError("reconstruct: SecretShare scheme mismatch")
        if scheme == SCHEME_BLS12381G1:
            inners = [(index, share.inner) for index, share in indexed_shares]
            s = bls12381_g1.reconstruct(inners).unwrap_or_throw(
                ValueError("reconstruct: Bls12381G1 failed")
            )
            return Scalar(SCHEME_BLS12381G1, s)
        if scheme == SCHEME_BLS12381G2:
            inners = [(index, share.inner) for index, share in indexed_shares]
            s = bls12381_g2.reconstruct(inners).unwrap_or_throw(
                ValueError("reconstruct: Bls12381G2 failed")
            )
            return Scalar(SCHEME_BLS12381G2, s)
        raise ValueError(f"reconstruct: unsupported scheme {scheme}")

    return Result.capture(task)


# == SecretShare ==============================================================


class SecretShare:
    def __init__(self, scheme: int, inner) -> None:
        self.scheme = scheme
        self.inner = inner

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["SecretShare"]:
        def task(extra: dict) -> "SecretShare":
            scheme = deserializer.deserialize_u8()
            extra["scheme"] = scheme
            if scheme == SCHEME_BLS12381G1:
                inner = bls12381_g1.SecretShare.deserialize(deserializer).unwrap_or_throw(
                    ValueError("deserialize failed")
                )
                return SecretShare(SCHEME_BLS12381G1, inner)
            if scheme == SCHEME_BLS12381G2:
                inner = bls12381_g2.SecretShare.deserialize(deserializer).unwrap_or_throw(
                    ValueError("deserialize failed")
                )
                return SecretShare(SCHEME_BLS12381G2, inner)
            raise ValueError(f"unsupported scheme {scheme}")

        return Result.capture(task)

    @staticmethod
    def from_bytes(data: bytes) -> Result["SecretShare"]:
        def task(_extra: dict) -> "SecretShare":
            deserializer = Deserializer(data)
            obj = SecretShare.deserialize(deserializer).unwrap_or_throw(
                ValueError("deserialization failed")
            )
            if deserializer.remaining() != 0:
                raise ValueError("trailing bytes")
            return obj

        return Result.capture(task)

    @staticmethod
    def from_hex(hex_str: str) -> Result["SecretShare"]:
        def task(_extra: dict) -> "SecretShare":
            return SecretShare.from_bytes(bytes.fromhex(hex_str)).unwrap_or_throw(
                ValueError("SecretShare.fromHex failed with bytes deserialization error")
            )

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u8(self.scheme)
        if self.scheme == SCHEME_BLS12381G1:
            self.inner.serialize(serializer)
        elif self.scheme == SCHEME_BLS12381G2:
            self.inner.serialize(serializer)
        else:
            raise ValueError(f"unsupported scheme {self.scheme}")

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    def add(self, other: "SecretShare") -> "SecretShare":
        if self.scheme != other.scheme:
            raise ValueError("SecretShare.add: scheme mismatch")
        if self.scheme == SCHEME_BLS12381G1:
            inner = self.inner.add(other.inner)
            return SecretShare(SCHEME_BLS12381G1, inner)
        if self.scheme == SCHEME_BLS12381G2:
            inner = self.inner.add(other.inner)
            return SecretShare(SCHEME_BLS12381G2, inner)
        raise ValueError(f"SecretShare.add: unsupported scheme {self.scheme}")


# == PrivateShareMessage ======================================================


class PrivateShareMessage:
    """The plaintext payload encrypted to each share holder: a Pedersen PCS opening."""

    def __init__(self, opening: PcsOpening) -> None:
        self.opening = opening

    @property
    def share(self) -> "SecretShare":
        return _secret_share_from_scalar(self.opening.eval_value_p)

    def serialize(self, serializer: Serializer) -> None:
        self.opening.serialize(serializer)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["PrivateShareMessage"]:
        def task(_extra: dict) -> "PrivateShareMessage":
            opening = PcsOpening.deserialize(deserializer).unwrap_or_throw(
                ValueError("opening deserialize failed")
            )
            return PrivateShareMessage(opening)

        return Result.capture(task)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> Result["PrivateShareMessage"]:
        def task(_extra: dict) -> "PrivateShareMessage":
            deserializer = Deserializer(data)
            msg = PrivateShareMessage.deserialize(deserializer).unwrap_or_throw(
                ValueError("deserialize failed")
            )
            if deserializer.remaining() != 0:
                raise ValueError("trailing bytes")
            return msg

        return Result.capture(task)

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @staticmethod
    def from_hex(hex_str: str) -> Result["PrivateShareMessage"]:
        def task(_extra: dict) -> "PrivateShareMessage":
            return PrivateShareMessage.from_bytes(bytes.fromhex(hex_str)).unwrap_or_throw(
                ValueError("deserialization failed")
            )

        return Result.capture(task)


def _secret_share_from_scalar(scalar: Scalar) -> SecretShare:
    if scalar.scheme == SCHEME_BLS12381G1:
        data = scalar.inner.to_bytes()
        inner = bls12381_g1.SecretShare.from_bytes(data).unwrap_or_throw(
            ValueError("SecretShare G1 from scalar failed")
        )
        return SecretShare(SCHEME_BLS12381G1, inner)
    if scalar.scheme == SCHEME_BLS12381G2:
        data = scalar.inner.to_bytes()
        inner = bls12381_g2.SecretShare.from_bytes(data).unwrap_or_throw(
            ValueError("SecretShare G2 from scalar failed")
        )
        return SecretShare(SCHEME_BLS12381G2, inner)
    raise ValueError(f"secretShareFromScalar: unsupported scheme {scalar.scheme}")


# == DealerState ==============================================================


class DealerState:
    def __init__(self, scheme: int, inner) -> None:
        self.scheme = scheme
        self.inner = inner

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u8(self.scheme)
        self.inner.serialize(serializer)

    def as_bls12381_fr(self) -> bls12381_g1.DealerState:
        if self.scheme != SCHEME_BLS12381G1:
            raise ValueError("wrong scheme")
        return self.inner

    def as_bls12381_g2_dealer_state(self) -> bls12381_g2.DealerState:
        if self.scheme != SCHEME_BLS12381G2:
            raise ValueError("wrong scheme")
        return self.inner

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["DealerState"]:
        def task(_extra: dict) -> "DealerState":
            scheme = deserializer.deserialize_u8()
            if scheme == SCHEME_BLS12381G1:
                inner = bls12381_g1.DealerState.deserialize(deserializer).unwrap_or_throw(
                    ValueError("deserialize failed")
                )
                return DealerState(SCHEME_BLS12381G1, inner)
            if scheme == SCHEME_BLS12381G2:
                inner = bls12381_g2.DealerState.deserialize(deserializer).unwrap_or_throw(
                    ValueError("deserialize failed")
                )
                return DealerState(SCHEME_BLS12381G2, inner)
            raise ValueError(f"unsupported scheme {scheme}")

        return Result.capture(task)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> Result["DealerState"]:
        def task(_extra: dict) -> "DealerState":
            deserializer = Deserializer(data)
            obj = DealerState.deserialize(deserializer).unwrap_or_throw(
                ValueError("deserialize failed")
            )
            if deserializer.remaining() != 0:
                raise ValueError("trailing bytes")
            return obj

        return Result.capture(task)

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @staticmethod
    def from_hex(hex_str: str) -> Result["DealerState"]:
        def task(_extra: dict) -> "DealerState":
            return DealerState.from_bytes(bytes.fromhex(hex_str)).unwrap_or_throw(
                ValueError("deserialization failed")
            )

        return Result.capture(task)


# == DealerContribution0 ======================================================


class DealerContribution0:
    def __init__(
        self,
        sharing_poly_commitment: PcsCommitment,
        private_share_messages: list[pke.Ciphertext],
        dealer_state: pke.Ciphertext | None = None,
        consistency_proof: SigmaDlogLinearProof | None = None,
    ) -> None:
        self.pcs_commitment = sharing_poly_commitment
        self.private_share_messages = private_share_messages
        self.dealer_state = dealer_state
        self.consistency_proof = consistency_proof

    def serialize(self, serializer: Serializer) -> None:
        """Wire format: [PcsCommitment] [share messages] [Option<dealer state>] [Option<consistency proof>]"""
        self.pcs_commitment.serialize(serializer)
        serializer.serialize_u32_as_uleb128(len(self.private_share_messages))
        for ct in self.private_share_messages:
            ct.serialize(serializer)
        if self.dealer_state is not None:
            serializer.serialize_u8(1)
            self.dealer_state.serialize(serializer)
        else:
            serializer.serialize_u8(0)
        if self.consistency_proof is not None:
            serializer.serialize_u8(1)
            self.consistency_proof.serialize(serializer)
        else:
            serializer.serialize_u8(0)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["DealerContribution0"]:
        def task(_extra: dict) -> "DealerContribution0":
            pcs_commitment = PcsCommitment.deserialize(deserializer).unwrap_or_throw(
                ValueError("pcsCommitment deserialize failed")
            )
            n = deserializer.deserialize_uleb128_as_u32()
            private_share_messages: list[pke.Ciphertext] = []
            for i in range(n):
                ct = pke.Ciphertext.deserialize(deserializer).unwrap_or_throw(
                    ValueError(f"privateShareMessages[{i}] deserialize failed")
                )
                private_share_messages.append(ct)
            dealer_state_tag = deserializer.deserialize_u8()
            dealer_state: pke.Ciphertext | None = None
            if dealer_state_tag == 1:
                dealer_state = pke.Ciphertext.deserialize(deserializer).unwrap_or_throw(
                    ValueError("dealerState deserialize failed")
                )
            elif dealer_state_tag != 0:
                raise ValueError(f"dealerState option tag must be 0 or 1, got {dealer_state_tag}")
            consistency_proof_tag = deserializer.deserialize_u8()
            consistency_proof = None
            if consistency_proof_tag == 1:
                consistency_proof = SigmaDlogLinearProof.deserialize(deserializer).unwrap_or_throw(
                    ValueError("consistencyProof deserialize failed")
                )
            elif consistency_proof_tag != 0:
                raise ValueError(
                    f"consistencyProof option tag must be 0 or 1, got {consistency_proof_tag}"
                )
            return DealerContribution0(
                pcs_commitment, private_share_messages, dealer_state, consistency_proof
            )

        return Result.capture(task)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()


# == DealerContribution1 ======================================================


class DealerContribution1:
    def __init__(
        self,
        shares_to_reveal: list,
        public_keys: list[Element],
        public_key_proofs: list,
    ) -> None:
        self.shares_to_reveal = shares_to_reveal
        self.public_keys = public_keys
        self.public_key_proofs = public_key_proofs

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u32_as_uleb128(len(self.shares_to_reveal))
        for opening in self.shares_to_reveal:
            if opening is None:
                serializer.serialize_u8(0)
            else:
                serializer.serialize_u8(1)
                opening.serialize(serializer)
        serializer.serialize_u32_as_uleb128(len(self.public_keys))
        for pk in self.public_keys:
            pk.serialize(serializer)
        serializer.serialize_u32_as_uleb128(len(self.public_key_proofs))
        for proof in self.public_key_proofs:
            if proof is None:
                serializer.serialize_u8(0)
            else:
                serializer.serialize_u8(1)
                proof.serialize(serializer)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["DealerContribution1"]:
        def task(_extra: dict) -> "DealerContribution1":
            n = deserializer.deserialize_uleb128_as_u32()
            shares_to_reveal = []
            for i in range(n):
                tag = deserializer.deserialize_u8()
                if tag == 0:
                    shares_to_reveal.append(None)
                elif tag == 1:
                    shares_to_reveal.append(
                        PcsOpening.deserialize(deserializer).unwrap_or_throw(
                            ValueError(f"sharesToReveal[{i}] deserialize failed")
                        )
                    )
                else:
                    raise ValueError(f"sharesToReveal[{i}]: invalid option tag {tag}")
            pk_len = deserializer.deserialize_uleb128_as_u32()
            public_keys = []
            for i in range(pk_len):
                public_keys.append(
                    Element.deserialize(deserializer).unwrap_or_throw(
                        ValueError(f"publicKeys[{i}] deserialize failed")
                    )
                )
            proof_len = deserializer.deserialize_uleb128_as_u32()
            public_key_proofs = []
            for i in range(proof_len):
                tag = deserializer.deserialize_u8()
                if tag == 0:
                    public_key_proofs.append(None)
                elif tag == 1:
                    public_key_proofs.append(
                        SigmaDlogLinearProof.deserialize(deserializer).unwrap_or_throw(
                            ValueError(f"publicKeyProofs[{i}] deserialize failed")
                        )
                    )
                else:
                    raise ValueError(f"publicKeyProofs[{i}]: invalid option tag {tag}")
            return DealerContribution1(shares_to_reveal, public_keys, public_key_proofs)

        return Result.capture(task)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> Result["DealerContribution1"]:
        def task(_extra: dict) -> "DealerContribution1":
            deserializer = Deserializer(data)
            obj = DealerContribution1.deserialize(deserializer).unwrap_or_throw(
                ValueError("deserialize failed")
            )
            if deserializer.remaining() != 0:
                raise ValueError("trailing bytes")
            return obj

        return Result.capture(task)

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @staticmethod
    def from_hex(hex_str: str) -> Result["DealerContribution1"]:
        def task(_extra: dict) -> "DealerContribution1":
            return DealerContribution1.from_bytes(bytes.fromhex(hex_str)).unwrap_or_throw(
                ValueError("deserialization failed")
            )

        return Result.capture(task)


# == Session ==================================================================


class Session:
    """
    Mirrors src/vss/index.ts Session. `dealer` / `shareHolders` are
    aptos_sdk.account_address.AccountAddress (BCS-compatible: fixed 32-byte
    serialize/deserialize, matching @aptos-labs/ts-sdk's AccountAddress).
    """

    STATE_SUCCESS = 3

    def __init__(
        self,
        dealer,
        share_holders: list,
        threshold: int,
        base_point: Element,
        previous_public_key: Element | None,
        pcs_context: PcsPublicParams,
        state_code: int,
        deal_time_micros: int,
        dealer_contribution0: DealerContribution0 | None,
        dealer_commitment_check: PcsDegreeCheckState,
        share_holder_acks: list[bool],
        dealer_contribution1: DealerContribution1 | None,
        next_public_key_to_verify: int,
        public_keys: list[Element],
        share_pks: list[Element],
    ) -> None:
        self.dealer = dealer
        self.share_holders = share_holders
        self.threshold = threshold
        self.base_point = base_point
        self.previous_public_key = previous_public_key
        self.pcs_context = pcs_context
        self.state_code = state_code
        self.deal_time_micros = deal_time_micros
        self.dealer_contribution0 = dealer_contribution0
        self.dealer_commitment_check = dealer_commitment_check
        self.share_holder_acks = share_holder_acks
        self.dealer_contribution1 = dealer_contribution1
        self.next_public_key_to_verify = next_public_key_to_verify
        self.public_keys = public_keys
        self.result_pk = public_keys[0] if public_keys else None
        self.share_pks = share_pks

    def serialize(self, serializer: Serializer) -> None:
        serialize_account_address(serializer, self.dealer)
        serializer.serialize_u32_as_uleb128(len(self.share_holders))
        for sh in self.share_holders:
            serialize_account_address(serializer, sh)
        serializer.serialize_u64(self.threshold)
        self.base_point.serialize(serializer)
        if self.previous_public_key is not None:
            serializer.serialize_u8(1)
            self.previous_public_key.serialize(serializer)
        else:
            serializer.serialize_u8(0)
        self.pcs_context.serialize(serializer)
        serializer.serialize_u8(self.state_code)
        serializer.serialize_u64(self.deal_time_micros)
        if self.dealer_contribution0 is None:
            serializer.serialize_u8(0)
        else:
            serializer.serialize_u8(1)
            self.dealer_contribution0.serialize(serializer)
        self.dealer_commitment_check.serialize(serializer)
        serializer.serialize_u32_as_uleb128(len(self.share_holder_acks))
        for ack in self.share_holder_acks:
            serializer.serialize_bool(ack)
        if self.dealer_contribution1 is None:
            serializer.serialize_u8(0)
        else:
            serializer.serialize_u8(1)
            self.dealer_contribution1.serialize(serializer)
        serializer.serialize_u64(self.next_public_key_to_verify)
        serializer.serialize_u32_as_uleb128(len(self.public_keys))
        for pk in self.public_keys:
            pk.serialize(serializer)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["Session"]:
        def task(_extra: dict) -> "Session":
            dealer = deserialize_account_address(deserializer)
            holders_len = deserializer.deserialize_uleb128_as_u32()
            share_holders = []
            for _ in range(holders_len):
                share_holders.append(deserialize_account_address(deserializer))
            threshold = deserializer.deserialize_u64()
            base_point = Element.deserialize(deserializer).unwrap_or_throw(
                ValueError("basePoint deserialize failed")
            )
            previous_public_key_tag = deserializer.deserialize_u8()
            previous_public_key = None
            if previous_public_key_tag == 1:
                previous_public_key = Element.deserialize(deserializer).unwrap_or_throw(
                    ValueError("previousPublicKey deserialize failed")
                )
            elif previous_public_key_tag != 0:
                raise ValueError(
                    f"previousPublicKey option tag must be 0 or 1, got {previous_public_key_tag}"
                )
            pcs_context = PcsPublicParams.deserialize(deserializer).unwrap_or_throw(
                ValueError("pcsContext deserialize failed")
            )
            state_code = deserializer.deserialize_u8()
            deal_time_micros = deserializer.deserialize_u64()
            dc0_tag = deserializer.deserialize_u8()
            dealer_contribution0 = None
            if dc0_tag == 1:
                dealer_contribution0 = DealerContribution0.deserialize(
                    deserializer
                ).unwrap_or_throw(ValueError("dealerContribution0 deserialize failed"))
            elif dc0_tag != 0:
                raise ValueError(f"dealerContribution0 option tag must be 0 or 1, got {dc0_tag}")
            dealer_commitment_check = PcsDegreeCheckState.deserialize(deserializer).unwrap_or_throw(
                ValueError("dealerCommitmentCheck deserialize failed")
            )
            acks_len = deserializer.deserialize_uleb128_as_u32()
            share_holder_acks = []
            for _ in range(acks_len):
                share_holder_acks.append(deserializer.deserialize_bool())
            dc1_tag = deserializer.deserialize_u8()
            dealer_contribution1 = None
            if dc1_tag == 1:
                dealer_contribution1 = DealerContribution1.deserialize(deserializer).unwrap_or_throw(
                    ValueError("dealerContribution1 deserialize failed")
                )
            elif dc1_tag != 0:
                raise ValueError(f"dealerContribution1 option tag must be 0 or 1, got {dc1_tag}")
            next_public_key_to_verify = deserializer.deserialize_u64()
            public_keys_len = deserializer.deserialize_uleb128_as_u32()
            public_keys = []
            for i in range(public_keys_len):
                public_keys.append(
                    Element.deserialize(deserializer).unwrap_or_throw(
                        ValueError(f"publicKeys[{i}] deserialize failed")
                    )
                )
            share_pks = public_keys[1:]
            return Session(
                dealer,
                share_holders,
                threshold,
                base_point,
                previous_public_key,
                pcs_context,
                state_code,
                deal_time_micros,
                dealer_contribution0,
                dealer_commitment_check,
                share_holder_acks,
                dealer_contribution1,
                next_public_key_to_verify,
                public_keys,
                share_pks,
            )

        return Result.capture(task)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

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

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @staticmethod
    def from_hex(hex_str: str) -> Result["Session"]:
        def task(_extra: dict) -> "Session":
            return Session.from_bytes(bytes.fromhex(hex_str)).unwrap_or_throw(
                ValueError("deserialization failed")
            )

        return Result.capture(task)

    def is_completed(self) -> bool:
        return self.state_code == Session.STATE_SUCCESS
