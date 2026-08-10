# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Mirrors src/pke/group.ts: ristretto255 Element/Scalar + msm/scalarFrom512BitHash."""

from __future__ import annotations

from ace_sdk.bcs import Deserializer, Serializer
from ace_sdk.pke import _ristretto255 as _r
from ace_sdk.utils import rand_bytes

Q = 0x1000000000000000000000000000000014DEF9DEA2F79CD65812631A5CF5D3ED


class Element:
    def __init__(self, data: bytes) -> None:
        self.bytes = data

    @staticmethod
    def dummy() -> "Element":
        return Element(bytes(32))

    @staticmethod
    def group_identity() -> "Element":
        return Element(_r.group_identity())

    @staticmethod
    def rand() -> "Element":
        random_bytes = rand_bytes(64)
        return Element(_r.from_hash(random_bytes))

    @staticmethod
    def decode(deserializer: Deserializer) -> "Element":
        data = deserializer.deserialize_bytes()
        return Element(data)

    def encode(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(self.bytes)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.encode(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    def add(self, other: "Element") -> "Element":
        return Element(_r.point_add(self.bytes, other.bytes))

    def sub(self, other: "Element") -> "Element":
        return Element(_r.point_sub(self.bytes, other.bytes))

    def scale(self, scalar: "Scalar") -> "Element":
        if scalar.is_zero():
            return Element.group_identity()
        return Element(_r.scalarmult(scalar.bytes, self.bytes))


class Scalar:
    def __init__(self, data: bytes) -> None:
        self.bytes = data

    @staticmethod
    def dummy() -> "Scalar":
        return Scalar(bytes(32))

    @staticmethod
    def from_u64(x: int) -> "Scalar":
        return Scalar(x.to_bytes(32, "little"))

    @staticmethod
    def from_little_endian_bytes_mod_q(data: bytes) -> "Scalar":
        value = int.from_bytes(data, "little") % Q
        return Scalar(value.to_bytes(32, "little"))

    @staticmethod
    def rand() -> "Scalar":
        random_bytes = rand_bytes(64)
        value = int.from_bytes(random_bytes, "little") % Q
        scalar_value = 1 if value == 0 else value
        return Scalar(scalar_value.to_bytes(32, "little"))

    @staticmethod
    def decode(deserializer: Deserializer) -> "Scalar":
        data = deserializer.deserialize_bytes()
        return Scalar(data)

    def encode(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(self.bytes)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.encode(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    def is_zero(self) -> bool:
        return all(b == 0 for b in self.bytes)

    def add(self, other: "Scalar") -> "Scalar":
        result = (int.from_bytes(self.bytes, "little") + int.from_bytes(other.bytes, "little")) % Q
        return Scalar(result.to_bytes(32, "little"))

    def sub(self, other: "Scalar") -> "Scalar":
        result = (Q - int.from_bytes(other.bytes, "little") + int.from_bytes(self.bytes, "little")) % Q
        return Scalar(result.to_bytes(32, "little"))

    def mul(self, other: "Scalar") -> "Scalar":
        result = (int.from_bytes(self.bytes, "little") * int.from_bytes(other.bytes, "little")) % Q
        return Scalar(result.to_bytes(32, "little"))

    def neg(self) -> "Scalar":
        result = Q - int.from_bytes(self.bytes, "little")
        return Scalar(result.to_bytes(32, "little"))


def msm(bases: list[Element], scalars: list[Scalar]) -> Element:
    acc = Element.group_identity()
    for base, scalar in zip(bases, scalars):
        acc = acc.add(base.scale(scalar))
    return acc


def scalar_from_512_bit_hash(hash_bytes: bytes) -> Scalar:
    if len(hash_bytes) != 64:
        raise ValueError("Hash must be 512 bits (64 bytes)")
    value = int.from_bytes(hash_bytes[:32], "little") % Q
    scalar_value = 1 if value == 0 else value
    return Scalar(scalar_value.to_bytes(32, "little"))
