# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""
Scheme-tagged Scalar/Element wrappers over the concrete BLS12-381 G1/G2 group
implementations. Mirrors src/group/index.ts.
"""

from __future__ import annotations

from ace_sdk.bcs import Deserializer, Serializer
from ace_sdk.group import bls12381g1 as bls12381_g1
from ace_sdk.group import bls12381g2 as bls12381_g2
from ace_sdk.result import Result

SCHEME_BLS12381G1 = 0
SCHEME_BLS12381G2 = 1


def scheme_supported(scheme: int) -> bool:
    return scheme in (SCHEME_BLS12381G1, SCHEME_BLS12381G2)


# == Scalar ===================================================================


class Scalar:
    def __init__(self, scheme: int, inner) -> None:
        self.scheme = scheme
        self.inner = inner

    def as_bls12381_g1(self) -> bls12381_g1.PrivateScalar:
        if self.scheme != SCHEME_BLS12381G1:
            raise ValueError("wrong scheme")
        return self.inner

    def as_bls12381_g2(self) -> bls12381_g2.PrivateScalar:
        if self.scheme != SCHEME_BLS12381G2:
            raise ValueError("wrong scheme")
        return self.inner

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["Scalar"]:
        def task(extra: dict) -> "Scalar":
            scheme = deserializer.deserialize_u8()
            extra["scheme"] = scheme
            if scheme == SCHEME_BLS12381G1:
                inner = bls12381_g1.PrivateScalar.deserialize(deserializer).unwrap_or_throw(
                    ValueError("deserialize failed")
                )
                return Scalar(SCHEME_BLS12381G1, inner)
            if scheme == SCHEME_BLS12381G2:
                inner = bls12381_g2.PrivateScalar.deserialize(deserializer).unwrap_or_throw(
                    ValueError("deserialize failed")
                )
                return Scalar(SCHEME_BLS12381G2, inner)
            raise ValueError(f"unsupported scheme {scheme}")

        return Result.capture(task)

    @staticmethod
    def from_bytes(data: bytes) -> Result["Scalar"]:
        def task(_extra: dict) -> "Scalar":
            deserializer = Deserializer(data)
            obj = Scalar.deserialize(deserializer).unwrap_or_throw(
                ValueError("deserialization failed")
            )
            if deserializer.remaining() != 0:
                raise ValueError("trailing bytes")
            return obj

        return Result.capture(task)

    @staticmethod
    def from_hex(hex_str: str) -> Result["Scalar"]:
        def task(_extra: dict) -> "Scalar":
            return Scalar.from_bytes(bytes.fromhex(hex_str)).unwrap_or_throw(
                ValueError("deserialization failed")
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


# == Element ==================================================================


class Element:
    def __init__(self, scheme: int, inner) -> None:
        self.scheme = scheme
        self.inner = inner

    @staticmethod
    def from_bls12381_g1(inner: bls12381_g1.PublicPoint) -> "Element":
        return Element(SCHEME_BLS12381G1, inner)

    @staticmethod
    def from_bls12381_g2(inner: bls12381_g2.PublicPoint) -> "Element":
        return Element(SCHEME_BLS12381G2, inner)

    def scale(self, scalar: Scalar) -> "Element":
        """Scalar multiplication: returns scalar * this. Schemes must match."""
        if self.scheme != scalar.scheme:
            raise ValueError(
                f"scale: scheme mismatch (element={self.scheme}, scalar={scalar.scheme})"
            )
        if self.scheme == SCHEME_BLS12381G1:
            result = self.inner.scale(scalar.as_bls12381_g1())
            return Element(SCHEME_BLS12381G1, result)
        if self.scheme == SCHEME_BLS12381G2:
            result = self.inner.scale(scalar.as_bls12381_g2())
            return Element(SCHEME_BLS12381G2, result)
        raise ValueError(f"scale: unsupported scheme {self.scheme}")

    def equals(self, other: "Element") -> bool:
        """Projective equality check."""
        if self.scheme != other.scheme:
            return False
        if self.scheme == SCHEME_BLS12381G1:
            return self.inner.equals(other.inner)
        if self.scheme == SCHEME_BLS12381G2:
            return self.inner.equals(other.inner)
        raise ValueError(f"equals: unsupported scheme {self.scheme}")

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u8(self.scheme)
        if self.scheme == SCHEME_BLS12381G1:
            self.inner.serialize(serializer)
        elif self.scheme == SCHEME_BLS12381G2:
            self.inner.serialize(serializer)
        else:
            raise ValueError(f"unsupported scheme {self.scheme}")

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["Element"]:
        def task(extra: dict) -> "Element":
            scheme = deserializer.deserialize_u8()
            extra["scheme"] = scheme
            if scheme == SCHEME_BLS12381G1:
                inner = bls12381_g1.PublicPoint.deserialize(deserializer).unwrap_or_throw(
                    ValueError("deserialize failed")
                )
                return Element(SCHEME_BLS12381G1, inner)
            if scheme == SCHEME_BLS12381G2:
                inner = bls12381_g2.PublicPoint.deserialize(deserializer).unwrap_or_throw(
                    ValueError("deserialize failed")
                )
                return Element(SCHEME_BLS12381G2, inner)
            raise ValueError(f"unsupported scheme {scheme}")

        return Result.capture(task)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> Result["Element"]:
        def task(_extra: dict) -> "Element":
            deserializer = Deserializer(data)
            obj = Element.deserialize(deserializer).unwrap_or_throw(
                ValueError("deserialize failed")
            )
            if deserializer.remaining() != 0:
                raise ValueError("trailing bytes")
            return obj

        return Result.capture(task)

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @staticmethod
    def from_hex(hex_str: str) -> Result["Element"]:
        def task(_extra: dict) -> "Element":
            return Element.from_bytes(bytes.fromhex(hex_str)).unwrap_or_throw(
                ValueError("deserialization failed")
            )

        return Result.capture(task)
