# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""
Feldman VSS over BLS12-381 G2: secrets in Fr, commitments in G2.

Mirror of bls12381g1.py with G1 -> G2. Fr is shared between G1 and G2 (same
prime order), so scalar/share/dealer-state semantics are identical; we
duplicate the types so the abstract Scalar / Element layer can carry a scheme
tag faithfully.

- PrivateScalar: a secret s in Fr.
- PublicPoint: a G2 element (used in Feldman commitment: g^{a_k} for g in G2).
- SecretShare: the evaluation y = f(i) in Fr for holder at index i (1-indexed).
- PcsCommitment: t G2 points [g^{a_0}, ..., g^{a_{t-1}}].
- DealerState: dealer's polynomial coefficients [a_0, ..., a_{t-1}] (a_0 = secret).

Mirrors src/group/bls12381g2.ts. Wire format uses 96-byte compressed G2 points
(two 48-byte Fp2 coordinates concatenated big-endian, matching @noble/curves).
"""

from __future__ import annotations

from dataclasses import dataclass

from py_ecc.bls.point_compression import compress_G2, decompress_G2
from py_ecc.optimized_bls12_381 import G2 as _G2_GENERATOR
from py_ecc.optimized_bls12_381 import curve_order as _CURVE_ORDER
from py_ecc.optimized_bls12_381 import is_inf as _g2_is_inf
from py_ecc.optimized_bls12_381 import multiply as _g2_multiply
from py_ecc.optimized_bls12_381 import normalize as _g2_normalize

from ace_sdk.bcs import Deserializer, Serializer
from ace_sdk.group.bls12381fr import FR_MODULUS, fr_add, fr_mod, fr_mul  # noqa: F401
from ace_sdk.result import Result
from ace_sdk.utils import rand_bytes
from ace_sdk.vss.dealing import lagrange_at_zero

_OptPoint = tuple  # (FQ2, FQ2, FQ2) Jacobian point from py_ecc


def _g2_from_compressed(raw: bytes) -> _OptPoint:
    if len(raw) != 96:
        raise ValueError("expected 96 bytes")
    c0 = int.from_bytes(raw[:48], "big")
    c1 = int.from_bytes(raw[48:], "big")
    # decompress_G2 already returns a Jacobian point (x, y, FQ2([1, 0])).
    pt = decompress_G2((c0, c1))
    if not _g2_is_inf(_g2_multiply(pt, _CURVE_ORDER)):
        raise ValueError("point is not in the prime-order G2 subgroup")
    return pt


def _g2_to_compressed(pt: _OptPoint) -> bytes:
    c0, c1 = compress_G2(pt)
    return c0.to_bytes(48, "big") + c1.to_bytes(48, "big")


def _g2_equals(a: _OptPoint, b: _OptPoint) -> bool:
    ax, ay = _g2_normalize(a)
    bx, by = _g2_normalize(b)
    return ax == bx and ay == by


# == PrivateScalar ============================================================


@dataclass(frozen=True)
class PrivateScalar:
    scalar: int

    @staticmethod
    def from_bigint(unchecked: int) -> Result["PrivateScalar"]:
        def task(_extra: dict) -> "PrivateScalar":
            if unchecked < 0 or unchecked >= FR_MODULUS:
                raise ValueError("")
            return PrivateScalar(unchecked)

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(self.scalar.to_bytes(32, "little"))

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["PrivateScalar"]:
        def task(_extra: dict) -> "PrivateScalar":
            s_le = deserializer.deserialize_bytes()
            if len(s_le) != 32:
                raise ValueError("expected 32 bytes")
            s = int.from_bytes(s_le, "little")
            return PrivateScalar.from_bigint(s).unwrap_or_throw(ValueError("value out of range"))

        return Result.capture(task)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> Result["PrivateScalar"]:
        def task(_extra: dict) -> "PrivateScalar":
            deserializer = Deserializer(data)
            secret = PrivateScalar.deserialize(deserializer).unwrap_or_throw(
                ValueError("deserialize failed")
            )
            if deserializer.remaining() != 0:
                raise ValueError("trailing bytes")
            return secret

        return Result.capture(task)

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @staticmethod
    def from_hex(hex_str: str) -> Result["PrivateScalar"]:
        def task(_extra: dict) -> "PrivateScalar":
            data = bytes.fromhex(hex_str)
            return PrivateScalar.from_bytes(data).unwrap_or_throw(
                ValueError("deserialization failed")
            )

        return Result.capture(task)


# == PublicPoint ==============================================================


def g2_generator() -> "PublicPoint":
    """Returns the BLS12-381 G2 generator as a PublicPoint."""
    return PublicPoint(_G2_GENERATOR)


class PublicPoint:
    """A BLS12-381 G2 element. Wire format: [uleb128(96)][96-byte compressed G2]."""

    def __init__(self, pt: _OptPoint) -> None:
        self.pt = pt

    @staticmethod
    def from_raw_bytes(raw_bytes: bytes) -> Result["PublicPoint"]:
        def task(_extra: dict) -> "PublicPoint":
            if len(raw_bytes) != 96:
                raise ValueError("expected 96 bytes")
            pt = _g2_from_compressed(raw_bytes)
            return PublicPoint(pt)

        return Result.capture(task)

    def raw_bytes(self) -> bytes:
        return _g2_to_compressed(self.pt)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(self.raw_bytes())

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["PublicPoint"]:
        def task(_extra: dict) -> "PublicPoint":
            pt_bytes = deserializer.deserialize_bytes()
            return PublicPoint.from_raw_bytes(pt_bytes).unwrap_or_throw(
                ValueError("invalid G2 point")
            )

        return Result.capture(task)

    @staticmethod
    def from_bytes(data: bytes) -> Result["PublicPoint"]:
        def task(_extra: dict) -> "PublicPoint":
            deserializer = Deserializer(data)
            obj = PublicPoint.deserialize(deserializer).unwrap_or_throw(
                ValueError("deserialize failed")
            )
            if deserializer.remaining() != 0:
                raise ValueError("trailing bytes")
            return obj

        return Result.capture(task)

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @staticmethod
    def from_hex(hex_str: str) -> Result["PublicPoint"]:
        def task(_extra: dict) -> "PublicPoint":
            data = bytes.fromhex(hex_str)
            return PublicPoint.from_bytes(data).unwrap_or_throw(
                ValueError("deserialization failed")
            )

        return Result.capture(task)

    def scale(self, scalar: PrivateScalar) -> "PublicPoint":
        """Scalar multiplication: returns scalar * this."""
        result = _g2_multiply(self.pt, scalar.scalar)
        return PublicPoint(result)

    def equals(self, other: "PublicPoint") -> bool:
        """Projective equality check."""
        return _g2_equals(self.pt, other.pt)


# == SecretShare ==============================================================


@dataclass(frozen=True)
class SecretShare:
    """
    A Feldman share for holder at (implicit) index i: y = f(i) in Fr.
    Wire format: [uleb128(32)][32-byte Fr LE].
    """

    y: int

    @staticmethod
    def from_bigint(unchecked_y: int) -> Result["SecretShare"]:
        def task(_extra: dict) -> "SecretShare":
            if unchecked_y < 0 or unchecked_y >= FR_MODULUS:
                raise ValueError("y out of range")
            return SecretShare(unchecked_y)

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(self.y.to_bytes(32, "little"))

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["SecretShare"]:
        def task(_extra: dict) -> "SecretShare":
            y_bytes = deserializer.deserialize_bytes()
            if len(y_bytes) != 32:
                raise ValueError("expected 32 bytes")
            y = int.from_bytes(y_bytes, "little")
            return SecretShare.from_bigint(y).unwrap_or_throw(ValueError("value out of range"))

        return Result.capture(task)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> Result["SecretShare"]:
        def task(_extra: dict) -> "SecretShare":
            deserializer = Deserializer(data)
            share = SecretShare.deserialize(deserializer).unwrap_or_throw(
                ValueError("deserialize failed")
            )
            if deserializer.remaining() != 0:
                raise ValueError("trailing bytes")
            return share

        return Result.capture(task)

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    def add(self, other: "SecretShare") -> "SecretShare":
        total = fr_mod(self.y + other.y)
        return SecretShare.from_bigint(total).unwrap_or_throw(RuntimeError("unreachable"))

    @staticmethod
    def from_hex(hex_str: str) -> Result["SecretShare"]:
        def task(_extra: dict) -> "SecretShare":
            data = bytes.fromhex(hex_str)
            return SecretShare.from_bytes(data).unwrap_or_throw(
                ValueError("deserialization failed")
            )

        return Result.capture(task)


# == PcsCommitment ============================================================


class PcsCommitment:
    """
    Feldman polynomial commitment: t G2 points [g^{a_0}, ..., g^{a_{t-1}}].
    Wire format (no scheme prefix): [uleb128 t] { [uleb128(96)] [96-byte G2] } x t.
    """

    def __init__(self, v_values: list) -> None:
        self.v_values = v_values

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u32_as_uleb128(len(self.v_values))
        for pt in self.v_values:
            serializer.serialize_bytes(_g2_to_compressed(pt))

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["PcsCommitment"]:
        def task(_extra: dict) -> "PcsCommitment":
            length = deserializer.deserialize_uleb128_as_u32()
            v_values = []
            for _ in range(length):
                pt_bytes = deserializer.deserialize_bytes()
                v_values.append(_g2_from_compressed(pt_bytes))
            return PcsCommitment(v_values)

        return Result.capture(task)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> Result["PcsCommitment"]:
        def task(_extra: dict) -> "PcsCommitment":
            deserializer = Deserializer(data)
            obj = PcsCommitment.deserialize(deserializer).unwrap_or_throw(
                ValueError("deserialize failed")
            )
            if deserializer.remaining() != 0:
                raise ValueError("trailing bytes")
            return obj

        return Result.capture(task)

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @staticmethod
    def from_hex(hex_str: str) -> Result["PcsCommitment"]:
        def task(_extra: dict) -> "PcsCommitment":
            data = bytes.fromhex(hex_str)
            return PcsCommitment.from_bytes(data).unwrap_or_throw(
                ValueError("deserialization failed")
            )

        return Result.capture(task)


# == DealerState ==============================================================


class DealerState:
    """
    Dealer's private polynomial coefficients [a_0, ..., a_{t-1}]. a_0 = secret.
    Wire format: [u64 n] [uleb128 t] { [uleb128(32)] [32-byte Fr LE] } x t
    """

    def __init__(self, n: int, coefs_poly_p: list[int]) -> None:
        self.n = n
        self.coefs_poly_p = coefs_poly_p

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u64(self.n)
        serializer.serialize_u32_as_uleb128(len(self.coefs_poly_p))
        for coef in self.coefs_poly_p:
            serializer.serialize_bytes(coef.to_bytes(32, "little"))

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["DealerState"]:
        def task(_extra: dict) -> "DealerState":
            n = deserializer.deserialize_u64()
            coefs_len = deserializer.deserialize_uleb128_as_u32()
            coefs_poly_p = []
            for i in range(coefs_len):
                coef = deserializer.deserialize_bytes()
                if len(coef) != 32:
                    raise ValueError(f"coefsPolyP[{i}]: expected 32 bytes")
                v = int.from_bytes(coef, "little")
                if v >= FR_MODULUS:
                    raise ValueError(f"coefsPolyP[{i}] out of range")
                coefs_poly_p.append(v)
            return DealerState(n, coefs_poly_p)

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
            data = bytes.fromhex(hex_str)
            return DealerState.from_bytes(data).unwrap_or_throw(
                ValueError("deserialization failed")
            )

        return Result.capture(task)


# == Functions ================================================================


def sample() -> PrivateScalar:
    x = int.from_bytes(rand_bytes(64), "little")
    val = fr_mod(x)
    return PrivateScalar.from_bigint(val).unwrap_or_throw(RuntimeError("unreachable"))


def reconstruct(indexed_shares: list[tuple[int, SecretShare]]) -> Result[PrivateScalar]:
    """
    Reconstruct the secret from a subset of indexed shares.
    `index` is 1-based (holder i has share f(i)).
    """

    def task(_extra: dict) -> PrivateScalar:
        points = [(index, share.y) for index, share in indexed_shares]
        s_rec = lagrange_at_zero(points)
        return PrivateScalar.from_bigint(s_rec).unwrap_or_throw(RuntimeError("unreachable"))

    return Result.capture(task)


def split(secret: bytes, threshold: int, total: int) -> Result[list[bytes]]:
    """Split a 32-byte LE Fr secret into Shamir shares over BLS12-381 Fr."""

    def task(_extra: dict) -> list[bytes]:
        if threshold < 1 or threshold > total:
            raise ValueError("split: invalid threshold or total")
        s = fr_mod(int.from_bytes(secret, "little"))
        coeffs = [s]
        for _ in range(1, threshold):
            coeffs.append(fr_mod(int.from_bytes(rand_bytes(32), "little")))
        shares = []
        for i in range(total):
            x = i + 1
            y = 0
            x_pow = 1
            for c in coeffs:
                y = fr_add(y, fr_mul(c, x_pow))
                x_pow = fr_mul(x_pow, x)
            shares.append(y.to_bytes(32, "little"))
        return shares

    return Result.capture(task)
