# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Mirrors src/pedersen-polynomial-commitment/index.ts."""

from __future__ import annotations

from ace_sdk.bcs import Deserializer, Serializer
from ace_sdk.group import Element, Scalar
from ace_sdk.group import bls12381g1 as bls12381_g1
from ace_sdk.group import bls12381g2 as bls12381_g2
from ace_sdk.result import Result


class PublicParams:
    def __init__(self, generator_g: Element, generator_h: Element) -> None:
        self.generator_g = generator_g
        self.generator_h = generator_h

    def serialize(self, serializer: Serializer) -> None:
        self.generator_g.serialize(serializer)
        self.generator_h.serialize(serializer)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["PublicParams"]:
        def task(_extra: dict) -> "PublicParams":
            generator_g = Element.deserialize(deserializer).unwrap_or_throw(
                ValueError("generatorG deserialize failed")
            )
            generator_h = Element.deserialize(deserializer).unwrap_or_throw(
                ValueError("generatorH deserialize failed")
            )
            return PublicParams(generator_g, generator_h)

        return Result.capture(task)


# == Commitment ===============================================================


class Commitment:
    """Pedersen PCS commitment points over the ACE domain {0, 1, ..., n}."""

    def __init__(self, points: list[Element]) -> None:
        self.points = points

    @staticmethod
    def from_bls12381_g1(inner_points: bls12381_g1.PcsCommitment) -> "Commitment":
        return Commitment(
            [Element.from_bls12381_g1(bls12381_g1.PublicPoint(pt)) for pt in inner_points.v_values]
        )

    @staticmethod
    def from_bls12381_g2(inner_points: bls12381_g2.PcsCommitment) -> "Commitment":
        return Commitment(
            [Element.from_bls12381_g2(bls12381_g2.PublicPoint(pt)) for pt in inner_points.v_values]
        )

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u32_as_uleb128(len(self.points))
        for pt in self.points:
            pt.serialize(serializer)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["Commitment"]:
        def task(_extra: dict) -> "Commitment":
            length = deserializer.deserialize_uleb128_as_u32()
            points: list[Element] = []
            for i in range(length):
                pt = Element.deserialize(deserializer).unwrap_or_throw(
                    ValueError(f"point[{i}] deserialize failed")
                )
                points.append(pt)
            return Commitment(points)

        return Result.capture(task)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> Result["Commitment"]:
        def task(_extra: dict) -> "Commitment":
            deserializer = Deserializer(data)
            obj = Commitment.deserialize(deserializer).unwrap_or_throw(
                ValueError("deserialize failed")
            )
            if deserializer.remaining() != 0:
                raise ValueError("trailing bytes")
            return obj

        return Result.capture(task)

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @staticmethod
    def from_hex(hex_str: str) -> Result["Commitment"]:
        def task(_extra: dict) -> "Commitment":
            return Commitment.from_bytes(bytes.fromhex(hex_str)).unwrap_or_throw(
                ValueError("deserialization failed")
            )

        return Result.capture(task)


# == Opening ==================================================================


class Opening:
    def __init__(self, eval_position: int, eval_value_p: Scalar, eval_value_r: Scalar) -> None:
        self.eval_position = eval_position
        self.eval_value_p = eval_value_p
        self.eval_value_r = eval_value_r

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u64(self.eval_position)
        self.eval_value_p.serialize(serializer)
        self.eval_value_r.serialize(serializer)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["Opening"]:
        def task(_extra: dict) -> "Opening":
            eval_position = deserializer.deserialize_u64()
            eval_value_p = Scalar.deserialize(deserializer).unwrap_or_throw(
                ValueError("evalValueP deserialize failed")
            )
            eval_value_r = Scalar.deserialize(deserializer).unwrap_or_throw(
                ValueError("evalValueR deserialize failed")
            )
            return Opening(eval_position, eval_value_p, eval_value_r)

        return Result.capture(task)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> Result["Opening"]:
        def task(_extra: dict) -> "Opening":
            deserializer = Deserializer(data)
            obj = Opening.deserialize(deserializer).unwrap_or_throw(
                ValueError("deserialize failed")
            )
            if deserializer.remaining() != 0:
                raise ValueError("trailing bytes")
            return obj

        return Result.capture(task)


# == DegreeCheckState =========================================================


class DegreeCheckState:
    def __init__(self, z_poly: list[Scalar], accumulator: Element, next_eval_position: int) -> None:
        self.z_poly = z_poly
        self.accumulator = accumulator
        self.next_eval_position = next_eval_position

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u32_as_uleb128(len(self.z_poly))
        for z in self.z_poly:
            z.serialize(serializer)
        self.accumulator.serialize(serializer)
        serializer.serialize_u64(self.next_eval_position)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["DegreeCheckState"]:
        def task(_extra: dict) -> "DegreeCheckState":
            z_len = deserializer.deserialize_uleb128_as_u32()
            z_poly: list[Scalar] = []
            for i in range(z_len):
                z_poly.append(
                    Scalar.deserialize(deserializer).unwrap_or_throw(
                        ValueError(f"zPoly[{i}] deserialize failed")
                    )
                )
            accumulator = Element.deserialize(deserializer).unwrap_or_throw(
                ValueError("accumulator deserialize failed")
            )
            next_eval_position = deserializer.deserialize_u64()
            return DegreeCheckState(z_poly, accumulator, next_eval_position)

        return Result.capture(task)
