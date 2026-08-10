# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Mirrors src/sigma-dlog-linear/index.ts: a Sigma-protocol proof of knowledge
of discrete logs (linear relations) over scheme-tagged group Elements/Scalars."""

from __future__ import annotations

from ace_sdk.bcs import Deserializer, Serializer
from ace_sdk.group import Element, Scalar
from ace_sdk.result import Result


class Proof:
    def __init__(self, t_vals: list[Element], z_vals: list[Scalar]) -> None:
        self.t_vals = t_vals
        self.z_vals = z_vals

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u32_as_uleb128(len(self.t_vals))
        for t in self.t_vals:
            t.serialize(serializer)
        serializer.serialize_u32_as_uleb128(len(self.z_vals))
        for z in self.z_vals:
            z.serialize(serializer)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["Proof"]:
        def task(_extra: dict) -> "Proof":
            t_len = deserializer.deserialize_uleb128_as_u32()
            t_vals: list[Element] = []
            for i in range(t_len):
                t_vals.append(
                    Element.deserialize(deserializer).unwrap_or_throw(
                        ValueError(f"tVals[{i}] deserialize failed")
                    )
                )
            z_len = deserializer.deserialize_uleb128_as_u32()
            z_vals: list[Scalar] = []
            for i in range(z_len):
                z_vals.append(
                    Scalar.deserialize(deserializer).unwrap_or_throw(
                        ValueError(f"zVals[{i}] deserialize failed")
                    )
                )
            return Proof(t_vals, z_vals)

        return Result.capture(task)
