# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""
BLS12-381 Fr field arithmetic. Shared between G1 and G2 (both groups have the
same prime order r). Other modules should import field ops from here, not from
a specific group module.
"""

from __future__ import annotations

FR_MODULUS = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000001


def fr_mod(a: int) -> int:
    return ((a % FR_MODULUS) + FR_MODULUS) % FR_MODULUS


def assert_canonical_fr_scalar(label: str, s: int) -> None:
    if s < 0 or s >= FR_MODULUS:
        raise ValueError(f"{label}: expected canonical Fr scalar in [0, FR_MODULUS)")


def fr_add(a: int, b: int) -> int:
    return fr_mod(a + b)


def fr_mul(a: int, b: int) -> int:
    return fr_mod(a * b)


def fr_inv(a: int) -> int:
    return pow(fr_mod(a), FR_MODULUS - 2, FR_MODULUS)
