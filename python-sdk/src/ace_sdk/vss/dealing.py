# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""
Fr-only Shamir dealing: polynomial coefficients derived from (SplitConfig, seed,
baseCompressed). Evaluation points are fixed: s(0) = secret, s(i) = share for
holder i (1-indexed). Shared by G1 and G2 variants.

Mirrors src/vss/dealing.ts.
"""

from __future__ import annotations

from dataclasses import dataclass

from ace_sdk.group.bls12381fr import fr_add, fr_inv, fr_mod, fr_mul
from ace_sdk.utils import sha3_512

# First byte of Secret / PublicCommitment / SecretShare payloads. Bump when layout changes.
SSS_WIRE_VERSION = 4

# Seed length in bytes (CSPRNG in split(), fixed on the wire).
SSS_SEED_BYTES = 32


@dataclass(frozen=True)
class SplitConfig:
    n: int  # number of shares / evaluation points
    t: int  # reconstruction threshold (polynomial degree is t - 1)


def split_config_equals(a: SplitConfig, b: SplitConfig) -> bool:
    return a.n == b.n and a.t == b.t


def _u32le(n: int) -> bytes:
    return (n & 0xFFFFFFFF).to_bytes(4, "little")


def _u64le(v: int) -> bytes:
    return (v & 0xFFFFFFFFFFFFFFFF).to_bytes(8, "little")


def derive_dealing_frs(split_config: SplitConfig, seed: bytes, base_compressed: bytes) -> list[int]:
    """
    Derive t - 1 pseudorandom Fr values for Shamir polynomial coefficients.
    (Evaluation points are fixed: holder i uses x = i, 1-indexed.)

    For each slot i in 0 .. t-2:
      sha3_512("ace-sss-dealing-v2" || seed || n || t || u32le(i) || baseCompressed)
    64-byte digest as unsigned LE integer, then fr_mod to Fr.
    """
    n, t = split_config.n, split_config.t
    if n < 1 or t < 1 or n < t:
        raise ValueError("deriveDealingFrs: require 1 <= t <= n")
    if len(seed) != SSS_SEED_BYTES:
        raise ValueError("deriveDealingFrs: invalid seed length")

    num_draws = t - 1
    draws: list[int] = []
    for i in range(num_draws):
        transcript = (
            b"ace-sss-dealing-v2" + seed + _u64le(n) + _u64le(t) + _u32le(i) + base_compressed
        )
        digest = sha3_512(transcript)
        draws.append(fr_mod(int.from_bytes(digest, "little")))
    return draws


def eval_poly(coeffs: list[int], x: int) -> int:
    xr = fr_mod(x)
    y = 0
    xp = 1
    for c in coeffs:
        y = fr_add(y, fr_mul(fr_mod(c), xp))
        xp = fr_mul(xp, xr)
    return fr_mod(y)


def lagrange_at_zero(points: list[tuple[int, int]]) -> int:
    """Lagrange interpolation: recover f(0) given points (x_i, y_i) with distinct x_i in Fr."""
    m = len(points)
    if m < 1:
        raise ValueError("lagrangeAtZero: need at least one point")
    xs = [fr_mod(p[0]) for p in points]
    ys = [fr_mod(p[1]) for p in points]
    for i in range(m):
        for j in range(i + 1, m):
            if xs[i] == xs[j]:
                raise ValueError("lagrangeAtZero: duplicate x")
    result = 0
    for i in range(m):
        lam = 1
        for j in range(m):
            if i == j:
                continue
            num = fr_mod(-xs[j])
            den = fr_mod(xs[i] - xs[j])
            lam = fr_mul(lam, fr_mul(num, fr_inv(den)))
        result = fr_add(result, fr_mul(ys[i], lam))
    return fr_mod(result)


def fr_point_key(x: int) -> str:
    return fr_mod(x).to_bytes(32, "little").hex()


def x_in_allowed_set(x: int, allowed: list[int]) -> bool:
    k = fr_point_key(x)
    return any(fr_point_key(a) == k for a in allowed)
