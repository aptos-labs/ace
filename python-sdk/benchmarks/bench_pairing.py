# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Small opt-in benchmark for the pure-Python BLS12-381 pairing."""

from __future__ import annotations

import argparse
import statistics
import time

from ace_sdk.group import bls12381g1, bls12381g2
from ace_sdk.group.bls12381_pairing import fp12_to_bytes, pairing_from_jacobian


def measure_pairing(iterations: int) -> list[float]:
    g1 = bls12381g1.g1_generator().pt
    g2 = bls12381g2.g2_generator().pt
    timings_ms: list[float] = []
    for _ in range(iterations):
        start = time.perf_counter()
        result = pairing_from_jacobian(g1, g2)
        fp12_to_bytes(result)
        timings_ms.append((time.perf_counter() - start) * 1000)
    return timings_ms


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-n",
        "--iterations",
        type=int,
        default=5,
        help="number of pairing operations to measure",
    )
    args = parser.parse_args()
    if args.iterations < 1:
        raise ValueError("iterations must be >= 1")

    measure_pairing(1)
    timings_ms = measure_pairing(args.iterations)
    mean_ms = statistics.fmean(timings_ms)
    print(f"pairing_from_jacobian+fp12_to_bytes: {mean_ms:.2f} ms/op")
    print(f"iterations={args.iterations} min={min(timings_ms):.2f} max={max(timings_ms):.2f}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
