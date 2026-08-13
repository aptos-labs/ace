# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Mirrors src/utils.ts: randomness, byte helpers, KDF, HMAC-SHA3-256."""

from __future__ import annotations

import hashlib
import os

from ace_sdk.bcs import Serializer


def rand_bytes(length: int) -> bytes:
    """Cryptographically strong randomness (os.urandom == CSPRNG)."""
    return os.urandom(length)


def rand_u64() -> int:
    return int.from_bytes(rand_bytes(8), "little")


def xor_bytes(blinder: bytes, plaintext: bytes) -> bytes:
    if len(blinder) != len(plaintext):
        raise ValueError("Blinder and plaintext must be the same length")
    return bytes(b ^ p for b, p in zip(blinder, plaintext))


def concat_bytes(a: bytes, b: bytes) -> bytes:
    return a + b


def sha3_256(message: bytes) -> bytes:
    return hashlib.sha3_256(message).digest()


def sha3_512(message: bytes) -> bytes:
    return hashlib.sha3_512(message).digest()


class _KeyBlockDeriveInput:
    def __init__(self, seed: bytes, dst: bytes, target_length: int, block_index: int) -> None:
        self.seed = seed
        self.dst = dst
        self.target_length = target_length
        self.block_index = block_index

    def to_bytes(self) -> bytes:
        s = Serializer()
        s.serialize_bytes(self.seed)
        s.serialize_bytes(self.dst)
        s.serialize_u64(self.target_length)
        s.serialize_u64(self.block_index)
        return s.to_bytes()


def kdf(seed: bytes, dst: bytes, target_length: int) -> bytes:
    if len(seed) < 32:
        raise ValueError("Seed must be at least 32 bytes")
    block_pre_image = _KeyBlockDeriveInput(seed, dst, target_length, 0)
    output = b""
    remaining = target_length
    while remaining > 0:
        block_output = sha3_256(block_pre_image.to_bytes())[: min(32, remaining)]
        output += block_output
        remaining -= len(block_output)
        block_pre_image.block_index += 1
    return output


def hmac_sha3_256(key: bytes, message: bytes) -> bytes:
    if len(key) != 32:
        raise ValueError("Key must be 32 bytes")
    key = concat_bytes(key, bytes(32))
    ipad = bytes([0x36]) * 64
    opad = bytes([0x5C]) * 64
    inner_input = concat_bytes(xor_bytes(ipad, key), message)
    outer_input = concat_bytes(xor_bytes(opad, key), sha3_256(inner_input))
    return sha3_256(outer_input)
