# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""
ctypes bindings to libsodium's ristretto255 group, matching the byte encoding
used by @noble/curves' RistrettoPoint (which src/pke/group.ts wraps).

PyNaCl 1.6.2's bundled libsodium build does not export
crypto_core_ristretto255_*, so we bind directly against the system libsodium
(Homebrew on macOS: /opt/homebrew/lib/libsodium.dylib; apt on Linux:
libsodium.so.23 / libsodium.so). Verified byte-for-byte against
`@noble/curves/ed25519`'s RistrettoPoint for: hash-to-curve (64-byte input),
base-point scalar multiplication, identity encoding, and add/sub.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import os

RISTRETTO_BYTES = 32
SCALAR_BYTES = 32
HASH_BYTES = 64


def _load_libsodium() -> ctypes.CDLL:
    candidates = []
    env_path = os.environ.get("ACE_SDK_LIBSODIUM_PATH")
    if env_path:
        candidates.append(env_path)
    candidates += [
        "/opt/homebrew/lib/libsodium.dylib",
        "/usr/local/lib/libsodium.dylib",
        "libsodium.so.23",
        "libsodium.so",
        "libsodium.dylib",
    ]
    found = ctypes.util.find_library("sodium")
    if found:
        candidates.append(found)
    last_err: Exception | None = None
    for name in candidates:
        try:
            lib = ctypes.CDLL(name)
            if not hasattr(lib, "crypto_core_ristretto255_add"):
                continue
            return lib
        except OSError as e:  # pragma: no cover - platform dependent
            last_err = e
            continue
    raise RuntimeError(
        "Could not load a libsodium build exposing crypto_core_ristretto255_*. "
        "Install libsodium >= 1.0.18 (e.g. `brew install libsodium` on macOS, "
        "`apt install libsodium23` on Debian/Ubuntu), or set "
        "ACE_SDK_LIBSODIUM_PATH to its full path."
    ) from last_err


_lib = _load_libsodium()
_lib.sodium_init()

_lib.crypto_core_ristretto255_add.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_lib.crypto_core_ristretto255_sub.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_lib.crypto_core_ristretto255_from_hash.argtypes = [ctypes.c_char_p, ctypes.c_char_p]
_lib.crypto_core_ristretto255_is_valid_point.argtypes = [ctypes.c_char_p]
_lib.crypto_scalarmult_ristretto255.argtypes = [
    ctypes.c_char_p,
    ctypes.c_char_p,
    ctypes.c_char_p,
]
_lib.crypto_scalarmult_ristretto255_base.argtypes = [ctypes.c_char_p, ctypes.c_char_p]


def is_valid_point(point: bytes) -> bool:
    if len(point) != RISTRETTO_BYTES:
        return False
    return _lib.crypto_core_ristretto255_is_valid_point(point) == 1


def group_identity() -> bytes:
    return bytes(RISTRETTO_BYTES)


def from_hash(h: bytes) -> bytes:
    """Maps a 64-byte uniform hash to a ristretto255 point (hash-to-curve)."""
    if len(h) != HASH_BYTES:
        raise ValueError("hash must be 64 bytes")
    out = ctypes.create_string_buffer(RISTRETTO_BYTES)
    _lib.crypto_core_ristretto255_from_hash(out, h)
    return out.raw


def point_add(a: bytes, b: bytes) -> bytes:
    if a == group_identity():
        return b
    if b == group_identity():
        return a
    out = ctypes.create_string_buffer(RISTRETTO_BYTES)
    ret = _lib.crypto_core_ristretto255_add(out, a, b)
    if ret != 0:
        raise ValueError("ristretto255 point addition failed (invalid point)")
    return out.raw


def point_sub(a: bytes, b: bytes) -> bytes:
    if b == group_identity():
        return a
    out = ctypes.create_string_buffer(RISTRETTO_BYTES)
    ret = _lib.crypto_core_ristretto255_sub(out, a, b)
    if ret != 0:
        raise ValueError("ristretto255 point subtraction failed (invalid point)")
    return out.raw


def scalarmult(scalar_le: bytes, point: bytes) -> bytes:
    """scalar * point. libsodium requires the scalar be reduced mod the group
    order; ACE's Scalar type always keeps values reduced mod Q, matching
    @noble/curves' RistrettoPoint#multiply."""
    if len(scalar_le) != SCALAR_BYTES:
        raise ValueError("scalar must be 32 bytes")
    out = ctypes.create_string_buffer(RISTRETTO_BYTES)
    ret = _lib.crypto_scalarmult_ristretto255(out, scalar_le, point)
    if ret != 0:
        raise ValueError("ristretto255 scalar multiplication failed")
    return out.raw


def scalarmult_base(scalar_le: bytes) -> bytes:
    if len(scalar_le) != SCALAR_BYTES:
        raise ValueError("scalar must be 32 bytes")
    out = ctypes.create_string_buffer(RISTRETTO_BYTES)
    ret = _lib.crypto_scalarmult_ristretto255_base(out, scalar_le)
    if ret != 0:
        raise ValueError("ristretto255 base scalar multiplication failed")
    return out.raw
