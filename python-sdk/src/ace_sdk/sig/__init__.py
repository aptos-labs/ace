# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Generic, scheme-tagged signature helpers. Mirrors ts-sdk/src/sig."""

from __future__ import annotations

import os

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey as _Ed25519SigningKey
from nacl.signing import VerifyKey as _Ed25519VerifyKey

from ace_sdk.bcs import Deserializer, Serializer
from ace_sdk.result import Result

SCHEME_ED25519 = 0


def _hex_string_to_bytes(hex_str: str) -> bytes:
    h = hex_str.strip()
    if h.startswith("0x") or h.startswith("0X"):
        h = h[2:]
    return bytes.fromhex(h)


def _assert_consumed(d: Deserializer, label: str) -> None:
    if d.remaining() != 0:
        raise ValueError(f"{label}: trailing bytes after deserialization")


def _assert_byte_length(data: bytes, expected: int, label: str) -> None:
    if len(data) != expected:
        raise ValueError(f"{label} must be {expected} bytes, got {len(data)}")


class PublicKey:
    def __init__(self, scheme: int, bytes_: bytes) -> None:
        if scheme != SCHEME_ED25519:
            raise ValueError(f"unsupported sig public key scheme {scheme}")
        self.scheme = scheme
        self.bytes = bytes(bytes_)
        _assert_byte_length(self.bytes, 32, "Ed25519 public key")

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u32_as_uleb128(self.scheme)
        serializer.serialize_bytes(self.bytes)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    def verify(self, message: bytes, signature: "Signature") -> bool:
        if signature.scheme != self.scheme:
            return False
        try:
            _Ed25519VerifyKey(self.bytes).verify(bytes(message), signature.bytes)
        except BadSignatureError:
            return False
        return True

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["PublicKey"]:
        def task(_extra: dict) -> "PublicKey":
            scheme = deserializer.deserialize_uleb128_as_u32()
            if scheme != SCHEME_ED25519:
                raise ValueError(f"unsupported sig public key scheme {scheme}")
            return PublicKey(scheme, deserializer.deserialize_bytes())

        return Result.capture(task)

    @staticmethod
    def from_bytes(data: bytes) -> Result["PublicKey"]:
        def task(_extra: dict) -> "PublicKey":
            deserializer = Deserializer(data)
            public_key = PublicKey.deserialize(deserializer).unwrap_or_throw(
                ValueError("PublicKey.from_bytes")
            )
            _assert_consumed(deserializer, "PublicKey.from_bytes")
            return public_key

        return Result.capture(task)

    @staticmethod
    def from_hex(hex_str: str) -> Result["PublicKey"]:
        return PublicKey.from_bytes(_hex_string_to_bytes(hex_str))


class Signature:
    def __init__(self, scheme: int, bytes_: bytes) -> None:
        if scheme != SCHEME_ED25519:
            raise ValueError(f"unsupported sig signature scheme {scheme}")
        self.scheme = scheme
        self.bytes = bytes(bytes_)
        _assert_byte_length(self.bytes, 64, "Ed25519 signature")

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u32_as_uleb128(self.scheme)
        serializer.serialize_bytes(self.bytes)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["Signature"]:
        def task(_extra: dict) -> "Signature":
            scheme = deserializer.deserialize_uleb128_as_u32()
            if scheme != SCHEME_ED25519:
                raise ValueError(f"unsupported sig signature scheme {scheme}")
            return Signature(scheme, deserializer.deserialize_bytes())

        return Result.capture(task)

    @staticmethod
    def from_bytes(data: bytes) -> Result["Signature"]:
        def task(_extra: dict) -> "Signature":
            deserializer = Deserializer(data)
            signature = Signature.deserialize(deserializer).unwrap_or_throw(
                ValueError("Signature.from_bytes")
            )
            _assert_consumed(deserializer, "Signature.from_bytes")
            return signature

        return Result.capture(task)

    @staticmethod
    def from_hex(hex_str: str) -> Result["Signature"]:
        return Signature.from_bytes(_hex_string_to_bytes(hex_str))


class SigningKey:
    def __init__(self, scheme: int, bytes_: bytes) -> None:
        if scheme != SCHEME_ED25519:
            raise ValueError(f"unsupported sig signing key scheme {scheme}")
        self.scheme = scheme
        self.bytes = bytes(bytes_)
        _assert_byte_length(self.bytes, 32, "Ed25519 signing key")

    def public_key(self) -> PublicKey:
        return PublicKey(self.scheme, bytes(_Ed25519SigningKey(self.bytes).verify_key))

    def sign(self, message: bytes) -> Signature:
        signed = _Ed25519SigningKey(self.bytes).sign(bytes(message))
        return Signature(self.scheme, signed.signature)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u32_as_uleb128(self.scheme)
        serializer.serialize_bytes(self.bytes)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["SigningKey"]:
        def task(_extra: dict) -> "SigningKey":
            scheme = deserializer.deserialize_uleb128_as_u32()
            if scheme != SCHEME_ED25519:
                raise ValueError(f"unsupported sig signing key scheme {scheme}")
            return SigningKey(scheme, deserializer.deserialize_bytes())

        return Result.capture(task)

    @staticmethod
    def from_bytes(data: bytes) -> Result["SigningKey"]:
        def task(_extra: dict) -> "SigningKey":
            deserializer = Deserializer(data)
            signing_key = SigningKey.deserialize(deserializer).unwrap_or_throw(
                ValueError("SigningKey.from_bytes")
            )
            _assert_consumed(deserializer, "SigningKey.from_bytes")
            return signing_key

        return Result.capture(task)

    @staticmethod
    def from_hex(hex_str: str) -> Result["SigningKey"]:
        return SigningKey.from_bytes(_hex_string_to_bytes(hex_str))

    @staticmethod
    def random(scheme: int = SCHEME_ED25519) -> "SigningKey":
        if scheme != SCHEME_ED25519:
            raise ValueError(f"unsupported sig signing key scheme {scheme}")
        return SigningKey(scheme, os.urandom(32))


def keygen(scheme: int = SCHEME_ED25519) -> tuple[PublicKey, SigningKey]:
    if scheme == SCHEME_ED25519:
        signing_key = SigningKey.random(scheme)
        return signing_key.public_key(), signing_key
    raise ValueError(f"keygen: unknown signature scheme {scheme}")


def verify(message: bytes, signature: Signature, public_key: PublicKey) -> bool:
    return public_key.verify(message, signature)


__all__ = [
    "SCHEME_ED25519",
    "PublicKey",
    "Signature",
    "SigningKey",
    "keygen",
    "verify",
]
