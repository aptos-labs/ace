# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Mirrors src/_internal/aptos.ts.

Only BCS wire-format (serialize/deserialize) is implemented for every Aptos
public-key/signature scheme: actual signature *verification* happens
server-side (Move contract / worker), never in this SDK, so we do not need
real crypto verification logic here -- just byte-exact encode/decode for
every variant a wallet might produce (Ed25519, AnyPublicKey/SingleKey
[Secp256k1, Secp256r1, Keyless, FederatedKeyless], MultiEd25519, MultiKey,
Keyless, FederatedKeyless).
"""

from __future__ import annotations

from aptos_sdk.account_address import AccountAddress

from ace_sdk.bcs import (
    Deserializer,
    Serializer,
    deserialize_account_address,
    deserialize_option,
    deserialize_option_str,
    deserialize_vector,
    serialize_account_address,
    serialize_option,
    serialize_vector,
)
from ace_sdk.result import Result

# == Ed25519 ===================================================================


class Ed25519PublicKey:
    LENGTH = 32

    def __init__(self, key: bytes) -> None:
        if len(key) != self.LENGTH:
            raise ValueError(f"Ed25519PublicKey length should be {self.LENGTH}")
        self.key = key

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(self.key)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "Ed25519PublicKey":
        return Ed25519PublicKey(deserializer.deserialize_bytes())


class Ed25519Signature:
    LENGTH = 64

    def __init__(self, data: bytes) -> None:
        if len(data) != self.LENGTH:
            raise ValueError(f"Ed25519Signature length should be {self.LENGTH}")
        self.data = data

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(self.data)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "Ed25519Signature":
        return Ed25519Signature(deserializer.deserialize_bytes())


# == Secp256k1 ==================================================================


class Secp256k1PublicKey:
    LENGTH = 65
    COMPRESSED_LENGTH = 33

    def __init__(self, key: bytes) -> None:
        if len(key) == self.LENGTH:
            self.key = key
        elif len(key) == self.COMPRESSED_LENGTH:
            import ecdsa

            point = ecdsa.VerifyingKey.from_string(key, curve=ecdsa.SECP256k1).pubkey.point
            x = point.x().to_bytes(32, "big")
            y = point.y().to_bytes(32, "big")
            self.key = b"\x04" + x + y
        else:
            raise ValueError(
                f"Secp256k1PublicKey length should be {self.LENGTH} or "
                f"{self.COMPRESSED_LENGTH}, received {len(key)}"
            )

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(self.key)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "Secp256k1PublicKey":
        return Secp256k1PublicKey(deserializer.deserialize_bytes())


class Secp256k1Signature:
    LENGTH = 64

    def __init__(self, data: bytes) -> None:
        if len(data) != self.LENGTH:
            raise ValueError(f"Secp256k1Signature length should be {self.LENGTH}")
        self.data = data

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(self.data)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "Secp256k1Signature":
        return Secp256k1Signature(deserializer.deserialize_bytes())


# == Secp256r1 (WebAuthn / passkeys) ============================================


class Secp256r1PublicKey:
    LENGTH = 65
    COMPRESSED_LENGTH = 33

    def __init__(self, key: bytes) -> None:
        if len(key) == self.COMPRESSED_LENGTH:
            import ecdsa

            point = ecdsa.VerifyingKey.from_string(key, curve=ecdsa.NIST256p).pubkey.point
            x = point.x().to_bytes(32, "big")
            y = point.y().to_bytes(32, "big")
            self.key = b"\x04" + x + y
        elif len(key) == self.LENGTH:
            self.key = key
        else:
            raise ValueError(
                f"Secp256r1PublicKey length should be {self.LENGTH} or "
                f"{self.COMPRESSED_LENGTH}, received {len(key)}"
            )

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(self.key)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "Secp256r1PublicKey":
        return Secp256r1PublicKey(deserializer.deserialize_bytes())


class Secp256r1Signature:
    LENGTH = 64

    def __init__(self, data: bytes) -> None:
        if len(data) != self.LENGTH:
            raise ValueError(f"Secp256r1Signature length should be {self.LENGTH}")
        self.data = data

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(self.data)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "Secp256r1Signature":
        return Secp256r1Signature(deserializer.deserialize_bytes())


class WebAuthnSignature:
    def __init__(
        self, signature: bytes, authenticator_data: bytes, client_data_json: bytes
    ) -> None:
        self.signature = signature
        self.authenticator_data = authenticator_data
        self.client_data_json = client_data_json

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u32_as_uleb128(0)
        serializer.serialize_bytes(self.signature)
        serializer.serialize_bytes(self.authenticator_data)
        serializer.serialize_bytes(self.client_data_json)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "WebAuthnSignature":
        variant_id = deserializer.deserialize_uleb128_as_u32()
        if variant_id != 0:
            raise ValueError(f"Invalid id for WebAuthnSignature: {variant_id}")
        signature = deserializer.deserialize_bytes()
        authenticator_data = deserializer.deserialize_bytes()
        client_data_json = deserializer.deserialize_bytes()
        return WebAuthnSignature(signature, authenticator_data, client_data_json)


# == MultiEd25519 ================================================================


class MultiEd25519PublicKey:
    MAX_KEYS = 32
    MIN_KEYS = 2
    MIN_THRESHOLD = 1

    def __init__(self, public_keys: list[Ed25519PublicKey], threshold: int) -> None:
        if not (self.MIN_KEYS <= len(public_keys) <= self.MAX_KEYS):
            raise ValueError(
                f"Must have between {self.MIN_KEYS} and {self.MAX_KEYS} public keys"
            )
        if not (self.MIN_THRESHOLD <= threshold <= len(public_keys)):
            raise ValueError(f"Threshold must be between {self.MIN_THRESHOLD} and {len(public_keys)}")
        self.public_keys = public_keys
        self.threshold = threshold

    def to_bytes_inner(self) -> bytes:
        out = bytearray()
        for k in self.public_keys:
            out += k.key
        out.append(self.threshold)
        return bytes(out)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(self.to_bytes_inner())

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "MultiEd25519PublicKey":
        data = deserializer.deserialize_bytes()
        threshold = data[-1]
        keys: list[Ed25519PublicKey] = []
        i = 0
        while i < len(data) - 1:
            keys.append(Ed25519PublicKey(data[i : i + Ed25519PublicKey.LENGTH]))
            i += Ed25519PublicKey.LENGTH
        return MultiEd25519PublicKey(keys, threshold)


class MultiEd25519Signature:
    def __init__(self, signatures: list[Ed25519Signature], bitmap: bytes) -> None:
        self.signatures = signatures
        self.bitmap = bitmap

    def to_bytes_inner(self) -> bytes:
        out = bytearray()
        for s in self.signatures:
            out += s.data
        out += self.bitmap
        return bytes(out)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(self.to_bytes_inner())

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "MultiEd25519Signature":
        data = deserializer.deserialize_bytes()
        bitmap = data[-4:]
        signatures: list[Ed25519Signature] = []
        i = 0
        end = len(data) - len(bitmap)
        while i < end:
            signatures.append(Ed25519Signature(data[i : i + Ed25519Signature.LENGTH]))
            i += Ed25519Signature.LENGTH
        return MultiEd25519Signature(signatures, bitmap)


# == Ephemeral (used inside Keyless) ============================================


class EphemeralPublicKey:
    """Only Ed25519 variant exists today (EphemeralPublicKeyVariant.Ed25519 = 0)."""

    VARIANT_ED25519 = 0

    def __init__(self, public_key: Ed25519PublicKey) -> None:
        if not isinstance(public_key, Ed25519PublicKey):
            raise ValueError(f"Unsupported key for EphemeralPublicKey - {type(public_key)}")
        self.public_key = public_key
        self.variant = self.VARIANT_ED25519

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u32_as_uleb128(self.VARIANT_ED25519)
        self.public_key.serialize(serializer)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "EphemeralPublicKey":
        index = deserializer.deserialize_uleb128_as_u32()
        if index == EphemeralPublicKey.VARIANT_ED25519:
            return EphemeralPublicKey(Ed25519PublicKey.deserialize(deserializer))
        raise ValueError(f"Unknown variant index for EphemeralPublicKey: {index}")


class EphemeralSignature:
    VARIANT_ED25519 = 0

    def __init__(self, signature: Ed25519Signature) -> None:
        if not isinstance(signature, Ed25519Signature):
            raise ValueError(f"Unsupported signature for EphemeralSignature - {type(signature)}")
        self.signature = signature

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u32_as_uleb128(self.VARIANT_ED25519)
        self.signature.serialize(serializer)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> "EphemeralSignature":
        index = deserializer.deserialize_uleb128_as_u32()
        if index == EphemeralSignature.VARIANT_ED25519:
            return EphemeralSignature(Ed25519Signature.deserialize(deserializer))
        raise ValueError(f"Unknown variant index for EphemeralSignature: {index}")
