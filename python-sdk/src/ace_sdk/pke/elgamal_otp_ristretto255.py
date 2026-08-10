# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Mirrors src/pke/elgamal_otp_ristretto255.ts: ElGamal-encrypted OTP key + HMAC."""

from __future__ import annotations

from ace_sdk.bcs import Deserializer, Serializer
from ace_sdk.pke import elgamal as ElGamal
from ace_sdk.pke import group as Group
from ace_sdk.result import Result
from ace_sdk.utils import hmac_sha3_256, kdf, xor_bytes


def _assert_consumed(d: Deserializer, label: str) -> None:
    if d.remaining() != 0:
        raise ValueError(f"{label}: trailing bytes")


def _hex_string_to_bytes(hex_str: str) -> bytes:
    h = hex_str.strip()
    if h.startswith("0x") or h.startswith("0X"):
        h = h[2:]
    return bytes.fromhex(h)


class EncryptionKey:
    def __init__(self, elgamal_ek: ElGamal.EncKey) -> None:
        self.elgamal_ek = elgamal_ek

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["EncryptionKey"]:
        def task(_extra: dict) -> "EncryptionKey":
            elgamal_ek = ElGamal.EncKey.decode(deserializer)
            return EncryptionKey(elgamal_ek)

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        self.elgamal_ek.encode(serializer)

    def to_bytes(self) -> bytes:
        s = Serializer()
        self.serialize(s)
        return s.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> Result["EncryptionKey"]:
        def task(_extra: dict) -> "EncryptionKey":
            d = Deserializer(data)
            obj = EncryptionKey.deserialize(d).unwrap_or_throw(
                ValueError("EncryptionKey.fromBytes")
            )
            _assert_consumed(d, "EncryptionKey.fromBytes")
            return obj

        return Result.capture(task)

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @staticmethod
    def from_hex(hex_str: str) -> Result["EncryptionKey"]:
        def task(_extra: dict) -> "EncryptionKey":
            return EncryptionKey.from_bytes(_hex_string_to_bytes(hex_str)).unwrap_or_throw(
                ValueError("EncryptionKey.fromHex")
            )

        return Result.capture(task)


class DecryptionKey:
    def __init__(self, elgamal_dk: ElGamal.DecKey) -> None:
        self.elgamal_dk = elgamal_dk

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["DecryptionKey"]:
        def task(_extra: dict) -> "DecryptionKey":
            elgamal_dk = ElGamal.DecKey.decode(deserializer)
            return DecryptionKey(elgamal_dk)

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        self.elgamal_dk.encode(serializer)

    def to_bytes(self) -> bytes:
        s = Serializer()
        self.serialize(s)
        return s.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> Result["DecryptionKey"]:
        def task(_extra: dict) -> "DecryptionKey":
            d = Deserializer(data)
            obj = DecryptionKey.deserialize(d).unwrap_or_throw(
                ValueError("DecryptionKey.fromBytes")
            )
            _assert_consumed(d, "DecryptionKey.fromBytes")
            return obj

        return Result.capture(task)

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @staticmethod
    def from_hex(hex_str: str) -> Result["DecryptionKey"]:
        def task(_extra: dict) -> "DecryptionKey":
            return DecryptionKey.from_bytes(_hex_string_to_bytes(hex_str)).unwrap_or_throw(
                ValueError("DecryptionKey.fromHex")
            )

        return Result.capture(task)


class Ciphertext:
    def __init__(
        self, elgamal_ciph: ElGamal.Ciphertext, symmetric_ciph: bytes, mac: bytes
    ) -> None:
        self.elgamal_ciph = elgamal_ciph
        self.symmetric_ciph = symmetric_ciph
        self.mac = mac

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["Ciphertext"]:
        def task(_extra: dict) -> "Ciphertext":
            elgamal_ciph = ElGamal.Ciphertext.decode(deserializer)
            symmetric_ciph = deserializer.deserialize_bytes()
            mac = deserializer.deserialize_bytes()
            return Ciphertext(elgamal_ciph, symmetric_ciph, mac)

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        self.elgamal_ciph.encode(serializer)
        serializer.serialize_bytes(self.symmetric_ciph)
        serializer.serialize_bytes(self.mac)

    def to_bytes(self) -> bytes:
        s = Serializer()
        self.serialize(s)
        return s.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> Result["Ciphertext"]:
        def task(_extra: dict) -> "Ciphertext":
            d = Deserializer(data)
            obj = Ciphertext.deserialize(d).unwrap_or_throw(ValueError("Ciphertext.fromBytes"))
            _assert_consumed(d, "Ciphertext.fromBytes")
            return obj

        return Result.capture(task)

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @staticmethod
    def from_hex(hex_str: str) -> Result["Ciphertext"]:
        def task(_extra: dict) -> "Ciphertext":
            return Ciphertext.from_bytes(_hex_string_to_bytes(hex_str)).unwrap_or_throw(
                ValueError("Ciphertext.fromHex")
            )

        return Result.capture(task)


def keygen() -> DecryptionKey:
    enc_base = Group.Element.rand()
    private_scalar = Group.Scalar.rand()
    elgamal_dk = ElGamal.DecKey(enc_base, private_scalar)
    return DecryptionKey(elgamal_dk)


def derive_encryption_key(dk: DecryptionKey) -> EncryptionKey:
    elgamal_dk = dk.elgamal_dk
    enc_base = elgamal_dk.enc_base
    private_scalar = elgamal_dk.private_scalar
    public_point = enc_base.scale(private_scalar)
    elgamal_ek = ElGamal.EncKey(enc_base, public_point)
    return EncryptionKey(elgamal_ek)


def encrypt(encryption_key: EncryptionKey, plaintext: bytes) -> Ciphertext:
    elgamal_ek = encryption_key.elgamal_ek
    elgamal_ptxt = Group.Element.rand()
    elgamal_rand = Group.Scalar.rand()
    elgamal_ciph = ElGamal.enc(elgamal_ek, elgamal_rand, elgamal_ptxt)
    seed = elgamal_ptxt.to_bytes()
    otp = kdf(seed, b"OTP/ELGAMAL_OTP_RISTRETTO255", len(plaintext))
    symmetric_ciph = xor_bytes(otp, plaintext)
    hmac_key = kdf(seed, b"HMAC/ELGAMAL_OTP_RISTRETTO255", 32)
    mac = hmac_sha3_256(hmac_key, symmetric_ciph)
    return Ciphertext(elgamal_ciph, symmetric_ciph, mac)


def decrypt(dk: DecryptionKey, ciphertext: Ciphertext) -> Result[bytes]:
    def task(_extra: dict) -> bytes:
        elgamal_ptxt = ElGamal.dec(dk.elgamal_dk, ciphertext.elgamal_ciph)
        seed = elgamal_ptxt.to_bytes()  # BCS-encoded, same as encrypt
        otp = kdf(
            seed,
            b"OTP/ELGAMAL_OTP_RISTRETTO255",
            len(ciphertext.symmetric_ciph),
        )
        hmac_key = kdf(seed, b"HMAC/ELGAMAL_OTP_RISTRETTO255", 32)
        expected_mac = hmac_sha3_256(hmac_key, ciphertext.symmetric_ciph)
        # Timing-safe MAC comparison
        if len(expected_mac) != len(ciphertext.mac):
            raise ValueError("MAC verification failed")
        diff = 0
        for a, b in zip(expected_mac, ciphertext.mac):
            diff |= a ^ b
        if diff != 0:
            raise ValueError("MAC verification failed")
        return xor_bytes(otp, ciphertext.symmetric_ciph)

    return Result.capture(task)
