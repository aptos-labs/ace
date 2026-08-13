# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""
Mirrors src/pke/index.ts: scheme-dispatching abstract PKE wrapper over
ElGamalOtpRistretto255 and HpkeX25519ChaCha20Poly1305.

Note: ts-sdk's keygen/encrypt/decrypt are async (HPKE/WebCrypto heritage);
pyhpke's API is fully synchronous so the Python port drops the async/await
and Promise wrapping but is otherwise a direct 1:1 port. Call sites should
just call these functions directly (no `await`/asyncio needed).
"""

from __future__ import annotations

from ace_sdk.bcs import Deserializer, Serializer
from ace_sdk.pke import elgamal_otp_ristretto255 as ElGamalOtpRistretto255
from ace_sdk.pke import hpke_x25519_chacha20poly1305 as HpkeX25519ChaCha20Poly1305
from ace_sdk.result import Result

SCHEME_ELGAMAL_OTP_RISTRETTO255 = 0
SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305 = 1


def _hex_string_to_bytes(hex_str: str) -> bytes:
    h = hex_str.strip()
    if h.startswith("0x") or h.startswith("0X"):
        h = h[2:]
    return bytes.fromhex(h)


def _assert_consumed(d: Deserializer, label: str) -> None:
    if d.remaining() != 0:
        raise ValueError(f"{label}: trailing bytes after deserialization")


class EncryptionKey:
    def __init__(self, scheme: int, inner) -> None:
        self.scheme = scheme
        self.inner = inner

    def derive_from_decryption_key(self, decryption_key: "DecryptionKey") -> "EncryptionKey":
        return derive_encryption_key(decryption_key)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["EncryptionKey"]:
        def task(_extra: dict) -> "EncryptionKey":
            scheme = deserializer.deserialize_u8()
            if scheme == SCHEME_ELGAMAL_OTP_RISTRETTO255:
                inner = ElGamalOtpRistretto255.EncryptionKey.deserialize(
                    deserializer
                ).unwrap_or_throw(ValueError("EncryptionKey.deserialize: ElGamal"))
                return EncryptionKey(scheme, inner)
            if scheme == SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305:
                inner = HpkeX25519ChaCha20Poly1305.EncryptionKey.deserialize(
                    deserializer
                ).unwrap_or_throw(ValueError("EncryptionKey.deserialize: HPKE-X25519"))
                return EncryptionKey(scheme, inner)
            raise ValueError(f"Unknown PKE scheme: {scheme}")

        return Result.capture(task)

    @staticmethod
    def from_bytes(data: bytes) -> Result["EncryptionKey"]:
        def task(_extra: dict) -> "EncryptionKey":
            deserializer = Deserializer(data)
            key = EncryptionKey.deserialize(deserializer).unwrap_or_throw(
                ValueError("EncryptionKey.fromBytes")
            )
            _assert_consumed(deserializer, "EncryptionKey.fromBytes")
            return key

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u8(self.scheme)
        self.inner.serialize(serializer)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

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
    def __init__(self, scheme: int, inner) -> None:
        self.scheme = scheme
        self.inner = inner

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["DecryptionKey"]:
        def task(_extra: dict) -> "DecryptionKey":
            scheme = deserializer.deserialize_u8()
            if scheme == SCHEME_ELGAMAL_OTP_RISTRETTO255:
                inner = ElGamalOtpRistretto255.DecryptionKey.deserialize(
                    deserializer
                ).unwrap_or_throw(ValueError("DecryptionKey.deserialize: ElGamal"))
                return DecryptionKey(scheme, inner)
            if scheme == SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305:
                inner = HpkeX25519ChaCha20Poly1305.DecryptionKey.deserialize(
                    deserializer
                ).unwrap_or_throw(ValueError("DecryptionKey.deserialize: HPKE-X25519"))
                return DecryptionKey(scheme, inner)
            raise ValueError(f"Unknown PKE scheme: {scheme}")

        return Result.capture(task)

    @staticmethod
    def from_bytes(data: bytes) -> Result["DecryptionKey"]:
        def task(_extra: dict) -> "DecryptionKey":
            deserializer = Deserializer(data)
            key = DecryptionKey.deserialize(deserializer).unwrap_or_throw(
                ValueError("DecryptionKey.fromBytes")
            )
            _assert_consumed(deserializer, "DecryptionKey.fromBytes")
            return key

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u8(self.scheme)
        self.inner.serialize(serializer)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

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
    def __init__(self, scheme: int, inner) -> None:
        self.scheme = scheme
        self.inner = inner

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["Ciphertext"]:
        def task(_extra: dict) -> "Ciphertext":
            scheme = deserializer.deserialize_u8()
            if scheme == SCHEME_ELGAMAL_OTP_RISTRETTO255:
                inner = ElGamalOtpRistretto255.Ciphertext.deserialize(
                    deserializer
                ).unwrap_or_throw(ValueError("Ciphertext.deserialize: ElGamal"))
                return Ciphertext(scheme, inner)
            if scheme == SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305:
                inner = HpkeX25519ChaCha20Poly1305.Ciphertext.deserialize(
                    deserializer
                ).unwrap_or_throw(ValueError("Ciphertext.deserialize: HPKE-X25519"))
                return Ciphertext(scheme, inner)
            raise ValueError(f"Unknown PKE scheme: {scheme}")

        return Result.capture(task)

    @staticmethod
    def from_bytes(data: bytes) -> Result["Ciphertext"]:
        def task(_extra: dict) -> "Ciphertext":
            deserializer = Deserializer(data)
            ciph = Ciphertext.deserialize(deserializer).unwrap_or_throw(
                ValueError("Ciphertext.fromBytes")
            )
            _assert_consumed(deserializer, "Ciphertext.fromBytes")
            return ciph

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u8(self.scheme)
        self.inner.serialize(serializer)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()

    @staticmethod
    def from_hex(hex_str: str) -> Result["Ciphertext"]:
        def task(_extra: dict) -> "Ciphertext":
            return Ciphertext.from_bytes(_hex_string_to_bytes(hex_str)).unwrap_or_throw(
                ValueError("Ciphertext.fromHex")
            )

        return Result.capture(task)


def derive_encryption_key(decryption_key: DecryptionKey) -> EncryptionKey:
    """Derive the encryption (public) key from a decryption (private) key."""
    if decryption_key.scheme == SCHEME_ELGAMAL_OTP_RISTRETTO255:
        ek = ElGamalOtpRistretto255.derive_encryption_key(decryption_key.inner)
        return EncryptionKey(decryption_key.scheme, ek)
    if decryption_key.scheme == SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305:
        ek = HpkeX25519ChaCha20Poly1305.derive_encryption_key(decryption_key.inner)
        return EncryptionKey(decryption_key.scheme, ek)
    raise ValueError(f"deriveEncryptionKey: unknown scheme {decryption_key.scheme}")


def keygen(
    scheme: int = SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305,
) -> tuple[EncryptionKey, DecryptionKey]:
    """Generate a fresh PKE keypair. Defaults to HPKE-X25519-HKDF-SHA256-ChaCha20-Poly1305
    (RFC 9180 base mode). The legacy ElGamalOtpRistretto255 scheme is still supported by
    passing SCHEME_ELGAMAL_OTP_RISTRETTO255 explicitly.

    Returns (encryption_key, decryption_key) to match Python tuple-unpacking idiom; ts-sdk
    returns { encryptionKey, decryptionKey }."""
    if scheme == SCHEME_ELGAMAL_OTP_RISTRETTO255:
        dk_inner = ElGamalOtpRistretto255.keygen()
        ek_inner = ElGamalOtpRistretto255.derive_encryption_key(dk_inner)
        return (
            EncryptionKey(scheme, ek_inner),
            DecryptionKey(scheme, dk_inner),
        )
    if scheme == SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305:
        ek_inner, dk_inner = HpkeX25519ChaCha20Poly1305.keygen()
        return (
            EncryptionKey(scheme, ek_inner),
            DecryptionKey(scheme, dk_inner),
        )
    raise ValueError(f"keygen: unknown scheme {scheme}")


def encrypt(encryption_key: EncryptionKey, plaintext: bytes) -> Ciphertext:
    if encryption_key.scheme == SCHEME_ELGAMAL_OTP_RISTRETTO255:
        ct = ElGamalOtpRistretto255.encrypt(encryption_key.inner, plaintext)
        return Ciphertext(encryption_key.scheme, ct)
    if encryption_key.scheme == SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305:
        ct = HpkeX25519ChaCha20Poly1305.encrypt(encryption_key.inner, plaintext)
        return Ciphertext(encryption_key.scheme, ct)
    raise ValueError(f"encrypt: unknown scheme {encryption_key.scheme}")


def decrypt(decryption_key: DecryptionKey, ciphertext: Ciphertext) -> Result[bytes]:
    def task(extra: dict) -> bytes:
        extra["dk_scheme"] = decryption_key.scheme
        extra["ciph_scheme"] = ciphertext.scheme
        if decryption_key.scheme != ciphertext.scheme:
            raise ValueError(
                f"decrypt: scheme mismatch (dk={decryption_key.scheme}, "
                f"ct={ciphertext.scheme})"
            )
        if decryption_key.scheme == SCHEME_ELGAMAL_OTP_RISTRETTO255:
            return ElGamalOtpRistretto255.decrypt(
                decryption_key.inner, ciphertext.inner
            ).unwrap_or_throw(ValueError("ElGamalOtpRistretto255.decrypt failed"))
        if decryption_key.scheme == SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305:
            return HpkeX25519ChaCha20Poly1305.decrypt(
                decryption_key.inner, ciphertext.inner
            ).unwrap_or_throw(ValueError("HPKE-X25519.decrypt failed"))
        raise ValueError(f"decrypt: unknown scheme {decryption_key.scheme}")

    return Result.capture(task)
