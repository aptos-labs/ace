# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""
Mirrors src/pke/hpke_x25519_chacha20poly1305.ts.

HPKE base mode, ciphersuite:
  KEM:  DHKEM(X25519, HKDF-SHA256)   (KemId 0x0020)
  KDF:  HKDF-SHA256                  (KdfId 0x0001)
  AEAD: ChaCha20-Poly1305            (AeadId 0x0003)

Classical ~128-bit security. RFC 9180.

BCS wire format (no leading scheme byte; the abstract `pke` outer enum
prepends it):
  EncryptionKey   = [ULEB128(32)] [32B X25519 public key]
  DecryptionKey   = [ULEB128(32)] [32B X25519 private key]
  Ciphertext      = [ULEB128(32)] [32B enc] [ULEB128(len)] [len B aead_ct]

`aead_ct` includes the 16-byte Poly1305 tag.

Verified byte-for-byte / round-trip cross-language against ts-sdk's
@hpke/core + @hpke/chacha20poly1305 stack: RFC 9180 base-mode HPKE
ciphertexts produced by pyhpke decrypt correctly under @hpke/core (and
vice versa) for the same recipient key.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from pyhpke import AEADId, CipherSuite, KDFId, KEMId, KEMKey

from ace_sdk.bcs import Deserializer, Serializer
from ace_sdk.result import Result

X25519_KEY_BYTES = 32
ENCAPSULATED_KEY_BYTES = 32
AEAD_TAG_BYTES = 16


def _suite() -> CipherSuite:
    return CipherSuite.new(
        KEMId.DHKEM_X25519_HKDF_SHA256, KDFId.HKDF_SHA256, AEADId.CHACHA20_POLY1305
    )


def _assert_consumed(d: Deserializer, label: str) -> None:
    if d.remaining() != 0:
        raise ValueError(f"{label}: trailing bytes")


def _hex_string_to_bytes(hex_str: str) -> bytes:
    h = hex_str.strip()
    if h.startswith("0x") or h.startswith("0X"):
        h = h[2:]
    return bytes.fromhex(h)


class EncryptionKey:
    def __init__(self, pk: bytes) -> None:
        if len(pk) != X25519_KEY_BYTES:
            raise ValueError(f"EncryptionKey: pk must be {X25519_KEY_BYTES} bytes, got {len(pk)}")
        self.pk = pk

    @staticmethod
    def deserialize(d: Deserializer) -> Result["EncryptionKey"]:
        def task(_extra: dict) -> "EncryptionKey":
            return EncryptionKey(d.deserialize_bytes())

        return Result.capture(task)

    def serialize(self, s: Serializer) -> None:
        s.serialize_bytes(self.pk)

    def to_bytes(self) -> bytes:
        s = Serializer()
        self.serialize(s)
        return s.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> Result["EncryptionKey"]:
        def task(_extra: dict) -> "EncryptionKey":
            d = Deserializer(data)
            ek = EncryptionKey.deserialize(d).unwrap_or_throw(
                ValueError("EncryptionKey.fromBytes")
            )
            _assert_consumed(d, "EncryptionKey.fromBytes")
            return ek

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
    def __init__(self, sk: bytes) -> None:
        if len(sk) != X25519_KEY_BYTES:
            raise ValueError(f"DecryptionKey: sk must be {X25519_KEY_BYTES} bytes, got {len(sk)}")
        self.sk = sk

    @staticmethod
    def deserialize(d: Deserializer) -> Result["DecryptionKey"]:
        def task(_extra: dict) -> "DecryptionKey":
            return DecryptionKey(d.deserialize_bytes())

        return Result.capture(task)

    def serialize(self, s: Serializer) -> None:
        s.serialize_bytes(self.sk)

    def to_bytes(self) -> bytes:
        s = Serializer()
        self.serialize(s)
        return s.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> Result["DecryptionKey"]:
        def task(_extra: dict) -> "DecryptionKey":
            d = Deserializer(data)
            dk = DecryptionKey.deserialize(d).unwrap_or_throw(
                ValueError("DecryptionKey.fromBytes")
            )
            _assert_consumed(d, "DecryptionKey.fromBytes")
            return dk

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
    def __init__(self, enc: bytes, aead_ct: bytes) -> None:
        if len(enc) != ENCAPSULATED_KEY_BYTES:
            raise ValueError(
                f"Ciphertext: enc must be {ENCAPSULATED_KEY_BYTES} bytes, got {len(enc)}"
            )
        if len(aead_ct) < AEAD_TAG_BYTES:
            raise ValueError(
                f"Ciphertext: aeadCt must be >= {AEAD_TAG_BYTES} bytes (Poly1305 tag), "
                f"got {len(aead_ct)}"
            )
        self.enc = enc
        self.aead_ct = aead_ct

    @staticmethod
    def deserialize(d: Deserializer) -> Result["Ciphertext"]:
        def task(_extra: dict) -> "Ciphertext":
            return Ciphertext(d.deserialize_bytes(), d.deserialize_bytes())

        return Result.capture(task)

    def serialize(self, s: Serializer) -> None:
        s.serialize_bytes(self.enc)
        s.serialize_bytes(self.aead_ct)

    def to_bytes(self) -> bytes:
        s = Serializer()
        self.serialize(s)
        return s.to_bytes()

    @staticmethod
    def from_bytes(data: bytes) -> Result["Ciphertext"]:
        def task(_extra: dict) -> "Ciphertext":
            d = Deserializer(data)
            ct = Ciphertext.deserialize(d).unwrap_or_throw(ValueError("Ciphertext.fromBytes"))
            _assert_consumed(d, "Ciphertext.fromBytes")
            return ct

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


def keygen() -> tuple[EncryptionKey, DecryptionKey]:
    sk = X25519PrivateKey.generate()
    pk = sk.public_key()
    pk_bytes = pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    sk_bytes = sk.private_bytes(
        serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption()
    )
    return EncryptionKey(pk_bytes), DecryptionKey(sk_bytes)


def derive_encryption_key(dk: DecryptionKey) -> EncryptionKey:
    """Derive the public key from a private key via X25519 scalar-base-mult."""
    sk = X25519PrivateKey.from_private_bytes(dk.sk)
    pk = sk.public_key()
    pk_bytes = pk.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return EncryptionKey(pk_bytes)


def encrypt(encryption_key: EncryptionKey, plaintext: bytes, aad: bytes = b"") -> Ciphertext:
    suite = _suite()
    pk = X25519PublicKey.from_public_bytes(encryption_key.pk)
    recipient_public_key = KEMKey.from_pyca_cryptography_key(pk)
    enc, sender_ctx = suite.create_sender_context(recipient_public_key, info=b"")
    ct = sender_ctx.seal(plaintext, aad)
    return Ciphertext(enc, ct)


def decrypt(dk: DecryptionKey, ciphertext: Ciphertext, aad: bytes = b"") -> Result[bytes]:
    def task(_extra: dict) -> bytes:
        suite = _suite()
        sk = X25519PrivateKey.from_private_bytes(dk.sk)
        recipient_key = KEMKey.from_pyca_cryptography_key(sk)
        recip_ctx = suite.create_recipient_context(ciphertext.enc, recipient_key, info=b"")
        return recip_ctx.open(ciphertext.aead_ct, aad)

    return Result.capture(task)
