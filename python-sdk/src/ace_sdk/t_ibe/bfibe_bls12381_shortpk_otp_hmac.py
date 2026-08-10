# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""
Mirrors src/t-ibe/bfibe-bls12381-shortpk-otp-hmac.ts.

Boneh-Franklin IBE over BLS12-381:
- The public key is in G1.
- Identity hashed to G2 (Q_id in G2, 96 bytes compressed).
- The symmetric cipher inside is a one-time pad.
- HMAC-SHA3-256 is used for authentication.
- In decryption, decryption key shares combine via Lagrange interpolation (G2).
"""

from __future__ import annotations

import hashlib

import py_ecc.optimized_bls12_381 as _ob
from py_ecc.bls.hash_to_curve import hash_to_G2

from ace_sdk.bcs import Deserializer, Serializer
from ace_sdk.group.bls12381_pairing import (
    fp12_eq,
    fp12_to_aptos_gt_bytes,
    g1_jacobian_to_affine,
    g2_jacobian_to_affine,
    pairing,
)
from ace_sdk.group.bls12381fr import fr_inv, fr_mod, fr_mul
from ace_sdk.group.bls12381g1 import _g1_from_compressed, _g1_to_compressed
from ace_sdk.group.bls12381g2 import _g2_from_compressed, _g2_to_compressed
from ace_sdk.result import Result
from ace_sdk.utils import hmac_sha3_256, kdf, rand_bytes, xor_bytes

DST_OTP = b"BONEH_FRANKLIN_BLS12381_SHORT_PK/OTP"
DST_ID_HASH = b"BONEH_FRANKLIN_BLS12381_SHORT_PK/HASH_ID_TO_CURVE"
DST_MAC = b"BONEH_FRANKLIN_BLS12381_SHORT_PK/MAC"

_G1Point = tuple
_G2Point = tuple


def _hash_id_to_g2(identity: bytes) -> _G2Point:
    return hash_to_G2(identity, DST_ID_HASH, hashlib.sha256)


def _seed_from_gt(g1_pt: _G1Point, g2_pt: _G2Point) -> bytes:
    e = pairing(g1_jacobian_to_affine(g1_pt), g2_jacobian_to_affine(g2_pt))
    return fp12_to_aptos_gt_bytes(e)


# == MasterPublicKey ==========================================================


class MasterPublicKey:
    def __init__(self, base_point: _G1Point, pk: _G1Point) -> None:
        self.base_point = base_point
        self.pk = pk

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["MasterPublicKey"]:
        def task(_extra: dict) -> "MasterPublicKey":
            base_bytes = deserializer.deserialize_bytes()
            base = _g1_from_compressed(base_bytes)
            pk_bytes = deserializer.deserialize_bytes()
            pk = _g1_from_compressed(pk_bytes)
            return MasterPublicKey(base, pk)

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(_g1_to_compressed(self.base_point))
        serializer.serialize_bytes(_g1_to_compressed(self.pk))

    @staticmethod
    def from_bytes(data: bytes) -> Result["MasterPublicKey"]:
        def task(_extra: dict) -> "MasterPublicKey":
            deserializer = Deserializer(data)
            obj = MasterPublicKey.deserialize(deserializer).unwrap_or_throw(
                ValueError("MasterPublicKey.from_bytes failed")
            )
            if deserializer.remaining() != 0:
                raise ValueError("MasterPublicKey.from_bytes: trailing bytes")
            return obj

        return Result.capture(task)

    @staticmethod
    def from_hex(hex_str: str) -> Result["MasterPublicKey"]:
        def task(_extra: dict) -> "MasterPublicKey":
            return MasterPublicKey.from_bytes(bytes.fromhex(hex_str)).unwrap_or_throw(
                ValueError("MasterPublicKey.from_hex failed")
            )

        return Result.capture(task)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()


# == MasterPrivateKey =========================================================


class MasterPrivateKey:
    def __init__(self, base: _G1Point, scalar: int) -> None:
        self.base = base
        self.scalar = scalar

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["MasterPrivateKey"]:
        def task(_extra: dict) -> "MasterPrivateKey":
            base_bytes = deserializer.deserialize_bytes()
            base = _g1_from_compressed(base_bytes)
            scalar_bytes = deserializer.deserialize_bytes()
            scalar = int.from_bytes(scalar_bytes, "little")
            return MasterPrivateKey(base, scalar)

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(_g1_to_compressed(self.base))
        serializer.serialize_bytes(self.scalar.to_bytes(32, "little"))

    @staticmethod
    def from_bytes(data: bytes) -> Result["MasterPrivateKey"]:
        def task(_extra: dict) -> "MasterPrivateKey":
            deserializer = Deserializer(data)
            obj = MasterPrivateKey.deserialize(deserializer).unwrap_or_throw(
                ValueError("MasterPrivateKey.from_bytes failed")
            )
            if deserializer.remaining() != 0:
                raise ValueError("MasterPrivateKey.from_bytes: trailing bytes")
            return obj

        return Result.capture(task)

    @staticmethod
    def from_hex(hex_str: str) -> Result["MasterPrivateKey"]:
        def task(_extra: dict) -> "MasterPrivateKey":
            return MasterPrivateKey.from_bytes(bytes.fromhex(hex_str)).unwrap_or_throw(
                ValueError("MasterPrivateKey.from_hex failed")
            )

        return Result.capture(task)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()


# == IdentityDecryptionKeyShare ================================================


class IdentityDecryptionKeyShare:
    def __init__(self, eval_point: int, idk_share: _G2Point, proof: bytes | None) -> None:
        self.eval_point = eval_point
        self.idk_share = idk_share
        self.proof = proof

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(self.eval_point.to_bytes(32, "little"))
        serializer.serialize_bytes(_g2_to_compressed(self.idk_share))
        serializer.serialize_u8(1 if self.proof is not None else 0)
        if self.proof is not None:
            serializer.serialize_bytes(self.proof)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["IdentityDecryptionKeyShare"]:
        def task(_extra: dict) -> "IdentityDecryptionKeyShare":
            eval_point_bytes = deserializer.deserialize_bytes()
            if len(eval_point_bytes) != 32:
                raise ValueError("IdentityDecryptionKeyShare: expected 32-byte evalPoint")
            eval_point = int.from_bytes(eval_point_bytes, "little")
            idk_share_bytes = deserializer.deserialize_bytes()
            idk_share = _g2_from_compressed(idk_share_bytes)
            has_proof = deserializer.deserialize_u8() != 0
            proof = deserializer.deserialize_bytes() if has_proof else None
            return IdentityDecryptionKeyShare(eval_point, idk_share, proof)

        return Result.capture(task)

    @staticmethod
    def from_bytes(data: bytes) -> Result["IdentityDecryptionKeyShare"]:
        def task(_extra: dict) -> "IdentityDecryptionKeyShare":
            deserializer = Deserializer(data)
            obj = IdentityDecryptionKeyShare.deserialize(deserializer).unwrap_or_throw(
                ValueError("IdentityDecryptionKeyShare.from_bytes failed")
            )
            if deserializer.remaining() != 0:
                raise ValueError("IdentityDecryptionKeyShare.from_bytes: trailing bytes")
            return obj

        return Result.capture(task)

    @staticmethod
    def from_hex(hex_str: str) -> Result["IdentityDecryptionKeyShare"]:
        def task(_extra: dict) -> "IdentityDecryptionKeyShare":
            return IdentityDecryptionKeyShare.from_bytes(
                bytes.fromhex(hex_str)
            ).unwrap_or_throw(ValueError("IdentityDecryptionKeyShare.from_hex failed"))

        return Result.capture(task)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()


# == Ciphertext ================================================================


class Ciphertext:
    def __init__(self, c0: _G1Point, symmetric_ciph: bytes, mac: bytes) -> None:
        self.c0 = c0
        self.symmetric_ciph = symmetric_ciph
        self.mac = mac

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["Ciphertext"]:
        def task(_extra: dict) -> "Ciphertext":
            c0_bytes = deserializer.deserialize_bytes()
            c0 = _g1_from_compressed(c0_bytes)
            symmetric_ciph = deserializer.deserialize_bytes()
            mac = deserializer.deserialize_bytes()
            return Ciphertext(c0, symmetric_ciph, mac)

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(_g1_to_compressed(self.c0))
        serializer.serialize_bytes(self.symmetric_ciph)
        serializer.serialize_bytes(self.mac)

    @staticmethod
    def from_bytes(data: bytes) -> Result["Ciphertext"]:
        def task(_extra: dict) -> "Ciphertext":
            deserializer = Deserializer(data)
            obj = Ciphertext.deserialize(deserializer).unwrap_or_throw(
                ValueError("Ciphertext.from_bytes failed")
            )
            if deserializer.remaining() != 0:
                raise ValueError("Ciphertext.from_bytes: trailing bytes")
            return obj

        return Result.capture(task)

    @staticmethod
    def from_hex(hex_str: str) -> Result["Ciphertext"]:
        def task(_extra: dict) -> "Ciphertext":
            return Ciphertext.from_bytes(bytes.fromhex(hex_str)).unwrap_or_throw(
                ValueError("Ciphertext.from_hex failed")
            )

        return Result.capture(task)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()


# == Key generation + derivation ==============================================


# Default G1 hash-to-curve DST used by @noble/curves' bls12_381.G1.htfDefaults
# (ts-sdk calls `bls12_381.G1.hashToCurve(randomBytes(32))` with no explicit DST).
_DEFAULT_G1_HTF_DST = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_NUL_"


def keygen_for_testing() -> MasterPrivateKey:
    """Generate a master private key with a hash-derived G1 base point. Tests only —
    in production the base point comes from the on-chain DKG session."""
    from py_ecc.bls.hash_to_curve import hash_to_G1

    base = hash_to_G1(rand_bytes(32), _DEFAULT_G1_HTF_DST, hashlib.sha256)
    scalar = fr_mod(int.from_bytes(rand_bytes(32), "big"))
    return MasterPrivateKey(base, scalar)


def derive_public_key(msk: MasterPrivateKey) -> MasterPublicKey:
    pk = _ob.multiply(msk.base, msk.scalar)
    return MasterPublicKey(msk.base, pk)


# == Encrypt / Decrypt =========================================================


def encrypt_with_randomness(
    mpk: MasterPublicKey, identity: bytes, plaintext: bytes, randomness: bytes
) -> Ciphertext:
    r = int.from_bytes(randomness, "little")
    id_point = _hash_id_to_g2(identity)
    seed_element_pt = _ob.multiply(mpk.pk, r)
    seed = _seed_from_gt(seed_element_pt, id_point)
    otp = kdf(seed, DST_OTP, len(plaintext))
    mac_key = kdf(seed, DST_MAC, 32)
    symmetric_ciph = xor_bytes(otp, plaintext)
    mac = hmac_sha3_256(mac_key, symmetric_ciph)
    c0 = _ob.multiply(mpk.base_point, r)
    return Ciphertext(c0, symmetric_ciph, mac)


def encrypt(mpk: MasterPublicKey, identity: bytes, plaintext: bytes) -> Result[Ciphertext]:
    def task(_extra: dict) -> Ciphertext:
        r = fr_mod(int.from_bytes(rand_bytes(64), "big"))
        randomness = r.to_bytes(32, "little")
        return encrypt_with_randomness(mpk, identity, plaintext, randomness)

    return Result.capture(task)


def verify_share(
    base_point: _G1Point, share_pk: _G1Point, identity: bytes, share: IdentityDecryptionKeyShare
) -> bool:
    """Verify that `share.idk_share = H_G2(id)^{f(x)}` where `share_pk = base_point^{f(x)}`.

    Pairing check: `e(base_point, idk_share) == e(share_pk, H_G2(id))`.
    """
    id_point = _hash_id_to_g2(identity)
    lhs = pairing(g1_jacobian_to_affine(base_point), g2_jacobian_to_affine(share.idk_share))
    rhs = pairing(g1_jacobian_to_affine(share_pk), g2_jacobian_to_affine(id_point))
    return fp12_eq(lhs, rhs)


def decrypt(
    idk_shares: list[IdentityDecryptionKeyShare], ciphertext: Ciphertext
) -> Result[bytes]:
    def task(_extra: dict) -> bytes:
        if len(idk_shares) == 0:
            raise ValueError("decrypt: no IDK shares provided")

        xs = [fr_mod(s.eval_point) for s in idk_shares]
        for i in range(len(xs)):
            for j in range(i + 1, len(xs)):
                if xs[i] == xs[j]:
                    raise ValueError("decrypt: duplicate evalPoint")

        lambdas: list[int] = []
        for i, xi in enumerate(xs):
            lam = 1
            for j, xj in enumerate(xs):
                if i == j:
                    continue
                lam = fr_mul(lam, fr_mul(fr_mod(-xj), fr_inv(fr_mod(xi - xj))))
            lambdas.append(lam)

        idk_full = None
        for i, share in enumerate(idk_shares):
            if lambdas[i] == 0:
                continue
            scaled = _ob.multiply(share.idk_share, lambdas[i])
            idk_full = scaled if idk_full is None else _ob.add(idk_full, scaled)
        if idk_full is None:
            raise ValueError("decrypt: all Lagrange coefficients were zero")

        seed = _seed_from_gt(ciphertext.c0, idk_full)
        mac_key = kdf(seed, DST_MAC, 32)
        mac_another = hmac_sha3_256(mac_key, ciphertext.symmetric_ciph)
        if ciphertext.mac != mac_another:
            raise ValueError("decrypt: MAC verification failed")
        otp = kdf(seed, DST_OTP, len(ciphertext.symmetric_ciph))
        return xor_bytes(otp, ciphertext.symmetric_ciph)

    return Result.capture(task)
