# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""
Mirrors src/t-ibe/bfibe-bls12381-shortsig-aead.ts.

Boneh-Franklin IBE over BLS12-381, "shortsig" variant ("minimal-signature-size"
convention from draft-irtf-cfrg-bls-signature):

- Master public key in G2.
- Identity hashed to G1 (Q_id in G1, 48 bytes compressed).
- Identity decryption key share in G1 (s_i * Q_id, 48 bytes compressed).
- Ciphertext c0 in G2 (96 bytes compressed).

DEM: HKDF-SHA256 -> ChaCha20-Poly1305 AEAD (matching the HPKE-X25519 PKE).
"""

from __future__ import annotations

import hashlib

import py_ecc.optimized_bls12_381 as _ob
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from py_ecc.bls.hash_to_curve import hash_to_G1

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
from ace_sdk.utils import rand_bytes

DST_HASH_ID_TO_CURVE = b"BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/HASH_ID_TO_CURVE"
DST_KDF = b"BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/KDF"

# Default G2 hash-to-curve DST used by @noble/curves' bls12_381.G2.htfDefaults
# (ts-sdk calls `bls12_381.G2.hashToCurve(randomBytes(32))` with no explicit DST).
_DEFAULT_G2_HTF_DST = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"

AEAD_KEY_BYTES = 32
AEAD_NONCE_BYTES = 12
AEAD_TAG_BYTES = 16

_G1Point = tuple
_G2Point = tuple


def _hash_id_to_g1(identity: bytes) -> _G1Point:
    return hash_to_G1(identity, DST_HASH_ID_TO_CURVE, hashlib.sha256)


def _gt_to_seed_bytes(g1_pt: _G1Point, g2_pt: _G2Point) -> bytes:
    e = pairing(g1_jacobian_to_affine(g1_pt), g2_jacobian_to_affine(g2_pt))
    return fp12_to_aptos_gt_bytes(e)


def _derive_aead_key_and_nonce(seed: bytes) -> tuple[bytes, bytes]:
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=AEAD_KEY_BYTES + AEAD_NONCE_BYTES,
        salt=b"",
        info=DST_KDF,
    )
    okm = hkdf.derive(seed)
    return okm[:AEAD_KEY_BYTES], okm[AEAD_KEY_BYTES : AEAD_KEY_BYTES + AEAD_NONCE_BYTES]


def _hex_string_to_bytes(hex_str: str) -> bytes:
    h = hex_str.strip()
    if h.startswith("0x") or h.startswith("0X"):
        h = h[2:]
    return bytes.fromhex(h)


# == MasterPublicKey ==========================================================


class MasterPublicKey:
    def __init__(self, base_point: _G2Point, pk: _G2Point) -> None:
        self.base_point = base_point
        self.pk = pk

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["MasterPublicKey"]:
        def task(_extra: dict) -> "MasterPublicKey":
            base_bytes = deserializer.deserialize_bytes()
            base = _g2_from_compressed(base_bytes)
            pk_bytes = deserializer.deserialize_bytes()
            pk = _g2_from_compressed(pk_bytes)
            return MasterPublicKey(base, pk)

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(_g2_to_compressed(self.base_point))
        serializer.serialize_bytes(_g2_to_compressed(self.pk))

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
            return MasterPublicKey.from_bytes(_hex_string_to_bytes(hex_str)).unwrap_or_throw(
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
    def __init__(self, base: _G2Point, scalar: int) -> None:
        self.base = base
        self.scalar = scalar

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["MasterPrivateKey"]:
        def task(_extra: dict) -> "MasterPrivateKey":
            base_bytes = deserializer.deserialize_bytes()
            base = _g2_from_compressed(base_bytes)
            scalar_bytes = deserializer.deserialize_bytes()
            scalar = int.from_bytes(scalar_bytes, "little")
            return MasterPrivateKey(base, scalar)

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(_g2_to_compressed(self.base))
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
            return MasterPrivateKey.from_bytes(_hex_string_to_bytes(hex_str)).unwrap_or_throw(
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
    def __init__(self, eval_point: int, idk_share: _G1Point, proof: bytes | None) -> None:
        self.eval_point = eval_point
        self.idk_share = idk_share
        self.proof = proof

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(self.eval_point.to_bytes(32, "little"))
        serializer.serialize_bytes(_g1_to_compressed(self.idk_share))
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
            idk_share = _g1_from_compressed(idk_share_bytes)
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
                _hex_string_to_bytes(hex_str)
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
    def __init__(self, c0: _G2Point, aead_ct: bytes) -> None:
        self.c0 = c0
        if len(aead_ct) < AEAD_TAG_BYTES:
            raise ValueError(
                f"Ciphertext: aeadCt must be >= {AEAD_TAG_BYTES} bytes (Poly1305 tag), "
                f"got {len(aead_ct)}"
            )
        self.aead_ct = aead_ct

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["Ciphertext"]:
        def task(_extra: dict) -> "Ciphertext":
            c0_bytes = deserializer.deserialize_bytes()
            c0 = _g2_from_compressed(c0_bytes)
            aead_ct = deserializer.deserialize_bytes()
            return Ciphertext(c0, aead_ct)

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_bytes(_g2_to_compressed(self.c0))
        serializer.serialize_bytes(self.aead_ct)

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
            return Ciphertext.from_bytes(_hex_string_to_bytes(hex_str)).unwrap_or_throw(
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


def keygen_for_testing() -> MasterPrivateKey:
    """Generate a master private key with a hash-derived G2 base point. Tests only —
    in production the base point comes from the on-chain DKG session."""
    from py_ecc.bls.hash_to_curve import hash_to_G2

    base = hash_to_G2(rand_bytes(32), _DEFAULT_G2_HTF_DST, hashlib.sha256)
    scalar = fr_mod(int.from_bytes(rand_bytes(32), "big"))
    return MasterPrivateKey(base, scalar)


def derive_public_key(msk: MasterPrivateKey) -> MasterPublicKey:
    pk = _ob.multiply(msk.base, msk.scalar)
    return MasterPublicKey(msk.base, pk)


def extract(msk_scalar: int, identity: bytes) -> IdentityDecryptionKeyShare:
    """Extract the full identity decryption key for `identity` from a master
    secret scalar. The result is encoded as a one-share threshold set at
    evalPoint 1, matching the TypeScript SDK's admin/disaster-recovery helper.
    """
    id_point = _hash_id_to_g1(identity)
    return IdentityDecryptionKeyShare(1, _ob.multiply(id_point, fr_mod(msk_scalar)), None)


# == Encrypt / Decrypt =========================================================


def ibe_encrypt_seed_and_c0(
    mpk: MasterPublicKey, identity: bytes, randomness: bytes
) -> tuple[bytes, _G2Point]:
    """IBE-half of encryption, shared by the block (IBE_*) and streaming (StreamIBE_*) DEMs:
    derive the raw Gt seed bytes fed into the DEM's HKDF, plus c0 = r * basePoint.
    Mirrors ts-sdk `ibeEncryptSeedAndC0`."""
    r = int.from_bytes(randomness, "little")
    id_point = _hash_id_to_g1(identity)
    # seed = e(H_G1(id), pk^r) in Gt
    pk_r = _ob.multiply(mpk.pk, r)
    seed = _gt_to_seed_bytes(id_point, pk_r)
    c0 = _ob.multiply(mpk.base_point, r)
    return seed, c0


def ibe_reconstruct_seed(idk_shares: list["IdentityDecryptionKeyShare"], c0: _G2Point) -> bytes:
    """IBE-half of decryption, shared by the block (IBE_*) and streaming (StreamIBE_*) DEMs:
    Lagrange-interpolate the IDK shares in G1 to recover the full identity decryption key, then
    recover the raw Gt seed bytes via e(idkFull, c0). Mirrors ts-sdk `ibeReconstructSeed`."""
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

    # e(idkFull, c0) = e(s * H_G1(id), r * basePoint) = e(H_G1(id), pk^r) = seed
    return _gt_to_seed_bytes(idk_full, c0)


def encrypt_with_randomness(
    mpk: MasterPublicKey, identity: bytes, plaintext: bytes, randomness: bytes
) -> Ciphertext:
    seed, c0 = ibe_encrypt_seed_and_c0(mpk, identity, randomness)
    key, nonce = _derive_aead_key_and_nonce(seed)
    aead_ct = ChaCha20Poly1305(key).encrypt(nonce, plaintext, None)
    return Ciphertext(c0, aead_ct)


def encrypt(mpk: MasterPublicKey, identity: bytes, plaintext: bytes) -> Result[Ciphertext]:
    def task(_extra: dict) -> Ciphertext:
        r = fr_mod(int.from_bytes(rand_bytes(64), "big"))
        randomness = r.to_bytes(32, "little")
        return encrypt_with_randomness(mpk, identity, plaintext, randomness)

    return Result.capture(task)


def verify_share(
    base_point: _G2Point, share_pk: _G2Point, identity: bytes, share: IdentityDecryptionKeyShare
) -> bool:
    """Verify an IDK share against the on-chain `sharePk` for the same evaluation point.

    Pairing check: e(idkShare, basePoint) == e(H_G1(id), sharePk).
    """
    id_point = _hash_id_to_g1(identity)
    lhs = pairing(g1_jacobian_to_affine(share.idk_share), g2_jacobian_to_affine(base_point))
    rhs = pairing(g1_jacobian_to_affine(id_point), g2_jacobian_to_affine(share_pk))
    return fp12_eq(lhs, rhs)


def decrypt(
    idk_shares: list[IdentityDecryptionKeyShare], ciphertext: Ciphertext
) -> Result[bytes]:
    def task(_extra: dict) -> bytes:
        seed = ibe_reconstruct_seed(idk_shares, ciphertext.c0)
        key, nonce = _derive_aead_key_and_nonce(seed)
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext.aead_ct, None)

    return Result.capture(task)
