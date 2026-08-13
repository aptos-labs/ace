# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""
Mirrors src/t-ibe/index.ts: scheme-dispatching wrapper over
BfibeBls12381ShortPkOtpHmac (scheme 0, G1 pk) and BfibeBls12381ShortSigAead
(scheme 1, G2 pk).
"""

from __future__ import annotations

from ace_sdk import group as _group
from ace_sdk.bcs import Deserializer, Serializer
from ace_sdk.result import Result
from ace_sdk.t_ibe import bfibe_bls12381_shortpk_otp_hmac as BfibeBls12381ShortPkOtpHmac
from ace_sdk.t_ibe import bfibe_bls12381_shortsig_aead as BfibeBls12381ShortSigAead

SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC = 0
SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD = 1


def _assert_consumed(d: Deserializer, label: str) -> None:
    if d.remaining() != 0:
        raise ValueError(f"{label}: trailing bytes")


def _hex_string_to_bytes(hex_str: str) -> bytes:
    h = hex_str.strip()
    if h.startswith("0x") or h.startswith("0X"):
        h = h[2:]
    return bytes.fromhex(h)


# == MasterPublicKey ==========================================================


class MasterPublicKey:
    def __init__(self, scheme: int, inner) -> None:
        self.scheme = scheme
        self.inner = inner

    @staticmethod
    def new_boneh_franklin_bls12381_shortpk_otp_hmac(
        base_point: "_group.Element", pk: "_group.Element"
    ) -> Result["MasterPublicKey"]:
        def task(_extra: dict) -> "MasterPublicKey":
            base_inner = base_point.inner.pt
            pk_inner = pk.inner.pt
            inner = BfibeBls12381ShortPkOtpHmac.MasterPublicKey(base_inner, pk_inner)
            return MasterPublicKey(SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC, inner)

        return Result.capture(task)

    @staticmethod
    def new_boneh_franklin_bls12381_shortsig_aead(
        base_point: "_group.Element", pk: "_group.Element"
    ) -> Result["MasterPublicKey"]:
        def task(_extra: dict) -> "MasterPublicKey":
            base_inner = base_point.inner.pt
            pk_inner = pk.inner.pt
            inner = BfibeBls12381ShortSigAead.MasterPublicKey(base_inner, pk_inner)
            return MasterPublicKey(SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD, inner)

        return Result.capture(task)

    @staticmethod
    def _create(scheme: int, inner) -> "MasterPublicKey":
        return MasterPublicKey(scheme, inner)

    @staticmethod
    def from_group_elements(
        scheme: int, base_point: "_group.Element", result_pk: "_group.Element"
    ) -> Result["MasterPublicKey"]:
        """Build a MasterPublicKey for the requested t-IBE `scheme` from on-chain DKG
        group elements, validating that the elements live in the group `scheme` expects.
        """

        def task(_extra: dict) -> "MasterPublicKey":
            if scheme == SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC:
                if (
                    base_point.scheme != _group.SCHEME_BLS12381G1
                    or result_pk.scheme != _group.SCHEME_BLS12381G1
                ):
                    raise ValueError(
                        "tibe.MasterPublicKey.from_group_elements: scheme=shortpk-otp-hmac "
                        f"requires G1 basepoint and resultPk, got basePoint.scheme="
                        f"{base_point.scheme}, resultPk.scheme={result_pk.scheme}"
                    )
                return MasterPublicKey.new_boneh_franklin_bls12381_shortpk_otp_hmac(
                    base_point, result_pk
                ).unwrap_or_throw(ValueError("new_boneh_franklin_bls12381_shortpk_otp_hmac"))
            if scheme == SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD:
                if (
                    base_point.scheme != _group.SCHEME_BLS12381G2
                    or result_pk.scheme != _group.SCHEME_BLS12381G2
                ):
                    raise ValueError(
                        "tibe.MasterPublicKey.from_group_elements: scheme=shortsig-aead "
                        f"requires G2 basepoint and resultPk, got basePoint.scheme="
                        f"{base_point.scheme}, resultPk.scheme={result_pk.scheme}"
                    )
                return MasterPublicKey.new_boneh_franklin_bls12381_shortsig_aead(
                    base_point, result_pk
                ).unwrap_or_throw(ValueError("new_boneh_franklin_bls12381_shortsig_aead"))
            raise ValueError(f"tibe.MasterPublicKey.from_group_elements: unknown scheme {scheme}")

        return Result.capture(task)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["MasterPublicKey"]:
        def task(_extra: dict) -> "MasterPublicKey":
            scheme = deserializer.deserialize_u8()
            if scheme == SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC:
                inner = BfibeBls12381ShortPkOtpHmac.MasterPublicKey.deserialize(
                    deserializer
                ).unwrap_or_throw(ValueError("MasterPublicKey inner deserialization failed"))
                return MasterPublicKey(scheme, inner)
            if scheme == SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD:
                inner = BfibeBls12381ShortSigAead.MasterPublicKey.deserialize(
                    deserializer
                ).unwrap_or_throw(ValueError("MasterPublicKey inner deserialization failed"))
                return MasterPublicKey(scheme, inner)
            raise ValueError(f"MasterPublicKey deserialization failed with unknown scheme: {scheme}")

        return Result.capture(task)

    @staticmethod
    def from_bytes(data: bytes) -> Result["MasterPublicKey"]:
        def task(_extra: dict) -> "MasterPublicKey":
            deserializer = Deserializer(data)
            obj = MasterPublicKey.deserialize(deserializer).unwrap_or_throw(
                ValueError("MasterPublicKey.from_bytes failed")
            )
            _assert_consumed(deserializer, "MasterPublicKey.from_bytes")
            return obj

        return Result.capture(task)

    @staticmethod
    def from_hex(hex_str: str) -> Result["MasterPublicKey"]:
        def task(_extra: dict) -> "MasterPublicKey":
            return MasterPublicKey.from_bytes(_hex_string_to_bytes(hex_str)).unwrap_or_throw(
                ValueError("MasterPublicKey.from_hex failed")
            )

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u8(self.scheme)
        if self.scheme == SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC:
            self.inner.serialize(serializer)
        elif self.scheme == SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD:
            self.inner.serialize(serializer)
        else:
            raise ValueError(f"MasterPublicKey.serialize: unknown scheme {self.scheme}")

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()


# == MasterPrivateKey =========================================================


class MasterPrivateKey:
    def __init__(self, scheme: int, inner) -> None:
        self.scheme = scheme
        self.inner = inner

    @staticmethod
    def _create(scheme: int, inner) -> "MasterPrivateKey":
        return MasterPrivateKey(scheme, inner)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["MasterPrivateKey"]:
        def task(_extra: dict) -> "MasterPrivateKey":
            scheme = deserializer.deserialize_u8()
            if scheme == SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC:
                inner = BfibeBls12381ShortPkOtpHmac.MasterPrivateKey.deserialize(
                    deserializer
                ).unwrap_or_throw(ValueError("MasterPrivateKey inner deserialization failed"))
                return MasterPrivateKey(scheme, inner)
            if scheme == SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD:
                inner = BfibeBls12381ShortSigAead.MasterPrivateKey.deserialize(
                    deserializer
                ).unwrap_or_throw(ValueError("MasterPrivateKey inner deserialization failed"))
                return MasterPrivateKey(scheme, inner)
            raise ValueError(f"MasterPrivateKey deserialization failed with unknown scheme: {scheme}")

        return Result.capture(task)

    @staticmethod
    def from_bytes(data: bytes) -> Result["MasterPrivateKey"]:
        def task(_extra: dict) -> "MasterPrivateKey":
            deserializer = Deserializer(data)
            obj = MasterPrivateKey.deserialize(deserializer).unwrap_or_throw(
                ValueError("MasterPrivateKey.from_bytes failed")
            )
            _assert_consumed(deserializer, "MasterPrivateKey.from_bytes")
            return obj

        return Result.capture(task)

    @staticmethod
    def from_hex(hex_str: str) -> Result["MasterPrivateKey"]:
        def task(_extra: dict) -> "MasterPrivateKey":
            return MasterPrivateKey.from_bytes(_hex_string_to_bytes(hex_str)).unwrap_or_throw(
                ValueError("MasterPrivateKey.from_hex failed")
            )

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u8(self.scheme)
        if self.scheme == SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC:
            self.inner.serialize(serializer)
        elif self.scheme == SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD:
            self.inner.serialize(serializer)
        else:
            raise ValueError(f"MasterPrivateKey.serialize: unknown scheme {self.scheme}")

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()


# == Ciphertext ================================================================


class Ciphertext:
    def __init__(self, scheme: int, inner) -> None:
        self.scheme = scheme
        self.inner = inner

    @staticmethod
    def _create(scheme: int, inner) -> "Ciphertext":
        return Ciphertext(scheme, inner)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["Ciphertext"]:
        def task(_extra: dict) -> "Ciphertext":
            scheme = deserializer.deserialize_u8()
            if scheme == SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC:
                inner = BfibeBls12381ShortPkOtpHmac.Ciphertext.deserialize(
                    deserializer
                ).unwrap_or_throw(ValueError("Ciphertext inner deserialization failed"))
                return Ciphertext(scheme, inner)
            if scheme == SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD:
                inner = BfibeBls12381ShortSigAead.Ciphertext.deserialize(
                    deserializer
                ).unwrap_or_throw(ValueError("Ciphertext inner deserialization failed"))
                return Ciphertext(scheme, inner)
            raise ValueError(f"Ciphertext deserialization failed with unknown scheme: {scheme}")

        return Result.capture(task)

    @staticmethod
    def from_bytes(data: bytes) -> Result["Ciphertext"]:
        def task(_extra: dict) -> "Ciphertext":
            deserializer = Deserializer(data)
            obj = Ciphertext.deserialize(deserializer).unwrap_or_throw(
                ValueError("Ciphertext.from_bytes failed")
            )
            _assert_consumed(deserializer, "Ciphertext.from_bytes")
            return obj

        return Result.capture(task)

    @staticmethod
    def from_hex(hex_str: str) -> Result["Ciphertext"]:
        def task(_extra: dict) -> "Ciphertext":
            return Ciphertext.from_bytes(_hex_string_to_bytes(hex_str)).unwrap_or_throw(
                ValueError("Ciphertext.from_hex failed")
            )

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u8(self.scheme)
        if self.scheme == SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC:
            self.inner.serialize(serializer)
        elif self.scheme == SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD:
            self.inner.serialize(serializer)
        else:
            raise ValueError(f"Ciphertext.serialize: unknown scheme {self.scheme}")

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()


# == IdentityDecryptionKeyShare ================================================


class IdentityDecryptionKeyShare:
    def __init__(self, scheme: int, inner) -> None:
        self.scheme = scheme
        self.inner = inner

    @staticmethod
    def new_boneh_franklin_bls12381_shortpk_otp_hmac(
        eval_point: int, idk_share, proof: bytes | None = None
    ) -> Result["IdentityDecryptionKeyShare"]:
        def task(_extra: dict) -> "IdentityDecryptionKeyShare":
            inner = BfibeBls12381ShortPkOtpHmac.IdentityDecryptionKeyShare(
                eval_point, idk_share, proof
            )
            return IdentityDecryptionKeyShare(SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC, inner)

        return Result.capture(task)

    @staticmethod
    def new_boneh_franklin_bls12381_shortsig_aead(
        eval_point: int, idk_share, proof: bytes | None = None
    ) -> Result["IdentityDecryptionKeyShare"]:
        def task(_extra: dict) -> "IdentityDecryptionKeyShare":
            inner = BfibeBls12381ShortSigAead.IdentityDecryptionKeyShare(
                eval_point, idk_share, proof
            )
            return IdentityDecryptionKeyShare(SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD, inner)

        return Result.capture(task)

    @staticmethod
    def deserialize(deserializer: Deserializer) -> Result["IdentityDecryptionKeyShare"]:
        def task(_extra: dict) -> "IdentityDecryptionKeyShare":
            scheme = deserializer.deserialize_u8()
            if scheme == SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC:
                inner = BfibeBls12381ShortPkOtpHmac.IdentityDecryptionKeyShare.deserialize(
                    deserializer
                ).unwrap_or_throw(
                    ValueError("IdentityDecryptionKeyShare inner deserialization failed")
                )
                return IdentityDecryptionKeyShare(scheme, inner)
            if scheme == SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD:
                inner = BfibeBls12381ShortSigAead.IdentityDecryptionKeyShare.deserialize(
                    deserializer
                ).unwrap_or_throw(
                    ValueError("IdentityDecryptionKeyShare inner deserialization failed")
                )
                return IdentityDecryptionKeyShare(scheme, inner)
            raise ValueError(
                f"IdentityDecryptionKeyShare deserialization failed with unknown scheme: {scheme}"
            )

        return Result.capture(task)

    @staticmethod
    def from_bytes(data: bytes) -> Result["IdentityDecryptionKeyShare"]:
        def task(_extra: dict) -> "IdentityDecryptionKeyShare":
            deserializer = Deserializer(data)
            obj = IdentityDecryptionKeyShare.deserialize(deserializer).unwrap_or_throw(
                ValueError("IdentityDecryptionKeyShare.from_bytes failed")
            )
            _assert_consumed(deserializer, "IdentityDecryptionKeyShare.from_bytes")
            return obj

        return Result.capture(task)

    @staticmethod
    def from_hex(hex_str: str) -> Result["IdentityDecryptionKeyShare"]:
        def task(_extra: dict) -> "IdentityDecryptionKeyShare":
            return IdentityDecryptionKeyShare.from_bytes(
                _hex_string_to_bytes(hex_str)
            ).unwrap_or_throw(ValueError("IdentityDecryptionKeyShare.from_hex failed"))

        return Result.capture(task)

    def serialize(self, serializer: Serializer) -> None:
        serializer.serialize_u8(self.scheme)
        if self.scheme == SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC:
            self.inner.serialize(serializer)
        elif self.scheme == SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD:
            self.inner.serialize(serializer)
        else:
            raise ValueError(f"IdentityDecryptionKeyShare.serialize: unknown scheme {self.scheme}")

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.serialize(serializer)
        return serializer.to_bytes()

    def to_hex(self) -> str:
        return self.to_bytes().hex()


# == Functions =================================================================


def keygen_for_testing(scheme: int | None = None) -> Result[MasterPrivateKey]:
    def task(_extra: dict) -> MasterPrivateKey:
        s = SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC if scheme is None else scheme
        if s == SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC:
            msk = BfibeBls12381ShortPkOtpHmac.keygen_for_testing()
            return MasterPrivateKey._create(s, msk)
        if s == SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD:
            msk = BfibeBls12381ShortSigAead.keygen_for_testing()
            return MasterPrivateKey._create(s, msk)
        raise ValueError(f"keygen_for_testing failed with unknown scheme {s}")

    return Result.capture(task)


def derive_public_key(msk: MasterPrivateKey) -> Result[MasterPublicKey]:
    def task(_extra: dict) -> MasterPublicKey:
        if msk.scheme == SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC:
            mpk = BfibeBls12381ShortPkOtpHmac.derive_public_key(msk.inner)
            return MasterPublicKey._create(SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC, mpk)
        if msk.scheme == SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD:
            mpk = BfibeBls12381ShortSigAead.derive_public_key(msk.inner)
            return MasterPublicKey._create(SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD, mpk)
        raise ValueError(f"derive_public_key failed with unknown scheme {msk.scheme}")

    return Result.capture(task)


def encrypt(mpk: MasterPublicKey, identity: bytes, plaintext: bytes) -> Result[Ciphertext]:
    def task(_extra: dict) -> Ciphertext:
        if mpk.scheme == SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC:
            inner_ciph = BfibeBls12381ShortPkOtpHmac.encrypt(
                mpk.inner, identity, plaintext
            ).unwrap_or_throw(ValueError("encrypt failed"))
            return Ciphertext._create(SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC, inner_ciph)
        if mpk.scheme == SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD:
            inner_ciph = BfibeBls12381ShortSigAead.encrypt(
                mpk.inner, identity, plaintext
            ).unwrap_or_throw(ValueError("encrypt failed"))
            return Ciphertext._create(SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD, inner_ciph)
        raise ValueError(f"encrypt: unknown scheme {mpk.scheme}")

    return Result.capture(task)


def encrypt_with_randomness(
    mpk: MasterPublicKey, identity: bytes, plaintext: bytes, randomness: bytes
) -> Result[Ciphertext]:
    """Do NOT use this, unless you are a maintainer. Use `encrypt` instead."""

    def task(_extra: dict) -> Ciphertext:
        if mpk.scheme == SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC:
            inner_ciph = BfibeBls12381ShortPkOtpHmac.encrypt_with_randomness(
                mpk.inner, identity, plaintext, randomness
            )
            return Ciphertext._create(SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC, inner_ciph)
        if mpk.scheme == SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD:
            inner_ciph = BfibeBls12381ShortSigAead.encrypt_with_randomness(
                mpk.inner, identity, plaintext, randomness
            )
            return Ciphertext._create(SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD, inner_ciph)
        raise ValueError(f"encrypt_with_randomness: unknown scheme {mpk.scheme}")

    return Result.capture(task)


def verify_share(
    base_point: "_group.Element",
    share_pk: "_group.Element",
    identity: bytes,
    share: IdentityDecryptionKeyShare,
) -> Result[bool]:
    """Verify that an IDK share is correct against the on-chain `sharePk` for the
    same evaluation point.

    Returns `true` if the share is well-formed for the given (basePoint, sharePk, id).
    Caller binds `sharePk` to the share's evaluation point (i.e. share_pks[i] for node i).
    """

    def task(_extra: dict) -> bool:
        if share.scheme == SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC:
            return BfibeBls12381ShortPkOtpHmac.verify_share(
                base_point.inner.pt, share_pk.inner.pt, identity, share.inner
            )
        if share.scheme == SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD:
            return BfibeBls12381ShortSigAead.verify_share(
                base_point.inner.pt, share_pk.inner.pt, identity, share.inner
            )
        raise ValueError(f"verify_share: unknown share scheme {share.scheme}")

    return Result.capture(task)


def extract(
    scheme: int | None = None,
    msk_scalar: int | None = None,
    identity: bytes | None = None,
) -> Result[IdentityDecryptionKeyShare]:
    """Extract a full identity decryption key from a master-secret scalar.

    This mirrors the TypeScript SDK's admin/disaster-recovery helper. Only the
    production shortsig-aead scheme is supported; the returned IDK is wrapped as
    a single share at evalPoint 1 and can be passed directly to `decrypt`.
    """

    def task(_extra: dict) -> IdentityDecryptionKeyShare:
        s = SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD if scheme is None else scheme
        if msk_scalar is None:
            raise ValueError("extract: msk_scalar is required")
        if identity is None:
            raise ValueError("extract: identity is required")
        if s == SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD:
            inner = BfibeBls12381ShortSigAead.extract(msk_scalar, identity)
            return IdentityDecryptionKeyShare(s, inner)
        raise ValueError(f"extract: unsupported scheme {s} (only shortsig-aead)")

    return Result.capture(task)


def decrypt(idk_shares: list[IdentityDecryptionKeyShare], ciphertext: Ciphertext) -> Result[bytes]:
    def task(_extra: dict) -> bytes:
        scheme = ciphertext.scheme
        for idk_share in idk_shares:
            if idk_share.scheme != scheme:
                raise ValueError("scheme mismatch")
        if scheme == SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC:
            return BfibeBls12381ShortPkOtpHmac.decrypt(
                [s.inner for s in idk_shares], ciphertext.inner
            ).unwrap_or_throw(ValueError("decrypt failed"))
        if scheme == SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD:
            return BfibeBls12381ShortSigAead.decrypt(
                [s.inner for s in idk_shares], ciphertext.inner
            ).unwrap_or_throw(ValueError("decrypt failed"))
        raise ValueError(f"decrypt: unknown scheme {scheme}")

    return Result.capture(task)
