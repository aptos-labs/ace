# Copyright (c) Aptos Labs
# SPDX-License-Identifier: Apache-2.0
"""Mirrors src/pke/elgamal.ts: exponential ElGamal over pke/group.py's ristretto255."""

from __future__ import annotations

from ace_sdk.bcs import Deserializer, Serializer
from ace_sdk.pke.group import Element, Scalar


class Ciphertext:
    def __init__(self, c0: Element, c1: Element) -> None:
        self.c0 = c0
        self.c1 = c1

    @staticmethod
    def decode(deserializer: Deserializer) -> "Ciphertext":
        c0 = Element.decode(deserializer)
        c1 = Element.decode(deserializer)
        return Ciphertext(c0, c1)

    def encode(self, serializer: Serializer) -> None:
        self.c0.encode(serializer)
        self.c1.encode(serializer)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.encode(serializer)
        return serializer.to_bytes()

    def add(self, other: "Ciphertext") -> "Ciphertext":
        return Ciphertext(self.c0.add(other.c0), self.c1.add(other.c1))

    def scale(self, scalar: Scalar) -> "Ciphertext":
        return Ciphertext(self.c0.scale(scalar), self.c1.scale(scalar))


class DecKey:
    def __init__(self, enc_base: Element, private_scalar: Scalar) -> None:
        self.enc_base = enc_base
        self.private_scalar = private_scalar

    @staticmethod
    def decode(deserializer: Deserializer) -> "DecKey":
        enc_base = Element.decode(deserializer)
        private_scalar = Scalar.decode(deserializer)
        return DecKey(enc_base, private_scalar)

    def encode(self, serializer: Serializer) -> None:
        self.enc_base.encode(serializer)
        self.private_scalar.encode(serializer)


class EncKey:
    def __init__(self, enc_base: Element, public_point: Element) -> None:
        self.enc_base = enc_base
        self.public_point = public_point

    @staticmethod
    def decode(deserializer: Deserializer) -> "EncKey":
        enc_base = Element.decode(deserializer)
        public_point = Element.decode(deserializer)
        return EncKey(enc_base, public_point)

    def encode(self, serializer: Serializer) -> None:
        self.enc_base.encode(serializer)
        self.public_point.encode(serializer)

    def to_bytes(self) -> bytes:
        serializer = Serializer()
        self.encode(serializer)
        return serializer.to_bytes()


def enc(ek: EncKey, randomizer: Scalar, ptxt: Element) -> Ciphertext:
    return Ciphertext(ek.enc_base.scale(randomizer), ptxt.add(ek.public_point.scale(randomizer)))


def dec(dk: DecKey, ciph: Ciphertext) -> Element:
    unblinder = ciph.c0.scale(dk.private_scalar)
    return ciph.c1.sub(unblinder)


def multi_exp(ciphs: list[Ciphertext], scalars: list[Scalar]) -> Ciphertext:
    acc = Ciphertext(Element.group_identity(), Element.group_identity())
    for ciph, scalar in zip(ciphs, scalars):
        acc = acc.add(ciph.scale(scalar))
    return acc
