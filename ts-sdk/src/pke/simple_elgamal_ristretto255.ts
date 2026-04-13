// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import * as ElGamal from "./elgamal";
import * as Group from "./group";
import { hmac_sha3_256, kdf, xorBytes } from "../utils";

export class SimpleElGamalRistretto255EncKey {
    elgamalEk: ElGamal.EncKey;

    constructor(elgamalEk: ElGamal.EncKey) {
        this.elgamalEk = elgamalEk;
    }

    static deserialize(deserializer: Deserializer): SimpleElGamalRistretto255EncKey {
        const elgamalEk = ElGamal.EncKey.decode(deserializer);
        return new SimpleElGamalRistretto255EncKey(elgamalEk);
    }

    serialize(serializer: Serializer): void {
        this.elgamalEk.encode(serializer);
    }
}

export class SimpleElGamalRistretto255DecKey {
    elgamalDk: ElGamal.DecKey;

    constructor(elgamalDk: ElGamal.DecKey) {
        this.elgamalDk = elgamalDk;
    }

    static deserialize(deserializer: Deserializer): SimpleElGamalRistretto255DecKey {
        const elgamalDk = ElGamal.DecKey.decode(deserializer);
        return new SimpleElGamalRistretto255DecKey(elgamalDk);
    }

    serialize(serializer: Serializer): void {
        this.elgamalDk.encode(serializer);
    }
}

export class SimpleElGamalRistretto255Ciphertext {
    elgamalCiph: ElGamal.Ciphertext;
    symmetricCiph: Uint8Array;
    mac: Uint8Array;

    constructor(elgamalCiph: ElGamal.Ciphertext, symmetricCiph: Uint8Array, mac: Uint8Array) {
        this.elgamalCiph = elgamalCiph;
        this.symmetricCiph = symmetricCiph;
        this.mac = mac;
    }

    static deserialize(deserializer: Deserializer): SimpleElGamalRistretto255Ciphertext {
        const elgamalCiph = ElGamal.Ciphertext.decode(deserializer);
        const symmetricCiph = deserializer.deserializeBytes();
        const mac = deserializer.deserializeBytes();
        return new SimpleElGamalRistretto255Ciphertext(elgamalCiph, symmetricCiph, mac);
    }

    serialize(serializer: Serializer): void {
        this.elgamalCiph.encode(serializer);
        serializer.serializeBytes(this.symmetricCiph);
        serializer.serializeBytes(this.mac);
    }
}

export function keygen(): SimpleElGamalRistretto255DecKey {
    const encBase = Group.Element.rand();
    const privateScalar = Group.Scalar.rand();
    const elgamalDk = new ElGamal.DecKey(encBase, privateScalar);
    return new SimpleElGamalRistretto255DecKey(elgamalDk);
}

export function deriveEncryptionKey(dk: SimpleElGamalRistretto255DecKey): SimpleElGamalRistretto255EncKey {
    const { elgamalDk } = dk;
    const { encBase, privateScalar } = elgamalDk;
    const publicPoint = encBase.scale(privateScalar);
    const elgamalEk = new ElGamal.EncKey(encBase, publicPoint);
    return new SimpleElGamalRistretto255EncKey(elgamalEk);
}

export function encrypt(ek: SimpleElGamalRistretto255EncKey, msg: Uint8Array): SimpleElGamalRistretto255Ciphertext {
    const { elgamalEk } = ek;
    const elgamalPtxt = Group.Element.rand();
    const elgamalRand = Group.Scalar.rand();
    const elgamalCiph = ElGamal.enc(elgamalEk, elgamalRand, elgamalPtxt);
    const seed = elgamalPtxt.toBytes();
    const otp = kdf(seed, new TextEncoder().encode("OTP/SIMPLE_ELGAMAL_RISTRETTO255"), msg.length);
    const symmetricCiph = xorBytes(otp, msg);
    const hmacKey = kdf(seed, new TextEncoder().encode("HMAC/SIMPLE_ELGAMAL_RISTRETTO255"), 32);
    const mac = hmac_sha3_256(hmacKey, symmetricCiph);
    return new SimpleElGamalRistretto255Ciphertext(elgamalCiph, symmetricCiph, mac);
}

export function decrypt(
    dk: SimpleElGamalRistretto255DecKey,
    ciphertext: SimpleElGamalRistretto255Ciphertext,
): Uint8Array | undefined {
    const { elgamalDk } = dk;
    const { elgamalCiph, symmetricCiph, mac } = ciphertext;
    const elgamalPtxt = ElGamal.dec(elgamalDk, elgamalCiph);
    const seed = elgamalPtxt.toBytes();
    const hmacKey = kdf(seed, new TextEncoder().encode("HMAC/SIMPLE_ELGAMAL_RISTRETTO255"), 32);
    const macAnother = hmac_sha3_256(hmacKey, symmetricCiph);
    if (!mac.every((byte, index) => byte === macAnother[index])) {
        return undefined;
    }
    const otp = kdf(seed, new TextEncoder().encode("OTP/SIMPLE_ELGAMAL_RISTRETTO255"), symmetricCiph.length);
    return xorBytes(otp, symmetricCiph);
}
