// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import * as ElGamal from "./elgamal";
import * as Group from "./group";
import { hmac_sha3_256, kdf, xorBytes } from "../utils";
import { Result } from "../result";

function assertConsumed(d: Deserializer, label: string): void {
    if (d.remaining() !== 0) throw new Error(`${label}: trailing bytes`);
}

function hexStringToBytes(hex: string): Uint8Array {
    const h = hex.trim();
    return hexToBytes(h.startsWith("0x") || h.startsWith("0X") ? h.slice(2) : h);
}

export class EncryptionKey {
    elgamalEk: ElGamal.EncKey;

    constructor(elgamalEk: ElGamal.EncKey) {
        this.elgamalEk = elgamalEk;
    }

    static deserialize(deserializer: Deserializer): Result<EncryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const elgamalEk = ElGamal.EncKey.decode(deserializer);
                return new EncryptionKey(elgamalEk);
            },
        });
    }

    serialize(serializer: Serializer): void {
        this.elgamalEk.encode(serializer);
    }

    toBytes(): Uint8Array {
        const s = new Serializer();
        this.serialize(s);
        return s.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<EncryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const d = new Deserializer(bytes);
                const obj = EncryptionKey.deserialize(d).unwrapOrThrow("EncryptionKey.fromBytes");
                assertConsumed(d, "EncryptionKey.fromBytes");
                return obj;
            },
        });
    }

    toHex(): string { return bytesToHex(this.toBytes()); }

    static fromHex(hex: string): Result<EncryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => EncryptionKey.fromBytes(hexStringToBytes(hex))
                            .unwrapOrThrow("EncryptionKey.fromHex"),
        });
    }
}

export class DecryptionKey {
    elgamalDk: ElGamal.DecKey;

    constructor(elgamalDk: ElGamal.DecKey) {
        this.elgamalDk = elgamalDk;
    }

    static deserialize(deserializer: Deserializer): Result<DecryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const elgamalDk = ElGamal.DecKey.decode(deserializer);
                return new DecryptionKey(elgamalDk);
            },
        });
    }

    serialize(serializer: Serializer): void {
        this.elgamalDk.encode(serializer);
    }

    toBytes(): Uint8Array {
        const s = new Serializer();
        this.serialize(s);
        return s.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<DecryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const d = new Deserializer(bytes);
                const obj = DecryptionKey.deserialize(d).unwrapOrThrow("DecryptionKey.fromBytes");
                assertConsumed(d, "DecryptionKey.fromBytes");
                return obj;
            },
        });
    }

    toHex(): string { return bytesToHex(this.toBytes()); }

    static fromHex(hex: string): Result<DecryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => DecryptionKey.fromBytes(hexStringToBytes(hex))
                            .unwrapOrThrow("DecryptionKey.fromHex"),
        });
    }
}

export class Ciphertext {
    elgamalCiph: ElGamal.Ciphertext;
    symmetricCiph: Uint8Array;
    mac: Uint8Array;

    constructor(elgamalCiph: ElGamal.Ciphertext, symmetricCiph: Uint8Array, mac: Uint8Array) {
        this.elgamalCiph = elgamalCiph;
        this.symmetricCiph = symmetricCiph;
        this.mac = mac;
    }

    static deserialize(deserializer: Deserializer): Result<Ciphertext> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
        const elgamalCiph = ElGamal.Ciphertext.decode(deserializer);
        const symmetricCiph = deserializer.deserializeBytes();
        const mac = deserializer.deserializeBytes();
        return new Ciphertext(elgamalCiph, symmetricCiph, mac);
            },
        });
    }

    serialize(serializer: Serializer): void {
        this.elgamalCiph.encode(serializer);
        serializer.serializeBytes(this.symmetricCiph);
        serializer.serializeBytes(this.mac);
    }

    toBytes(): Uint8Array {
        const s = new Serializer();
        this.serialize(s);
        return s.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<Ciphertext> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const d = new Deserializer(bytes);
                const obj = Ciphertext.deserialize(d).unwrapOrThrow("Ciphertext.fromBytes");
                assertConsumed(d, "Ciphertext.fromBytes");
                return obj;
            },
        });
    }

    toHex(): string { return bytesToHex(this.toBytes()); }

    static fromHex(hex: string): Result<Ciphertext> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => Ciphertext.fromBytes(hexStringToBytes(hex))
                            .unwrapOrThrow("Ciphertext.fromHex"),
        });
    }
}

export function keygen(): DecryptionKey {
    const encBase = Group.Element.rand();
    const privateScalar = Group.Scalar.rand();
    const elgamalDk = new ElGamal.DecKey(encBase, privateScalar);
    return new DecryptionKey(elgamalDk);
}

export function deriveEncryptionKey(dk: DecryptionKey): EncryptionKey {
    const { elgamalDk } = dk;
    const { encBase, privateScalar } = elgamalDk;
    const publicPoint = encBase.scale(privateScalar);
    const elgamalEk = new ElGamal.EncKey(encBase, publicPoint);
    return new EncryptionKey(elgamalEk);
}

export function encrypt({encryptionKey, plaintext}: {encryptionKey: EncryptionKey, plaintext: Uint8Array}): Ciphertext {
    const { elgamalEk } = encryptionKey;
    const elgamalPtxt = Group.Element.rand();
    const elgamalRand = Group.Scalar.rand();
    const elgamalCiph = ElGamal.enc(elgamalEk, elgamalRand, elgamalPtxt);
    const seed = elgamalPtxt.toBytes();
    const otp = kdf(seed, new TextEncoder().encode("OTP/ELGAMAL_OTP_RISTRETTO255"), plaintext.length);
    const symmetricCiph = xorBytes(otp, plaintext);
    const hmacKey = kdf(seed, new TextEncoder().encode("HMAC/ELGAMAL_OTP_RISTRETTO255"), 32);
    const mac = hmac_sha3_256(hmacKey, symmetricCiph);
    return new Ciphertext(elgamalCiph, symmetricCiph, mac);
}

export function decrypt(
    dk: DecryptionKey,
    ciphertext: Ciphertext,
): Result<Uint8Array> {
    return Result.capture({
        recordsExecutionTimeMs: false,
        task: () => {
            const elgamalPtxt = ElGamal.dec(dk.elgamalDk, ciphertext.elgamalCiph);
            const seed = elgamalPtxt.toBytes(); // BCS-encoded, same as encrypt
            const otp = kdf(
                seed,
                new TextEncoder().encode("OTP/ELGAMAL_OTP_RISTRETTO255"),
                ciphertext.symmetricCiph.length,
            );
            const hmacKey = kdf(seed, new TextEncoder().encode("HMAC/ELGAMAL_OTP_RISTRETTO255"), 32);
            const expectedMac = hmac_sha3_256(hmacKey, ciphertext.symmetricCiph);
            // Timing-safe MAC comparison
            if (expectedMac.length !== ciphertext.mac.length) throw new Error("MAC verification failed");
            let diff = 0;
            for (let i = 0; i < expectedMac.length; i++) diff |= expectedMac[i] ^ ciphertext.mac[i];
            if (diff !== 0) throw new Error("MAC verification failed");
            return xorBytes(otp, ciphertext.symmetricCiph);
        },
    });
}
