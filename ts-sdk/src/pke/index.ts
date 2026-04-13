// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { Result } from "../result";
import * as SimpleElGamalRistretto255 from "./simple_elgamal_ristretto255";

export const SCHEME_SIMPLE_ELGAMAL_RISTRETTO255 = 0;

function hexStringToBytes(hex: string): Uint8Array {
    const h = hex.trim();
    const noPrefix = h.startsWith("0x") || h.startsWith("0X") ? h.slice(2) : h;
    return hexToBytes(noPrefix);
}

function assertDeserializerConsumed(deserializer: Deserializer, label: string): void {
    if (deserializer.remaining() !== 0) {
        throw new Error(`${label}: trailing bytes after deserialization`);
    }
}

export class EncryptionKey {
    scheme: number;
    inner: SimpleElGamalRistretto255.SimpleElGamalRistretto255EncKey;

    constructor(scheme: number, inner: SimpleElGamalRistretto255.SimpleElGamalRistretto255EncKey) {
        this.scheme = scheme;
        this.inner = inner;
    }

    deriveFromDecryptionKey(decryptionKey: DecryptionKey): EncryptionKey {
        return deriveEncryptionKeyFromDecryptionKey(decryptionKey);
    }

    static deserialize(deserializer: Deserializer): Result<EncryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const scheme = deserializer.deserializeU8();
                if (scheme === SCHEME_SIMPLE_ELGAMAL_RISTRETTO255) {
                    const inner =
                        SimpleElGamalRistretto255.SimpleElGamalRistretto255EncKey.deserialize(deserializer);
                    return new EncryptionKey(scheme, inner);
                }
                throw new Error(`Unknown scheme: ${scheme}`);
            },
        });
    }

    static fromBytes(bytes: Uint8Array): Result<EncryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const key = EncryptionKey.deserialize(deserializer).unwrapOrThrow(
                    "EncryptionKey.deserialize failed",
                );
                assertDeserializerConsumed(deserializer, "EncryptionKey.fromBytes");
                return key;
            },
        });
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        this.inner.serialize(serializer);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<EncryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () =>
                EncryptionKey.fromBytes(hexStringToBytes(hex)).unwrapOrThrow(
                    "EncryptionKey.hex deserialization failed",
                ),
        });
    }
}

export class DecryptionKey {
    scheme: number;
    inner: SimpleElGamalRistretto255.SimpleElGamalRistretto255DecKey;

    constructor(scheme: number, inner: SimpleElGamalRistretto255.SimpleElGamalRistretto255DecKey) {
        this.scheme = scheme;
        this.inner = inner;
    }

    static deserialize(deserializer: Deserializer): Result<DecryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const scheme = deserializer.deserializeU8();
                if (scheme === SCHEME_SIMPLE_ELGAMAL_RISTRETTO255) {
                    const inner =
                        SimpleElGamalRistretto255.SimpleElGamalRistretto255DecKey.deserialize(deserializer);
                    return new DecryptionKey(scheme, inner);
                }
                throw new Error(`Unknown scheme: ${scheme}`);
            },
        });
    }

    static fromBytes(bytes: Uint8Array): Result<DecryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const key = DecryptionKey.deserialize(deserializer).unwrapOrThrow(
                    "DecryptionKey.deserialize failed",
                );
                assertDeserializerConsumed(deserializer, "DecryptionKey.fromBytes");
                return key;
            },
        });
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        this.inner.serialize(serializer);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<DecryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () =>
                DecryptionKey.fromBytes(hexStringToBytes(hex)).unwrapOrThrow(
                    "DecryptionKey.hex deserialization failed",
                ),
        });
    }
}

export class Ciphertext {
    scheme: number;
    inner: SimpleElGamalRistretto255.SimpleElGamalRistretto255Ciphertext;

    constructor(scheme: number, inner: SimpleElGamalRistretto255.SimpleElGamalRistretto255Ciphertext) {
        this.scheme = scheme;
        this.inner = inner;
    }

    static deserialize(deserializer: Deserializer): Result<Ciphertext> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const scheme = deserializer.deserializeU8();
                if (scheme === SCHEME_SIMPLE_ELGAMAL_RISTRETTO255) {
                    const inner =
                        SimpleElGamalRistretto255.SimpleElGamalRistretto255Ciphertext.deserialize(deserializer);
                    return new Ciphertext(scheme, inner);
                }
                throw new Error(`Unknown scheme: ${scheme}`);
            },
        });
    }

    static fromBytes(bytes: Uint8Array): Result<Ciphertext> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const ciph = Ciphertext.deserialize(deserializer).unwrapOrThrow("Ciphertext.deserialize failed");
                assertDeserializerConsumed(deserializer, "Ciphertext.fromBytes");
                return ciph;
            },
        });
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        this.inner.serialize(serializer);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<Ciphertext> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () =>
                Ciphertext.fromBytes(hexStringToBytes(hex)).unwrapOrThrow("Ciphertext.hex deserialization failed"),
        });
    }
}

function deriveEncryptionKeyFromDecryptionKey(dk: DecryptionKey): EncryptionKey {
    if (dk.scheme === SCHEME_SIMPLE_ELGAMAL_RISTRETTO255) {
        const ek = SimpleElGamalRistretto255.deriveEncryptionKey(dk.inner);
        return new EncryptionKey(dk.scheme, ek);
    }
    throw new Error(`Unknown scheme: ${dk.scheme}`);
}

/** Derive the ElGamal encryption key from a decryption key (same relationship as {@link keygen}). */
export function deriveEncryptionKey(decryptionKey: DecryptionKey): EncryptionKey {
    return deriveEncryptionKeyFromDecryptionKey(decryptionKey);
}

export function keygen(): { encryptionKey: EncryptionKey; decryptionKey: DecryptionKey } {
    const scheme = SCHEME_SIMPLE_ELGAMAL_RISTRETTO255;
    const dkInner = SimpleElGamalRistretto255.keygen();
    const decryptionKey = new DecryptionKey(scheme, dkInner);
    const encryptionKey = deriveEncryptionKeyFromDecryptionKey(decryptionKey);
    return { encryptionKey, decryptionKey };
}

export function encrypt({
    encryptionKey,
    plaintext,
}: {
    encryptionKey: EncryptionKey;
    plaintext: Uint8Array;
}): Uint8Array {
    if (encryptionKey.scheme === SCHEME_SIMPLE_ELGAMAL_RISTRETTO255) {
        const ciphertext = SimpleElGamalRistretto255.encrypt(encryptionKey.inner, plaintext);
        return new Ciphertext(encryptionKey.scheme, ciphertext).toBytes();
    }
    throw new Error(`Unknown scheme: ${encryptionKey.scheme}`);
}

export function decrypt({
    decryptionKey,
    ciphertext,
}: {
    decryptionKey: DecryptionKey;
    ciphertext: Uint8Array;
}): Result<Uint8Array> {
    return Result.capture({
        recordsExecutionTimeMs: false,
        task: (extra: Record<string, any>) => {
            const ciph = Ciphertext.fromBytes(ciphertext).unwrapOrThrow("Ciphertext.fromBytes failed");
            extra['dk_scheme'] = decryptionKey.scheme;
            extra['ciph_scheme'] = ciph.scheme;
            if (decryptionKey.scheme !== ciph.scheme) {
                throw 'scheme mismatch';
            }
            if (decryptionKey.scheme === SCHEME_SIMPLE_ELGAMAL_RISTRETTO255 && ciph.scheme === SCHEME_SIMPLE_ELGAMAL_RISTRETTO255) {
                const plain = SimpleElGamalRistretto255.decrypt(decryptionKey.inner, ciph.inner);
                if (plain === undefined) {
                    throw 'MAC verification failed';
                }
                return plain;
            }
            throw 'unknown scheme';
        },
    });
}
