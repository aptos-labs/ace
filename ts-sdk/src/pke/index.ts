// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { Result } from "../result";
import * as ElGamalOtpRistretto255 from "./elgamal_otp_ristretto255";

export const SCHEME_ELGAMAL_OTP_RISTRETTO255 = 0;

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
    inner: ElGamalOtpRistretto255.EncryptionKey;

    constructor(scheme: number, inner: ElGamalOtpRistretto255.EncryptionKey) {
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
                if (scheme === SCHEME_ELGAMAL_OTP_RISTRETTO255) {
                    const inner =
                        ElGamalOtpRistretto255.EncryptionKey.deserialize(deserializer);
                    return new EncryptionKey(scheme, inner.unwrapOrThrow("EncryptionKey.deserialize failed"));
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
    inner: ElGamalOtpRistretto255.DecryptionKey;

    constructor(scheme: number, inner: ElGamalOtpRistretto255.DecryptionKey) {
        this.scheme = scheme;
        this.inner = inner;
    }

    static deserialize(deserializer: Deserializer): Result<DecryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const scheme = deserializer.deserializeU8();
                if (scheme === SCHEME_ELGAMAL_OTP_RISTRETTO255) {
                    const inner =
                        ElGamalOtpRistretto255.DecryptionKey.deserialize(deserializer);
                    return new DecryptionKey(scheme, inner.unwrapOrThrow("DecryptionKey.deserialize failed"));
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
    inner: ElGamalOtpRistretto255.Ciphertext;

    constructor(scheme: number, inner: ElGamalOtpRistretto255.Ciphertext) {
        this.scheme = scheme;
        this.inner = inner;
    }

    static deserialize(deserializer: Deserializer): Result<Ciphertext> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const scheme = deserializer.deserializeU8();
                if (scheme === SCHEME_ELGAMAL_OTP_RISTRETTO255) {
                    const inner =
                        ElGamalOtpRistretto255.Ciphertext.deserialize(deserializer);
                    return new Ciphertext(scheme, inner.unwrapOrThrow("Ciphertext.deserialize failed"));
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
    if (dk.scheme === SCHEME_ELGAMAL_OTP_RISTRETTO255) {
        const ek = ElGamalOtpRistretto255.deriveEncryptionKey(dk.inner);
        return new EncryptionKey(dk.scheme, ek);
    }
    throw new Error(`Unknown scheme: ${dk.scheme}`);
}

/** Derive the ElGamal encryption key from a decryption key (same relationship as {@link keygen}). */
export function deriveEncryptionKey(decryptionKey: DecryptionKey): EncryptionKey {
    return deriveEncryptionKeyFromDecryptionKey(decryptionKey);
}

export function keygen(): { encryptionKey: EncryptionKey; decryptionKey: DecryptionKey } {
    const scheme = SCHEME_ELGAMAL_OTP_RISTRETTO255;
    const dkInner = ElGamalOtpRistretto255.keygen();
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
}): Ciphertext {
    if (encryptionKey.scheme === SCHEME_ELGAMAL_OTP_RISTRETTO255) {
        const ciphertext = ElGamalOtpRistretto255.encrypt({encryptionKey: encryptionKey.inner, plaintext});
        return new Ciphertext(encryptionKey.scheme, ciphertext);
    }
    throw 'unreachable';
}

export function decrypt({
    decryptionKey,
    ciphertext,
}: {
    decryptionKey: DecryptionKey;
    ciphertext: Ciphertext;
}): Result<Uint8Array> {
    return Result.capture({
        recordsExecutionTimeMs: false,
        task: (extra: Record<string, any>) => {
            extra['dk_scheme'] = decryptionKey.scheme;
            extra['ciph_scheme'] = ciphertext.scheme;
            if (decryptionKey.scheme !== ciphertext.scheme) {
                throw 'scheme mismatch';
            }
            if (decryptionKey.scheme === SCHEME_ELGAMAL_OTP_RISTRETTO255 && ciphertext.scheme === SCHEME_ELGAMAL_OTP_RISTRETTO255) {
                const plain = ElGamalOtpRistretto255.decrypt(decryptionKey.inner, ciphertext.inner).unwrapOrThrow("MAC verification failed");
                return plain;
            }
            throw 'decrypt: unknown scheme';
        },
    });
}
