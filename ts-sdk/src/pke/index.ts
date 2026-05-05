// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { Result } from "../result";
import * as ElGamalOtpRistretto255 from "./elgamal_otp_ristretto255";
import * as HpkeX25519ChaCha20Poly1305 from "./hpke_x25519_chacha20poly1305";

export const SCHEME_ELGAMAL_OTP_RISTRETTO255 = 0;
export const SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305 = 1;

type InnerEk =
    | ElGamalOtpRistretto255.EncryptionKey
    | HpkeX25519ChaCha20Poly1305.EncryptionKey;
type InnerDk =
    | ElGamalOtpRistretto255.DecryptionKey
    | HpkeX25519ChaCha20Poly1305.DecryptionKey;
type InnerCt =
    | ElGamalOtpRistretto255.Ciphertext
    | HpkeX25519ChaCha20Poly1305.Ciphertext;

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
    inner: InnerEk;

    constructor(scheme: number, inner: InnerEk) {
        this.scheme = scheme;
        this.inner = inner;
    }

    async deriveFromDecryptionKey(decryptionKey: DecryptionKey): Promise<EncryptionKey> {
        return deriveEncryptionKey(decryptionKey);
    }

    static deserialize(deserializer: Deserializer): Result<EncryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const scheme = deserializer.deserializeU8();
                if (scheme === SCHEME_ELGAMAL_OTP_RISTRETTO255) {
                    const inner = ElGamalOtpRistretto255.EncryptionKey.deserialize(deserializer)
                        .unwrapOrThrow("EncryptionKey.deserialize: ElGamal");
                    return new EncryptionKey(scheme, inner);
                }
                if (scheme === SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305) {
                    const inner = HpkeX25519ChaCha20Poly1305.EncryptionKey.deserialize(deserializer)
                        .unwrapOrThrow("EncryptionKey.deserialize: HPKE-X25519");
                    return new EncryptionKey(scheme, inner);
                }
                throw new Error(`Unknown PKE scheme: ${scheme}`);
            },
        });
    }

    static fromBytes(bytes: Uint8Array): Result<EncryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const key = EncryptionKey.deserialize(deserializer)
                    .unwrapOrThrow("EncryptionKey.fromBytes");
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
    scheme: number;
    inner: InnerDk;

    constructor(scheme: number, inner: InnerDk) {
        this.scheme = scheme;
        this.inner = inner;
    }

    static deserialize(deserializer: Deserializer): Result<DecryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const scheme = deserializer.deserializeU8();
                if (scheme === SCHEME_ELGAMAL_OTP_RISTRETTO255) {
                    const inner = ElGamalOtpRistretto255.DecryptionKey.deserialize(deserializer)
                        .unwrapOrThrow("DecryptionKey.deserialize: ElGamal");
                    return new DecryptionKey(scheme, inner);
                }
                if (scheme === SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305) {
                    const inner = HpkeX25519ChaCha20Poly1305.DecryptionKey.deserialize(deserializer)
                        .unwrapOrThrow("DecryptionKey.deserialize: HPKE-X25519");
                    return new DecryptionKey(scheme, inner);
                }
                throw new Error(`Unknown PKE scheme: ${scheme}`);
            },
        });
    }

    static fromBytes(bytes: Uint8Array): Result<DecryptionKey> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const key = DecryptionKey.deserialize(deserializer)
                    .unwrapOrThrow("DecryptionKey.fromBytes");
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
    scheme: number;
    inner: InnerCt;

    constructor(scheme: number, inner: InnerCt) {
        this.scheme = scheme;
        this.inner = inner;
    }

    static deserialize(deserializer: Deserializer): Result<Ciphertext> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const scheme = deserializer.deserializeU8();
                if (scheme === SCHEME_ELGAMAL_OTP_RISTRETTO255) {
                    const inner = ElGamalOtpRistretto255.Ciphertext.deserialize(deserializer)
                        .unwrapOrThrow("Ciphertext.deserialize: ElGamal");
                    return new Ciphertext(scheme, inner);
                }
                if (scheme === SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305) {
                    const inner = HpkeX25519ChaCha20Poly1305.Ciphertext.deserialize(deserializer)
                        .unwrapOrThrow("Ciphertext.deserialize: HPKE-X25519");
                    return new Ciphertext(scheme, inner);
                }
                throw new Error(`Unknown PKE scheme: ${scheme}`);
            },
        });
    }

    static fromBytes(bytes: Uint8Array): Result<Ciphertext> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const ciph = Ciphertext.deserialize(deserializer)
                    .unwrapOrThrow("Ciphertext.fromBytes");
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

    toHex(): string { return bytesToHex(this.toBytes()); }

    static fromHex(hex: string): Result<Ciphertext> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => Ciphertext.fromBytes(hexStringToBytes(hex))
                .unwrapOrThrow("Ciphertext.fromHex"),
        });
    }
}

/** Derive the encryption (public) key from a decryption (private) key. Async because some
 *  schemes (HPKE/WebCrypto) may compute via async primitives; for sync schemes the work is
 *  immediate but we keep a uniform Promise-returning shape. */
export async function deriveEncryptionKey(decryptionKey: DecryptionKey): Promise<EncryptionKey> {
    if (decryptionKey.scheme === SCHEME_ELGAMAL_OTP_RISTRETTO255) {
        const ek = ElGamalOtpRistretto255.deriveEncryptionKey(
            decryptionKey.inner as ElGamalOtpRistretto255.DecryptionKey,
        );
        return new EncryptionKey(decryptionKey.scheme, ek);
    }
    if (decryptionKey.scheme === SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305) {
        const ek = HpkeX25519ChaCha20Poly1305.deriveEncryptionKey(
            decryptionKey.inner as HpkeX25519ChaCha20Poly1305.DecryptionKey,
        );
        return new EncryptionKey(decryptionKey.scheme, ek);
    }
    throw new Error(`deriveEncryptionKey: unknown scheme ${decryptionKey.scheme}`);
}

/** Generate a fresh PKE keypair. The scheme parameter selects the underlying construction;
 *  defaults to ElGamalOtpRistretto255 for now. */
export async function keygen(
    scheme: number = SCHEME_ELGAMAL_OTP_RISTRETTO255,
): Promise<{ encryptionKey: EncryptionKey; decryptionKey: DecryptionKey }> {
    if (scheme === SCHEME_ELGAMAL_OTP_RISTRETTO255) {
        const dkInner = ElGamalOtpRistretto255.keygen();
        const ekInner = ElGamalOtpRistretto255.deriveEncryptionKey(dkInner);
        return {
            decryptionKey: new DecryptionKey(scheme, dkInner),
            encryptionKey: new EncryptionKey(scheme, ekInner),
        };
    }
    if (scheme === SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305) {
        const { encryptionKey: ekInner, decryptionKey: dkInner } =
            await HpkeX25519ChaCha20Poly1305.keygen();
        return {
            decryptionKey: new DecryptionKey(scheme, dkInner),
            encryptionKey: new EncryptionKey(scheme, ekInner),
        };
    }
    throw new Error(`keygen: unknown scheme ${scheme}`);
}

export async function encrypt({
    encryptionKey,
    plaintext,
}: {
    encryptionKey: EncryptionKey;
    plaintext: Uint8Array;
}): Promise<Ciphertext> {
    if (encryptionKey.scheme === SCHEME_ELGAMAL_OTP_RISTRETTO255) {
        const ct = ElGamalOtpRistretto255.encrypt({
            encryptionKey: encryptionKey.inner as ElGamalOtpRistretto255.EncryptionKey,
            plaintext,
        });
        return new Ciphertext(encryptionKey.scheme, ct);
    }
    if (encryptionKey.scheme === SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305) {
        const ct = await HpkeX25519ChaCha20Poly1305.encrypt({
            encryptionKey: encryptionKey.inner as HpkeX25519ChaCha20Poly1305.EncryptionKey,
            plaintext,
        });
        return new Ciphertext(encryptionKey.scheme, ct);
    }
    throw new Error(`encrypt: unknown scheme ${encryptionKey.scheme}`);
}

export async function decrypt({
    decryptionKey,
    ciphertext,
}: {
    decryptionKey: DecryptionKey;
    ciphertext: Ciphertext;
}): Promise<Result<Uint8Array>> {
    return Result.captureAsync({
        recordsExecutionTimeMs: false,
        task: async (extra: Record<string, any>) => {
            extra['dk_scheme'] = decryptionKey.scheme;
            extra['ciph_scheme'] = ciphertext.scheme;
            if (decryptionKey.scheme !== ciphertext.scheme) {
                throw new Error(
                    `decrypt: scheme mismatch (dk=${decryptionKey.scheme}, ct=${ciphertext.scheme})`,
                );
            }
            if (decryptionKey.scheme === SCHEME_ELGAMAL_OTP_RISTRETTO255) {
                return ElGamalOtpRistretto255.decrypt(
                    decryptionKey.inner as ElGamalOtpRistretto255.DecryptionKey,
                    ciphertext.inner as ElGamalOtpRistretto255.Ciphertext,
                ).unwrapOrThrow("ElGamalOtpRistretto255.decrypt failed");
            }
            if (decryptionKey.scheme === SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305) {
                const r = await HpkeX25519ChaCha20Poly1305.decrypt(
                    decryptionKey.inner as HpkeX25519ChaCha20Poly1305.DecryptionKey,
                    ciphertext.inner as HpkeX25519ChaCha20Poly1305.Ciphertext,
                );
                return r.unwrapOrThrow("HPKE-X25519.decrypt failed");
            }
            throw new Error(`decrypt: unknown scheme ${decryptionKey.scheme}`);
        },
    });
}
