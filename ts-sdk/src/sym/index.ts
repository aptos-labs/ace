// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import * as AES256GCM from "./aes256gcm";
import { Result } from "../result";

/**
 * AES-256-GCM symmetric encryption scheme.
 * - Key: 256-bit (32 bytes)
 * - IV/Nonce: 96-bit (12 bytes)
 * - Tag: 128-bit (16 bytes)
 */
export const SCHEME_AES256GCM = 0;

export class Key {
    readonly scheme: number;
    /** @internal */
    readonly inner: any;

    private constructor(scheme: number, inner: any) {
        this.scheme = scheme;
        this.inner = inner;
    }

    /** @internal */
    static _create(scheme: number, inner: any): Key {
        return new Key(scheme, inner);
    }

    static deserialize(deserializer: Deserializer): Result<Key> {
        const task = (_extra: Record<string, any>) => {
            const scheme = deserializer.deserializeU8();
            if (scheme === SCHEME_AES256GCM) {
                const inner = AES256GCM.Key.deserialize(deserializer).unwrapOrThrow('Key inner deserialization failed');
                return new Key(scheme, inner);
            }
            throw `Key deserialization failed with unknown scheme: ${scheme}`;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }
    
    static fromBytes(bytes: Uint8Array): Result<Key> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            const result = Key.deserialize(deserializer).unwrapOrThrow('Key deserialization failed');
            if (deserializer.remaining() !== 0) {
                throw 'Key deserialization failed with trailing bytes';
            }
            return result;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<Key> {
        const task = (_extra: Record<string, any>) => {
            return Key.fromBytes(hexToBytes(hex)).unwrapOrThrow('Key hex deserialization failed');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        (this.inner as AES256GCM.Key).serialize(serializer);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }
}

export class Ciphertext {
    readonly scheme: number;
    /** @internal */
    readonly inner: any;

    private constructor(scheme: number, inner: any) {
        this.scheme = scheme;
        this.inner = inner;
    }

    /** @internal */
    static _create(scheme: number, inner: any): Ciphertext {
        return new Ciphertext(scheme, inner);
    }

    static dummy(): Ciphertext {
        return new Ciphertext(SCHEME_AES256GCM, AES256GCM.Ciphertext.dummy());
    }

    static deserialize(deserializer: Deserializer): Result<Ciphertext> {
        const task = (extra: Record<string, any>) => {
            const scheme = deserializer.deserializeU8();
            extra['scheme'] = scheme;
            if (scheme === SCHEME_AES256GCM) {
                const inner = AES256GCM.Ciphertext.deserialize(deserializer).unwrapOrThrow('Sym.Ciphertext.deserialize failed with AES256GCM inner deserialization error');
                return new Ciphertext(scheme, inner);
            }
            throw 'Sym.Ciphertext.deserialize failed with unknown scheme';
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<Ciphertext> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            const result = Ciphertext.deserialize(deserializer).unwrapOrThrow('Sym.Ciphertext.fromBytes failed with deserialization error');
            if (deserializer.remaining() !== 0) {
                throw 'Sym.Ciphertext.fromBytes failed with trailing bytes';
            }
            return result;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<Ciphertext> {
        const task = (_extra: Record<string, any>) => {
            return Ciphertext.fromBytes(hexToBytes(hex)).unwrapOrThrow('Ciphertext hex deserialization failed');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        (this.inner as AES256GCM.Ciphertext).serialize(serializer);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }
}

export function keygen(scheme?: number): Result<Key> {
    const task = (_extra: Record<string, any>) => {
        if (scheme === undefined) {
            scheme = SCHEME_AES256GCM;
        }
        if (scheme === SCHEME_AES256GCM) {
            return Key._create(SCHEME_AES256GCM, AES256GCM.keygen());
        }
        throw 'keygen failed with unknown scheme';
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
}

export function encrypt(key: Key, plaintext: Uint8Array): Result<Ciphertext> {
    const task = (extra: Record<string, any>) => {
        extra['scheme'] = key.scheme;
        if (key.scheme === SCHEME_AES256GCM) {
            return Ciphertext._create(SCHEME_AES256GCM, AES256GCM.encrypt(key.inner as AES256GCM.Key, plaintext));
        }
        throw 'Sym.encrypt failed with unknown scheme';
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
}

/** Do NOT use this, unless you are a maintainer. Use `encrypt` instead. */
export function encryptWithRandomness(key: Key, plaintext: Uint8Array, randomness: Uint8Array): Result<Ciphertext> {
    const task = (extra: Record<string, any>) => {
        extra['scheme'] = key.scheme;
        if (key.scheme === SCHEME_AES256GCM) {
            return Ciphertext._create(SCHEME_AES256GCM, AES256GCM.encryptWithRandomness(key.inner as AES256GCM.Key, plaintext, randomness));
        }
        throw 'Sym.encryptWithRandomness failed with unknown scheme';
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
}

export function decrypt(key: Key, ciphertext: Ciphertext): Result<Uint8Array> {
    const task = (extra: Record<string, any>) => {
        extra['ciphertext_scheme'] = ciphertext.scheme;
        extra['key_scheme'] = key.scheme;
        if (ciphertext.scheme !== key.scheme) {
            throw 'Sym.decrypt failed with mismatched schemes';
        }
        if (key.scheme === SCHEME_AES256GCM) {
            const innerResult = AES256GCM.decrypt(key.inner as AES256GCM.Key, ciphertext.inner as AES256GCM.Ciphertext);
            return innerResult.unwrapOrThrow('Sym.decrypt failed with AES256GCM decryption error');
        }
        throw 'Sym.decrypt failed with unknown scheme';
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
}

