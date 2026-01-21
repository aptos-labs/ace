// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { gcm } from "@noble/ciphers/aes";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { Result } from "../result";

export class Key {
    /** @internal */
    readonly inner: Uint8Array;

    private constructor(inner: Uint8Array) {
        this.inner = inner;
    }

    /** @internal */
    static _create(inner: Uint8Array): Key {
        return new Key(inner);
    }

    static deserialize(deserializer: Deserializer): Result<Key> {
        const task = (_extra: Record<string, any>) => {
            const inner = deserializer.deserializeFixedBytes(32);
            return new Key(inner);
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
        serializer.serializeFixedBytes(this.inner);
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
    /** @internal */
    readonly iv: Uint8Array;
    /** @internal */
    readonly ct: Uint8Array;
    /** @internal */
    readonly tag: Uint8Array;

    private constructor(iv: Uint8Array, ct: Uint8Array, tag: Uint8Array) {
        this.iv = iv;
        this.ct = ct;
        this.tag = tag;
    }

    /** @internal */
    static _create(iv: Uint8Array, ct: Uint8Array, tag: Uint8Array): Ciphertext {
        return new Ciphertext(iv, ct, tag);
    }

    static dummy(): Ciphertext {
        return new Ciphertext(new Uint8Array(12), new Uint8Array(0), new Uint8Array(16));
    }

    static deserialize(deserializer: Deserializer): Result<Ciphertext> {
        const task = (_extra: Record<string, any>) => {
            const iv = deserializer.deserializeFixedBytes(12);
            const ct = deserializer.deserializeBytes();
            const tag = deserializer.deserializeFixedBytes(16);
            return new Ciphertext(iv, ct, tag);
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<Ciphertext> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            const result = Ciphertext.deserialize(deserializer).unwrapOrThrow('Ciphertext deserialization failed');
            if (deserializer.remaining() !== 0) {
                throw 'Ciphertext deserialization failed with trailing bytes';
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
        serializer.serializeFixedBytes(this.iv);
        serializer.serializeBytes(this.ct);
        serializer.serializeFixedBytes(this.tag);
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

export function keygen(): Key {
    const keyBytes = new Uint8Array(32);
    crypto.getRandomValues(keyBytes);
    return Key._create(keyBytes);
}

export function encrypt(key: Key, plaintext: Uint8Array): Ciphertext {
    const nonce = new Uint8Array(12);
    crypto.getRandomValues(nonce);
    return encryptWithRandomness(key, plaintext, nonce);
}

export function encryptWithRandomness(key: Key, plaintext: Uint8Array, randomness: Uint8Array): Ciphertext {
    const nonce = randomness.slice(0, 12);
    const gcmInstance = gcm(key.inner, nonce);
    const encrypted = gcmInstance.encrypt(plaintext);
    const tagLength = 16;
    const ciphertext = encrypted.slice(0, -tagLength);
    const tag = encrypted.slice(-tagLength);
    return Ciphertext._create(nonce, ciphertext, tag);
}

export function decrypt(key: Key, ciphertext: Ciphertext): Result<Uint8Array> {
    const task = (_extra: Record<string, any>) => {
        const gcmInstance = gcm(key.inner, ciphertext.iv);
        const encryptedData = new Uint8Array(ciphertext.ct.length + ciphertext.tag.length);
        encryptedData.set(ciphertext.ct, 0);
        encryptedData.set(ciphertext.tag, ciphertext.ct.length);
        return gcmInstance.decrypt(encryptedData);
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
}

