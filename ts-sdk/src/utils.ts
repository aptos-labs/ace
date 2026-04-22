// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Serializer } from "@aptos-labs/ts-sdk";
import { bytesToNumberLE } from "@noble/curves/utils";
import { sha3_256 as nobleSha3_256, sha3_512 as nobleSha3_512 } from "@noble/hashes/sha3";

export function randU64(): bigint {
    return bytesToNumberLE(randBytes(8));
}

/** Cryptographically strong when `crypto.getRandomValues` is available. */
export function randBytes(length: number): Uint8Array {
    if (typeof crypto !== "undefined" && crypto.getRandomValues) {
        return crypto.getRandomValues(new Uint8Array(length));
    }
    const bytes = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
        bytes[i] = Math.floor(Math.random() * 256);
    }
    return bytes;
}

export function xorBytes(blinder: Uint8Array<ArrayBufferLike>, plaintext: Uint8Array<ArrayBufferLike>): Uint8Array {
    if (blinder.length != plaintext.length) {
        throw new Error("Blinder and plaintext must be the same length");
    }
    return new Uint8Array(blinder.map((byte, index) => byte ^ plaintext[index]));
}

export function concatBytes(a: Uint8Array, b: Uint8Array): Uint8Array {
    const result = new Uint8Array(a.length + b.length);
    result.set(a, 0);
    result.set(b, a.length);
    return result;
}

class KeyBlockDeriveInput {
    seed: Uint8Array;
    dst: Uint8Array;
    targetLength: number;
    blockIndex: number;

    constructor(seed: Uint8Array, dst: Uint8Array, targetLength: number, blockIndex: number) {
        this.seed = seed;
        this.dst = dst;
        this.targetLength = targetLength;
        this.blockIndex = blockIndex;
    }

    serialize(serializer: Serializer) {
        serializer.serializeBytes(this.seed);
        serializer.serializeBytes(this.dst);
        serializer.serializeU64(this.targetLength);
        serializer.serializeU64(this.blockIndex);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }
}

export function kdf(seed: Uint8Array, dst: Uint8Array, targetLength: number): Uint8Array {
    if (seed.length < 32) {
        throw new Error("Seed must be at least 32 bytes");
    }
    let blockPreImage = new KeyBlockDeriveInput(seed, dst, targetLength, 0);
    let output: Uint8Array = new Uint8Array(0);
    while (targetLength > 0) {
        let blockOutput = new Uint8Array(sha3_256(blockPreImage.toBytes()).slice(0, Math.min(32, targetLength)));
        output = concatBytes(output, blockOutput);
        targetLength -= blockOutput.length;
        blockPreImage.blockIndex++;
    }
    return output;
}

export function hmac_sha3_256(key: Uint8Array, message: Uint8Array): Uint8Array {
    if (key.length !== 32) {
        throw new Error("Key must be 32 bytes");
    }
    key = concatBytes(key, new Uint8Array(32));
    let ipad = new Uint8Array(64);
    let opad = new Uint8Array(64);
    for (let i = 0; i < 64; i++) {
        ipad[i] = 0x36;
        opad[i] = 0x5c;
    }
    const innerInput = concatBytes(xorBytes(ipad, key), message);
    const outerInput = concatBytes(xorBytes(opad, key), sha3_256(innerInput));
    return sha3_256(outerInput);
}

export function sha3_256(message: Uint8Array): Uint8Array {
    return nobleSha3_256(message);
}

export function sha3_512(message: Uint8Array): Uint8Array {
    return nobleSha3_512(message);
}

