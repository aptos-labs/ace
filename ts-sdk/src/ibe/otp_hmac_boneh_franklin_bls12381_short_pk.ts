// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { Fp2 } from "@noble/curves/abstract/tower";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
import { bls12_381 } from "@noble/curves/bls12-381";
import { bytesToNumberBE, bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils";
import { bytesToHex, randomBytes } from "@noble/hashes/utils";
import { hmac_sha3_256, kdf, xorBytes } from "../utils";
import { Result } from "../result";

const DST_OTP = new TextEncoder().encode("BONEH_FRANKLIN_BLS12381_SHORT_PK/OTP");
const DST_ID_HASH = new TextEncoder().encode("BONEH_FRANKLIN_BLS12381_SHORT_PK/HASH_ID_TO_CURVE");
const DST_MAC = new TextEncoder().encode("BONEH_FRANKLIN_BLS12381_SHORT_PK/MAC");

export class MasterPublicKey {
    base: WeierstrassPoint<bigint>;
    publicPointG1: WeierstrassPoint<bigint>;

    constructor(base: WeierstrassPoint<bigint>, publicPointG1: WeierstrassPoint<bigint>) {
        this.base = base;
        this.publicPointG1 = publicPointG1;
    }

    static deserialize(deserializer: Deserializer): Result<MasterPublicKey> {
        const task = (_extra: Record<string, any>) => {
            const baseBytes = deserializer.deserializeBytes();
            const base = bls12_381.G1.Point.fromBytes(baseBytes);
            const publicPointG1Bytes = deserializer.deserializeBytes();
            const publicPointG1 = bls12_381.G1.Point.fromBytes(publicPointG1Bytes);
            return new MasterPublicKey(base, publicPointG1);
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeBytes(this.base.toBytes());
        serializer.serializeBytes(this.publicPointG1.toBytes());
    }
}

export class MasterPrivateKey {
    base: WeierstrassPoint<bigint>;
    privateScalar: bigint;

    constructor(base: WeierstrassPoint<bigint>, privateScalar: bigint) {
        this.base = base;
        this.privateScalar = privateScalar;
    }

    static deserialize(deserializer: Deserializer): Result<MasterPrivateKey> {
        const task = (_extra: Record<string, any>) => {
            const baseBytes = deserializer.deserializeBytes();
            const base = bls12_381.G1.Point.fromBytes(baseBytes);
            const privateScalarBytes = deserializer.deserializeBytes();
            const privateScalar = BigInt('0x' + Array.from(privateScalarBytes).reverse().map(b => b.toString(16).padStart(2, '0')).join(''));
            return new MasterPrivateKey(base, privateScalar);
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeBytes(this.base.toBytes());
        serializer.serializeBytes(numberToBytesLE(this.privateScalar, 32));
    }
}

export class IdentityPrivateKey {
    privatePointG2: WeierstrassPoint<Fp2>;

    constructor(privatePointG2: WeierstrassPoint<Fp2>) {
        this.privatePointG2 = privatePointG2;
    }

    static deserialize(deserializer: Deserializer): Result<IdentityPrivateKey> {
        const task = (_extra: Record<string, any>) => {
            const privatePointG2Bytes = deserializer.deserializeBytes();
            const privatePointG2 = bls12_381.G2.Point.fromBytes(privatePointG2Bytes);
            return new IdentityPrivateKey(privatePointG2);
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeBytes(this.privatePointG2.toBytes());
    }
}

export class Ciphertext {
    c0: WeierstrassPoint<bigint>;
    symmetricCiph: Uint8Array;
    mac: Uint8Array;

    constructor(c0: WeierstrassPoint<bigint>, symmetricCiph: Uint8Array, mac: Uint8Array) {
        this.c0 = c0;
        this.symmetricCiph = symmetricCiph;
        this.mac = mac;
    }

    static deserialize(deserializer: Deserializer): Result<Ciphertext> {
        const task = (_extra: Record<string, any>) => {
            const c0Bytes = deserializer.deserializeBytes();
            const c0 = bls12_381.G1.Point.fromBytes(c0Bytes);
            const symmetricCiph = deserializer.deserializeBytes();
            const mac = deserializer.deserializeBytes();
            return new Ciphertext(c0, symmetricCiph, mac);
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeBytes(this.c0.toBytes());
        serializer.serializeBytes(this.symmetricCiph);
        serializer.serializeBytes(this.mac);
    }
}

export function keygen(): MasterPrivateKey {
    const base = bls12_381.G1.hashToCurve(randomBytes(32)) as unknown as WeierstrassPoint<bigint>;
    const privateScalar = bytesToNumberBE(bls12_381.utils.randomSecretKey());
    return new MasterPrivateKey(base, privateScalar);
}

export function derivePublicKey(privateKey: MasterPrivateKey): MasterPublicKey {
    const publicPoint = privateKey.base.multiply(privateKey.privateScalar);
    return new MasterPublicKey(privateKey.base, publicPoint);
}

export function encrypt(publicKey: MasterPublicKey, id: Uint8Array, plaintext: Uint8Array): Ciphertext {
    const r = bytesToNumberBE(bls12_381.utils.randomSecretKey());
    return encryptWithRandomness(publicKey, id, plaintext, numberToBytesLE(r, 32));
}

export function encryptWithRandomness(publicKey: MasterPublicKey, id: Uint8Array, plaintext: Uint8Array, randomness: Uint8Array): Ciphertext {
    const r = bytesToNumberLE(randomness);
    const idPoint = bls12_381.G2.hashToCurve(id, { DST: DST_ID_HASH }) as unknown as WeierstrassPoint<Fp2>;
    const seedElement = bls12_381.pairing(publicKey.publicPointG1.multiply(r), idPoint);
    const seed = bls12381GtReprNobleToAptos(bls12_381.fields.Fp12.toBytes(seedElement)).unwrapOrThrow('encryption failed with noble to aptos conversion');
    const otp = kdf(seed, DST_OTP, plaintext.length);
    const macKey = kdf(seed, DST_MAC, 32);
    const symmetricCiph = xorBytes(otp, plaintext);
    const mac = hmac_sha3_256(macKey, symmetricCiph);
    const c0 = publicKey.base.multiply(r);
    return new Ciphertext(c0, symmetricCiph, mac);
}

/**
 * Aptos Gt format is defined in https://github.com/aptos-labs/aptos-core/blob/46d871fa1feb61ffafb73353a0755e8cc3aaed9d/aptos-move/framework/aptos-stdlib/sources/cryptography/bls12381_algebra.move#L204.
 * Noble format is similar except that each Fp element is big-endian.
 */
function bls12381GtReprNobleToAptos(noble: Uint8Array): Result<Uint8Array> {
    const task = (_extra: Record<string, any>) => {
        if (noble.length !== 576) {
            throw 'bls12381GtReprNobleToAptos failed with incorrect input length';
        }
        
        const chunks = [];
        for (let i = 0; i < noble.length; i += 48) {
            chunks.push(noble.slice(i, i + 48).reverse());
        }
    
        const result = new Uint8Array(576);
        for (let i = 0; i < 12; i++) {
            result.set(chunks[i], i * 48);
        }
        return result;
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
}

export function extract(privateKey: MasterPrivateKey, id: Uint8Array): IdentityPrivateKey {
    const idPoint = bls12_381.G2.hashToCurve(id, { DST: DST_ID_HASH }) as unknown as WeierstrassPoint<Fp2>;
    const privatePointG2 = idPoint.multiply(privateKey.privateScalar);
    return new IdentityPrivateKey(privatePointG2);
}

export function decrypt(identityKey: IdentityPrivateKey, ciphertext: Ciphertext): Result<Uint8Array> {
    const task = (_extra: Record<string, any>) => {
        const seedElementGt = bls12_381.pairing(ciphertext.c0, identityKey.privatePointG2);
        const seed = bls12381GtReprNobleToAptos(bls12_381.fields.Fp12.toBytes(seedElementGt)).unwrapOrThrow('decryption failed with noble to aptos conversion');
        const macKey = kdf(seed, DST_MAC, 32);
        const macAnother = hmac_sha3_256(macKey, ciphertext.symmetricCiph);
        if (bytesToHex(ciphertext.mac) !== bytesToHex(macAnother)) {
            throw 'decryption failed with incorrect mac';
        }
        const otp = kdf(seed, DST_OTP, ciphertext.symmetricCiph.length);
        const plaintext = xorBytes(otp, ciphertext.symmetricCiph);
        return plaintext;
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
}

