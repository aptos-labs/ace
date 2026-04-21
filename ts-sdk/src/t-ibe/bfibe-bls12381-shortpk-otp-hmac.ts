// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

// A threshold IBE based on Boneh-Franklin IBE, where...
// - The underlying curve is BLS12-381.
// - The public key is in G1.
// - The symmetric cipher inside is a one-time pad.
// - HMAC-SHA3-256 is used for authentication.
// - In decryption, decryption key shares can together reconstruct and then it will be like normal Boneh-Franklin IBE decryption.

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { Fp2 } from "@noble/curves/abstract/tower";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
import { bls12_381 } from "@noble/curves/bls12-381";
import { bytesToNumberBE, bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils";
import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils";
import { frMod, frMul, frInv } from "../group/bls12381g1";
import { hmac_sha3_256, kdf, xorBytes } from "../utils";
import { Result } from "../result";

const DST_OTP = new TextEncoder().encode("BONEH_FRANKLIN_BLS12381_SHORT_PK/OTP");
const DST_ID_HASH = new TextEncoder().encode("BONEH_FRANKLIN_BLS12381_SHORT_PK/HASH_ID_TO_CURVE");
const DST_MAC = new TextEncoder().encode("BONEH_FRANKLIN_BLS12381_SHORT_PK/MAC");

export class MasterPublicKey {
    basePoint: WeierstrassPoint<bigint>;
    pk: WeierstrassPoint<bigint>;
    constructor(basePoint: WeierstrassPoint<bigint>, pk: WeierstrassPoint<bigint>) {
        this.basePoint = basePoint;
        this.pk = pk;
    }

    static deserialize(deserializer: Deserializer): Result<MasterPublicKey> {
        const task = (_extra: Record<string, any>) => {
            const baseBytes = deserializer.deserializeBytes();
            const base = bls12_381.G1.Point.fromBytes(baseBytes) as unknown as WeierstrassPoint<bigint>;
            const pkBytes = deserializer.deserializeBytes();
            const pk = bls12_381.G1.Point.fromBytes(pkBytes) as unknown as WeierstrassPoint<bigint>;
            return new MasterPublicKey(base, pk);
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeBytes((this.basePoint as any).toBytes());
        serializer.serializeBytes((this.pk as any).toBytes());
    }

    static fromBytes(bytes: Uint8Array): Result<MasterPublicKey> {
        const task = (_extra: Record<string, any>) => {
            const des = new Deserializer(bytes);
            const ret = MasterPublicKey.deserialize(des).unwrapOrThrow('MasterPublicKey.fromBytes failed');
            if (des.remaining() !== 0) throw 'MasterPublicKey.fromBytes: trailing bytes';
            return ret;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<MasterPublicKey> {
        const task = (_extra: Record<string, any>) =>
            MasterPublicKey.fromBytes(hexToBytes(hex)).unwrapOrThrow('MasterPublicKey.fromHex failed');
        return Result.capture({task, recordsExecutionTimeMs: false});
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

export class MasterPrivateKey {
    base: WeierstrassPoint<bigint>;
    scalar: bigint;

    constructor(base: WeierstrassPoint<bigint>, scalar: bigint) {
        this.base = base;
        this.scalar = scalar;
    }

    static deserialize(deserializer: Deserializer): Result<MasterPrivateKey> {
        const task = (_extra: Record<string, any>) => {
            const baseBytes = deserializer.deserializeBytes();
            const base = bls12_381.G1.Point.fromBytes(baseBytes) as unknown as WeierstrassPoint<bigint>;
            const scalarBytes = deserializer.deserializeBytes();
            const scalar = bytesToNumberLE(scalarBytes);
            return new MasterPrivateKey(base, scalar);
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeBytes((this.base as any).toBytes());
        serializer.serializeBytes(numberToBytesLE(this.scalar, 32));
    }

    static fromBytes(bytes: Uint8Array): Result<MasterPrivateKey> {
        const task = (_extra: Record<string, any>) => {
            const des = new Deserializer(bytes);
            const ret = MasterPrivateKey.deserialize(des).unwrapOrThrow('MasterPrivateKey.fromBytes failed');
            if (des.remaining() !== 0) throw 'MasterPrivateKey.fromBytes: trailing bytes';
            return ret;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<MasterPrivateKey> {
        const task = (_extra: Record<string, any>) =>
            MasterPrivateKey.fromBytes(hexToBytes(hex)).unwrapOrThrow('MasterPrivateKey.fromHex failed');
        return Result.capture({task, recordsExecutionTimeMs: false});
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

export class IdentityDecryptionKeyShare {
    evalPoint: bigint;
    idkShare: WeierstrassPoint<Fp2>;
    proof: Uint8Array | undefined;

    constructor(evalPoint: bigint, idkShare: WeierstrassPoint<Fp2>, proof: Uint8Array | undefined) {
        this.evalPoint = evalPoint;
        this.idkShare = idkShare;
        this.proof = proof;
    }

    serialize(serializer: Serializer): void {
        serializer.serializeBytes(numberToBytesLE(this.evalPoint, 32));
        serializer.serializeBytes(this.idkShare.toBytes());
        serializer.serializeU8(this.proof !== undefined ? 1 : 0);
        if (this.proof !== undefined) {
            serializer.serializeBytes(this.proof);
        }
    }

    static deserialize(deserializer: Deserializer): Result<IdentityDecryptionKeyShare> {
        const task = (_extra: Record<string, any>) => {
            const evalPointBytes = deserializer.deserializeBytes();
            if (evalPointBytes.length !== 32) throw 'IdentityDecryptionKeyShare: expected 32-byte evalPoint';
            const evalPoint = bytesToNumberLE(evalPointBytes);
            const idkShareBytes = deserializer.deserializeBytes();
            const idkShare = bls12_381.G2.Point.fromBytes(idkShareBytes) as unknown as WeierstrassPoint<Fp2>;
            const hasProof = deserializer.deserializeU8() !== 0;
            const proof = hasProof ? deserializer.deserializeBytes() : undefined;
            return new IdentityDecryptionKeyShare(evalPoint, idkShare, proof);
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<IdentityDecryptionKeyShare> {
        const task = (_extra: Record<string, any>) => {
            const des = new Deserializer(bytes);
            const ret = IdentityDecryptionKeyShare.deserialize(des).unwrapOrThrow('IdentityDecryptionKeyShare.fromBytes failed');
            if (des.remaining() !== 0) throw 'IdentityDecryptionKeyShare.fromBytes: trailing bytes';
            return ret;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<IdentityDecryptionKeyShare> {
        const task = (_extra: Record<string, any>) =>
            IdentityDecryptionKeyShare.fromBytes(hexToBytes(hex)).unwrapOrThrow('IdentityDecryptionKeyShare.fromHex failed');
        return Result.capture({task, recordsExecutionTimeMs: false});
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
            const c0 = bls12_381.G1.Point.fromBytes(c0Bytes) as unknown as WeierstrassPoint<bigint>;
            const symmetricCiph = deserializer.deserializeBytes();
            const mac = deserializer.deserializeBytes();
            return new Ciphertext(c0, symmetricCiph, mac);
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeBytes((this.c0 as any).toBytes());
        serializer.serializeBytes(this.symmetricCiph);
        serializer.serializeBytes(this.mac);
    }

    static fromBytes(bytes: Uint8Array): Result<Ciphertext> {
        const task = (_extra: Record<string, any>) => {
            const des = new Deserializer(bytes);
            const ret = Ciphertext.deserialize(des).unwrapOrThrow('Ciphertext.fromBytes failed');
            if (des.remaining() !== 0) throw 'Ciphertext.fromBytes: trailing bytes';
            return ret;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<Ciphertext> {
        const task = (_extra: Record<string, any>) =>
            Ciphertext.fromBytes(hexToBytes(hex)).unwrapOrThrow('Ciphertext.fromHex failed');
        return Result.capture({task, recordsExecutionTimeMs: false});
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

export function keygenForTesting(): MasterPrivateKey {
    const base = bls12_381.G1.hashToCurve(randomBytes(32)) as unknown as WeierstrassPoint<bigint>;
    const scalar = bytesToNumberBE(bls12_381.utils.randomSecretKey());
    return new MasterPrivateKey(base, scalar);
}

export function derivePublicKey(msk: MasterPrivateKey): MasterPublicKey {
    const pk = msk.base.multiply(msk.scalar);
    return new MasterPublicKey(msk.base, pk);
}

export function encryptWithRandomness(mpk: MasterPublicKey, id: Uint8Array, plaintext: Uint8Array, randomness: Uint8Array): Ciphertext {
    const r = bytesToNumberLE(randomness);
    const idPoint = bls12_381.G2.hashToCurve(id, { DST: DST_ID_HASH }) as unknown as WeierstrassPoint<Fp2>;
    const seedElement = bls12_381.pairing(mpk.pk.multiply(r), idPoint);
    const seed = bls12381GtReprNobleToAptos(bls12_381.fields.Fp12.toBytes(seedElement)).unwrapOrThrow('encryptWithRandomness: Gt conversion failed');
    const otp = kdf(seed, DST_OTP, plaintext.length);
    const macKey = kdf(seed, DST_MAC, 32);
    const symmetricCiph = xorBytes(otp, plaintext);
    const mac = hmac_sha3_256(macKey, symmetricCiph);
    const c0 = mpk.basePoint.multiply(r);
    return new Ciphertext(c0, symmetricCiph, mac);
}

export function encrypt({mpk, id, plaintext}: {mpk: MasterPublicKey, id: Uint8Array, plaintext: Uint8Array}): Result<Ciphertext> {
    const task = (_extra: Record<string, any>) => {
        const r = bytesToNumberBE(bls12_381.utils.randomSecretKey());
        return encryptWithRandomness(mpk, id, plaintext, numberToBytesLE(r, 32));
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
}

export function decrypt({idkShares, ciphertext}: {idkShares: IdentityDecryptionKeyShare[], ciphertext: Ciphertext}): Result<Uint8Array> {
    const task = (_extra: Record<string, any>) => {
        if (idkShares.length === 0) throw 'decrypt: no IDK shares provided';

        // Step 1: Lagrange interpolation in the exponent (G2).
        // Each share is (x_i = evalPoint_i, H(id)^{s_i}).
        // Compute idkFull = Σ_i λ_i * H(id)^{s_i} where λ_i are Lagrange coefficients at x=0.
        const xs = idkShares.map(s => frMod(s.evalPoint));
        for (let i = 0; i < xs.length; i++) {
            for (let j = i + 1; j < xs.length; j++) {
                if (xs[i] === xs[j]) throw 'decrypt: duplicate evalPoint';
            }
        }

        const lambdas: bigint[] = xs.map((xi, i) => {
            let lambda = 1n;
            for (let j = 0; j < xs.length; j++) {
                if (i === j) continue;
                // λ_i = Π_{j≠i} (0 - x_j) / (x_i - x_j)  in Fr
                lambda = frMul(lambda, frMul(frMod(-xs[j]), frInv(frMod(xi - xs[j]))));
            }
            return lambda;
        });

        let idkFull: WeierstrassPoint<Fp2> | null = null;
        for (let i = 0; i < idkShares.length; i++) {
            if (lambdas[i] === 0n) continue;
            const scaled = idkShares[i].idkShare.multiply(lambdas[i]);
            idkFull = idkFull === null ? scaled : idkFull.add(scaled);
        }
        if (idkFull === null) throw 'decrypt: all Lagrange coefficients were zero';

        // Step 2: Standard BF-IBE decryption using the reconstructed identity key.
        // pair(c0, idkFull) = pair(base^r, H(id)^s) = pair(base, H(id))^{rs} = pair(pk^r, H(id))
        const seedElement = bls12_381.pairing(ciphertext.c0, idkFull);
        const seed = bls12381GtReprNobleToAptos(bls12_381.fields.Fp12.toBytes(seedElement)).unwrapOrThrow('decrypt: Gt conversion failed');
        const macKey = kdf(seed, DST_MAC, 32);
        const macAnother = hmac_sha3_256(macKey, ciphertext.symmetricCiph);
        if (bytesToHex(ciphertext.mac) !== bytesToHex(macAnother)) {
            throw 'decrypt: MAC verification failed';
        }
        const otp = kdf(seed, DST_OTP, ciphertext.symmetricCiph.length);
        return xorBytes(otp, ciphertext.symmetricCiph);
    };
    return Result.capture({task, recordsExecutionTimeMs: true});
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
