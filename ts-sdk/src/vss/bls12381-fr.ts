// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Shamir secret sharing over BLS12-381 Fr with curve base in **G1**.
 * Secret is `(B, s)` with `B` a random G1 point and `s` ∈ Fr; public commitment is `(B, s·B)`.
 */

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { bls12_381 } from "@noble/curves/bls12-381";
import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { FR_MODULUS, frMod } from "../shamir_fr";
import { Result } from "../result";
import { lagrangeAtZero } from "./dealing";
import { randBytes } from "../utils";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";

export class Secret {
    private constructor(readonly scalar: bigint) {}

    static fromBigint(unchecked: bigint): Result<Secret> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                if (unchecked < 0n || unchecked >= FR_MODULUS) throw '';
                return new Secret(unchecked);
            },
        });
    }

    serialize(serializer: Serializer): void {
        serializer.serializeBytes(numberToBytesLE(this.scalar, 32));
    }

    static deserialize(deserializer: Deserializer): Result<Secret> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const sLe = deserializer.deserializeBytes();
                if (sLe.length !== 32) throw 'expected 32 bytes';
                const s = bytesToNumberLE(sLe);
                return Secret.fromBigint(s).unwrapOrThrow('value out of range');
            },
        });
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<Secret> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const secret = Secret.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return secret;
            },
        });
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<Secret> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const bytes = hexToBytes(hex);
                return Secret.fromBytes(bytes).unwrapOrThrow("deserialization failed");
            },
        });
    }
}

export class SecretShare {
    constructor(
        readonly x: bigint,
        readonly y: bigint,
    ) {
    }

    static fromBigints(uncheckedX: bigint, uncheckedY: bigint): Result<SecretShare> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                if (uncheckedX < 0n || uncheckedX >= FR_MODULUS) throw 'x out of range';
                if (uncheckedY < 0n || uncheckedY >= FR_MODULUS) throw 'y out of range';
                return new SecretShare(uncheckedX, uncheckedY);
            },
        });
    }

    serialize(serializer: Serializer): void {
        serializer.serializeBytes(numberToBytesLE(this.x, 32));
        serializer.serializeBytes(numberToBytesLE(this.y, 32));
    }

    static deserialize(deserializer: Deserializer): Result<SecretShare> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const xBytes = deserializer.deserializeBytes();
                if (xBytes.length !== 32) throw 'x: expected 32 bytes';
                const yBytes = deserializer.deserializeBytes();
                if (yBytes.length !== 32) throw 'y: expected 32 bytes';
                const x = bytesToNumberLE(xBytes);
                const y = bytesToNumberLE(yBytes);
                return SecretShare.fromBigints(x, y).unwrapOrThrow("values out of range");
            },
        });
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<SecretShare> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const share = SecretShare.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return share;
            },
        });
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<SecretShare> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const bytes = hexToBytes(hex);
                return SecretShare.fromBytes(bytes).unwrapOrThrow("deserialization failed");
            },
        });
    }
}

export class PcsCommitment {
    vValues: WeierstrassPoint<bigint>[];

    constructor(vValues: WeierstrassPoint<bigint>[]) {
        this.vValues = vValues;
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU32AsUleb128(this.vValues.length);
        for (const pt of this.vValues) {
            serializer.serializeBytes(pt.toBytes());
        }
    }

    static deserialize(deserializer: Deserializer): Result<PcsCommitment> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const len = deserializer.deserializeUleb128AsU32();
                const vValues: WeierstrassPoint<bigint>[] = [];
                for (let i = 0; i < len; i++) {
                    const ptBytes = deserializer.deserializeBytes();
                    const pt = bls12_381.G1.Point.fromBytes(ptBytes) as unknown as WeierstrassPoint<bigint>;
                    vValues.push(pt);
                }
                return new PcsCommitment(vValues);
            },
        });
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<PcsCommitment> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = PcsCommitment.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return obj;
            },
        });
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<PcsCommitment> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const bytes = hexToBytes(hex);
                return PcsCommitment.fromBytes(bytes).unwrapOrThrow("deserialization failed");
            },
        });
    }
}

export class PcsOpening {
    pEval: bigint;
    rEval: bigint;

    constructor(pEval: bigint, rEval: bigint) {
        this.pEval = pEval;
        this.rEval = rEval;
    }

    serialize(serializer: Serializer): void {
        serializer.serializeBytes(numberToBytesLE(this.pEval, 32));
        serializer.serializeBytes(numberToBytesLE(this.rEval, 32));
    }

    static deserialize(deserializer: Deserializer): Result<PcsOpening> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const pEvalBytes = deserializer.deserializeBytes();
                if (pEvalBytes.length !== 32) throw 'pEval: expected 32 bytes';
                const rEvalBytes = deserializer.deserializeBytes();
                if (rEvalBytes.length !== 32) throw 'rEval: expected 32 bytes';
                const pEval = bytesToNumberLE(pEvalBytes);
                if (pEval >= FR_MODULUS) throw 'pEval out of range';
                const rEval = bytesToNumberLE(rEvalBytes);
                if (rEval >= FR_MODULUS) throw 'rEval out of range';
                return new PcsOpening(pEval, rEval);
            },
        });
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<PcsOpening> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = PcsOpening.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return obj;
            },
        });
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<PcsOpening> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const bytes = hexToBytes(hex);
                return PcsOpening.fromBytes(bytes).unwrapOrThrow("deserialization failed");
            },
        });
    }
}

export class PcsBatchOpening {
    pEvals: bigint[];
    rEvals: bigint[];

    constructor(pEvals: bigint[], rEvals: bigint[]) {
        this.pEvals = pEvals;
        this.rEvals = rEvals;
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU32AsUleb128(this.pEvals.length);
        for (const v of this.pEvals) {
            serializer.serializeBytes(numberToBytesLE(v, 32));
        }
        serializer.serializeU32AsUleb128(this.rEvals.length);
        for (const v of this.rEvals) {
            serializer.serializeBytes(numberToBytesLE(v, 32));
        }
    }

    static deserialize(deserializer: Deserializer): Result<PcsBatchOpening> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const pLen = deserializer.deserializeUleb128AsU32();
                const pEvals: bigint[] = [];
                for (let i = 0; i < pLen; i++) {
                    const b = deserializer.deserializeBytes();
                    if (b.length !== 32) throw `pEvals[${i}]: expected 32 bytes`;
                    const v = bytesToNumberLE(b);
                    if (v >= FR_MODULUS) throw `pEvals[${i}] out of range`;
                    pEvals.push(v);
                }
                const rLen = deserializer.deserializeUleb128AsU32();
                const rEvals: bigint[] = [];
                for (let i = 0; i < rLen; i++) {
                    const b = deserializer.deserializeBytes();
                    if (b.length !== 32) throw `rEvals[${i}]: expected 32 bytes`;
                    const v = bytesToNumberLE(b);
                    if (v >= FR_MODULUS) throw `rEvals[${i}] out of range`;
                    rEvals.push(v);
                }
                if (pLen !== rLen) throw `pEvals length ${pLen} != rEvals length ${rLen}`;
                return new PcsBatchOpening(pEvals, rEvals);
            },
        });
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<PcsBatchOpening> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = PcsBatchOpening.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return obj;
            },
        });
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<PcsBatchOpening> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const bytes = hexToBytes(hex);
                return PcsBatchOpening.fromBytes(bytes).unwrapOrThrow("deserialization failed");
            },
        });
    }
}

export class DealerState {
    n: number;
    coefsPolyP: bigint[];
    coefsPolyR: bigint[];

    constructor(n: number, coefsPolyP: bigint[], coefsPolyR: bigint[]) {
        this.n = n;
        this.coefsPolyP = coefsPolyP;
        this.coefsPolyR = coefsPolyR;
    }
    
    serialize(serializer: Serializer): void {
        serializer.serializeU64(this.n);
        serializer.serializeU32AsUleb128(this.coefsPolyP.length);
        for (const coef of this.coefsPolyP) {
            serializer.serializeBytes(numberToBytesLE(coef, 32));
        }
        serializer.serializeU32AsUleb128(this.coefsPolyR.length);
        for (const coef of this.coefsPolyR) {
            serializer.serializeBytes(numberToBytesLE(coef, 32));
        }
    }

    static deserialize(deserializer: Deserializer): Result<DealerState> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const n = deserializer.deserializeU64();
                const coefsPolyPLen = deserializer.deserializeUleb128AsU32();
                const coefsPolyP: bigint[] = [];
                for (let i = 0; i < coefsPolyPLen; i++) {
                    const coef = deserializer.deserializeBytes();
                    if (coef.length !== 32) throw `coefsPolyP[${i}]: expected 32 bytes`;
                    const v = bytesToNumberLE(coef);
                    if (v >= FR_MODULUS) throw `coefsPolyP[${i}] out of range`;
                    coefsPolyP.push(v);
                }
                const coefsPolyRLen = deserializer.deserializeUleb128AsU32();
                const coefsPolyR: bigint[] = [];
                for (let i = 0; i < coefsPolyRLen; i++) {
                    const coef = deserializer.deserializeBytes();
                    if (coef.length !== 32) throw `coefsPolyR[${i}]: expected 32 bytes`;
                    const v = bytesToNumberLE(coef);
                    if (v >= FR_MODULUS) throw `coefsPolyR[${i}] out of range`;
                    coefsPolyR.push(v);
                }
                return new DealerState(Number(n), coefsPolyP, coefsPolyR);
            },
        });
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<DealerState> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = DealerState.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return obj;
            },
        });
    }
    
    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<DealerState> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => DealerState.fromBytes(hexToBytes(hex)).unwrapOrThrow("deserialization failed"),
        });
    }
}

export function sample(): Secret {
    const x = bytesToNumberLE(randBytes(64));
    const val = frMod(x);
    return Secret.fromBigint(val).unwrapOrThrow('unreachable');
}

export function reconstruct({ secretShares }: { secretShares: SecretShare[] }): Result<Secret> {
    return Result.capture({
        recordsExecutionTimeMs: false,
        task: () => {
            const points = secretShares.map((sh) => ({ x: sh.x, y: sh.y }));
            const sRec = lagrangeAtZero(points);
            return Secret.fromBigint(sRec).unwrapOrThrow('unreachable');
        },
    });
}
