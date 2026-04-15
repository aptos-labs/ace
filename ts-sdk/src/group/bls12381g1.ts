// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Feldman VSS over BLS12-381: secrets in Fr, commitments in G1.
 *
 * - PrivateScalar: a secret s ∈ Fr.
 * - PublicPoint: a G1 element (used in Feldman commitment: g^{a_k}).
 * - SecretShare: the evaluation y = f(i) ∈ Fr for holder at index i (1-indexed; x is implicit).
 * - PcsCommitment: t G1 points [g^{a_0}, ..., g^{a_{t-1}}] (Feldman commitment).
 * - DealerState: dealer's polynomial coefficients [a_0, ..., a_{t-1}] (a_0 = secret).
 */

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { bls12_381 } from "@noble/curves/bls12-381";
import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { FR_MODULUS, frMod } from "../shamir_fr";
import { Result } from "../result";
import { lagrangeAtZero } from "../vss/dealing";
import { randBytes } from "../utils";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";

// ── PrivateScalar ─────────────────────────────────────────────────────────────

export class PrivateScalar {
    private constructor(readonly scalar: bigint) {}

    static fromBigint(unchecked: bigint): Result<PrivateScalar> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                if (unchecked < 0n || unchecked >= FR_MODULUS) throw '';
                return new PrivateScalar(unchecked);
            },
        });
    }

    serialize(serializer: Serializer): void {
        serializer.serializeBytes(numberToBytesLE(this.scalar, 32));
    }

    static deserialize(deserializer: Deserializer): Result<PrivateScalar> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const sLe = deserializer.deserializeBytes();
                if (sLe.length !== 32) throw 'expected 32 bytes';
                const s = bytesToNumberLE(sLe);
                return PrivateScalar.fromBigint(s).unwrapOrThrow('value out of range');
            },
        });
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<PrivateScalar> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const secret = PrivateScalar.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return secret;
            },
        });
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<PrivateScalar> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const bytes = hexToBytes(hex);
                return PrivateScalar.fromBytes(bytes).unwrapOrThrow("deserialization failed");
            },
        });
    }
}

// ── PublicPoint ───────────────────────────────────────────────────────────────

/** A BLS12-381 G1 element. Wire format: [uleb128(48)][48-byte compressed G1]. */
/** Returns the BLS12-381 G1 generator as a PublicPoint. */
export function g1Generator(): PublicPoint {
    return new PublicPoint(bls12_381.G1.ProjectivePoint.BASE as unknown as WeierstrassPoint<bigint>);
}

export class PublicPoint {
    constructor(readonly pt: WeierstrassPoint<bigint>) {}

    /** Parse from raw 48-byte compressed G1 bytes (not BCS-encoded). */
    static fromRawBytes(rawBytes: Uint8Array): Result<PublicPoint> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                if (rawBytes.length !== 48) throw 'expected 48 bytes';
                const pt = bls12_381.G1.ProjectivePoint.fromHex(rawBytes) as unknown as WeierstrassPoint<bigint>;
                return new PublicPoint(pt);
            },
        });
    }

    /** Raw 48-byte compressed G1 bytes. */
    rawBytes(): Uint8Array {
        return (this.pt as any).toBytes();
    }

    /** Serialize as BCS bytes field: [uleb128(48)][48 bytes]. */
    serialize(serializer: Serializer): void {
        serializer.serializeBytes(this.rawBytes());
    }

    /** BCS-encoded bytes (same as what serialize() writes). */
    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    static deserialize(deserializer: Deserializer): Result<PublicPoint> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const ptBytes = deserializer.deserializeBytes();
                return PublicPoint.fromRawBytes(ptBytes).unwrapOrThrow('invalid G1 point');
            },
        });
    }

    static fromBytes(bytes: Uint8Array): Result<PublicPoint> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = PublicPoint.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return obj;
            },
        });
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    /** Scalar multiplication: returns scalar * this. */
    scale(scalar: PrivateScalar): PublicPoint {
        const result = (this.pt as any).multiply(scalar.scalar);
        return new PublicPoint(result as unknown as WeierstrassPoint<bigint>);
    }

    /** Projective equality check. */
    equals(other: PublicPoint): boolean {
        return (this.pt as any).equals(other.pt);
    }
}

// ── SecretShare ───────────────────────────────────────────────────────────────

/**
 * A Feldman share for holder at (implicit) index i: y = f(i) ∈ Fr.
 * The evaluation point x = i is implicit (1-indexed by position in share_holders list).
 * Wire format: [uleb128(32)][32-byte Fr LE].
 */
export class SecretShare {
    constructor(readonly y: bigint) {}

    static fromBigint(uncheckedY: bigint): Result<SecretShare> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                if (uncheckedY < 0n || uncheckedY >= FR_MODULUS) throw 'y out of range';
                return new SecretShare(uncheckedY);
            },
        });
    }

    serialize(serializer: Serializer): void {
        serializer.serializeBytes(numberToBytesLE(this.y, 32));
    }

    static deserialize(deserializer: Deserializer): Result<SecretShare> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const yBytes = deserializer.deserializeBytes();
                if (yBytes.length !== 32) throw 'expected 32 bytes';
                const y = bytesToNumberLE(yBytes);
                return SecretShare.fromBigint(y).unwrapOrThrow("value out of range");
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

// ── PcsCommitment ─────────────────────────────────────────────────────────────

/**
 * Feldman polynomial commitment: t G1 points [g^{a_0}, ..., g^{a_{t-1}}].
 * Wire format (no scheme prefix): [uleb128 t] { [uleb128(48)] [48-byte G1] } × t.
 */
export class PcsCommitment {
    constructor(readonly vValues: WeierstrassPoint<bigint>[]) {}

    serialize(serializer: Serializer): void {
        serializer.serializeU32AsUleb128(this.vValues.length);
        for (const pt of this.vValues) {
            serializer.serializeBytes((pt as any).toBytes());
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
                    const pt = bls12_381.G1.ProjectivePoint.fromHex(ptBytes) as unknown as WeierstrassPoint<bigint>;
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

// ── DealerState ───────────────────────────────────────────────────────────────

/**
 * Dealer's private polynomial coefficients [a_0, ..., a_{t-1}].
 * a_0 = the secret s = f(0).
 * Wire format: [u64 n] [uleb128 t] { [uleb128(32)] [32-byte Fr LE] } × t
 */
export class DealerState {
    constructor(
        readonly n: number,
        readonly coefsPolyP: bigint[],
    ) {}

    serialize(serializer: Serializer): void {
        serializer.serializeU64(this.n);
        serializer.serializeU32AsUleb128(this.coefsPolyP.length);
        for (const coef of this.coefsPolyP) {
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
                return new DealerState(Number(n), coefsPolyP);
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

// ── Functions ─────────────────────────────────────────────────────────────────

export function sample(): PrivateScalar {
    const x = bytesToNumberLE(randBytes(64));
    const val = frMod(x);
    return PrivateScalar.fromBigint(val).unwrapOrThrow('unreachable');
}

/**
 * Reconstruct the secret from a subset of indexed shares.
 * `index` is 1-based (holder i has share f(i)).
 */
export function reconstruct({ indexedShares }: {
    indexedShares: { index: number; share: SecretShare }[]
}): Result<PrivateScalar> {
    return Result.capture({
        recordsExecutionTimeMs: false,
        task: () => {
            const points = indexedShares.map(({ index, share }) => ({
                x: BigInt(index),
                y: share.y,
            }));
            const sRec = lagrangeAtZero(points);
            return PrivateScalar.fromBigint(sRec).unwrapOrThrow('unreachable');
        },
    });
}
