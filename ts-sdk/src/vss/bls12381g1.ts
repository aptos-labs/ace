// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Shamir secret sharing over BLS12-381 Fr with curve base in **G1**.
 * Secret is `(B, s)` with `B` a random G1 point and `s` ∈ Fr; public commitment is `(B, s·B)`.
 */

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
import { bls12_381 } from "@noble/curves/bls12-381";
import { bytesToNumberBE, bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils";
import { bytesToHex, hexToBytes, randomBytes } from "@noble/hashes/utils";
import { assertCanonicalFrScalar, frMod } from "../shamir_fr";
import { Result } from "../result";
import {
    deriveDealingFrs,
    evalPoly,
    frPointKey,
    lagrangeAtZero,
    splitConfigEquals,
    SSS_SEED_BYTES,
    SSS_WIRE_VERSION,
    xInAllowedSet,
    type SplitConfig,
} from "./dealing";

const G1_COMPRESSED_BYTES = 48;

/** G1 `Secret` BCS: `version: u8`, `scalar: [u8;32]` (Fr LE), `B: [u8;48]` compressed G1. */
export class Secret {
    constructor(
        readonly base: WeierstrassPoint<bigint>,
        readonly scalar: bigint,
    ) {
        assertCanonicalFrScalar("Secret.scalar", scalar);
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(SSS_WIRE_VERSION);
        serializer.serializeFixedBytes(numberToBytesLE(this.scalar, 32));
        serializer.serializeFixedBytes(this.base.toBytes(true) as Uint8Array);
    }

    static deserialize(deserializer: Deserializer): Result<Secret> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const version = deserializer.deserializeU8();
                if (version !== SSS_WIRE_VERSION) throw "Secret.deserialize: unsupported version";
                const sLe = deserializer.deserializeFixedBytes(32);
                const s = bytesToNumberLE(sLe);
                const Bbytes = deserializer.deserializeFixedBytes(G1_COMPRESSED_BYTES);
                const B = bls12_381.G1.Point.fromBytes(Bbytes) as unknown as WeierstrassPoint<bigint>;
                return new Secret(B, s);
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
                const secret = Secret.deserialize(deserializer).unwrapOrThrow("Bls12381G1.Secret.fromBytes deserialize");
                if (deserializer.remaining() !== 0) throw "Secret.fromBytes: trailing bytes";
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
            task: () => Secret.fromBytes(hexToBytes(hex)).unwrapOrThrow("Bls12381G1.Secret.fromHex failed"),
        });
    }
}

/** `(B, s·B)` BCS: `version: u8`, `B: [u8;48]`, `sB: [u8;48]` compressed G1. */
export class PublicCommitment {
    constructor(
        readonly base: WeierstrassPoint<bigint>,
        readonly sTimesBase: WeierstrassPoint<bigint>,
    ) {}

    serialize(serializer: Serializer): void {
        serializer.serializeU8(SSS_WIRE_VERSION);
        serializer.serializeFixedBytes(this.base.toBytes(true) as Uint8Array);
        serializer.serializeFixedBytes(this.sTimesBase.toBytes(true) as Uint8Array);
    }

    static deserialize(deserializer: Deserializer): Result<PublicCommitment> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const version = deserializer.deserializeU8();
                if (version !== SSS_WIRE_VERSION) throw "PublicCommitment.deserialize: unsupported version";
                const Bbytes = deserializer.deserializeFixedBytes(G1_COMPRESSED_BYTES);
                const sBbytes = deserializer.deserializeFixedBytes(G1_COMPRESSED_BYTES);
                const B = bls12_381.G1.Point.fromBytes(Bbytes) as unknown as WeierstrassPoint<bigint>;
                const sB = bls12_381.G1.Point.fromBytes(sBbytes) as unknown as WeierstrassPoint<bigint>;
                return new PublicCommitment(B, sB);
            },
        });
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<PublicCommitment> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const pc = PublicCommitment.deserialize(deserializer).unwrapOrThrow(
                    "Bls12381G1.PublicCommitment.fromBytes deserialize",
                );
                if (deserializer.remaining() !== 0) throw "PublicCommitment.fromBytes: trailing bytes";
                return pc;
            },
        });
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<PublicCommitment> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => PublicCommitment.fromBytes(hexToBytes(hex)).unwrapOrThrow("Bls12381G1.PublicCommitment.fromHex failed"),
        });
    }
}

/**
 * G1 `SecretShare` BCS:
 * `version: u8`, `n: u64`, `t: u64`, `seed: [u8;32]`, `x: [u8;32]`, `y: [u8;32]`, `B: [u8;48]` compressed G1.
 * In memory, `base` is the decoded G1 point (same on every share from one `split`).
 */
export class SecretShare {
    constructor(
        readonly splitConfig: SplitConfig,
        readonly seed: Uint8Array,
        readonly x: bigint,
        readonly y: bigint,
        /** G1 base `B` (same on every share from one `split`). */
        readonly base: WeierstrassPoint<bigint>,
    ) {
        if (seed.length !== SSS_SEED_BYTES) throw "SecretShare: seed must be SSS_SEED_BYTES";
        assertCanonicalFrScalar("SecretShare.x", x);
        assertCanonicalFrScalar("SecretShare.y", y);
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(SSS_WIRE_VERSION);
        serializer.serializeU64(this.splitConfig.n);
        serializer.serializeU64(this.splitConfig.t);
        serializer.serializeFixedBytes(this.seed);
        serializer.serializeFixedBytes(numberToBytesLE(this.x, 32));
        serializer.serializeFixedBytes(numberToBytesLE(this.y, 32));
        serializer.serializeFixedBytes(this.base.toBytes(true) as Uint8Array);
    }

    static deserialize(deserializer: Deserializer): Result<SecretShare> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const version = deserializer.deserializeU8();
                if (version !== SSS_WIRE_VERSION) throw "SecretShare.deserialize: unsupported version";
                const n = deserializer.deserializeU64();
                const t = deserializer.deserializeU64();
                if (t < 1n || n < t) throw "SecretShare.deserialize: require 1 <= t <= n";
                const seed = deserializer.deserializeFixedBytes(SSS_SEED_BYTES);
                const x = bytesToNumberLE(deserializer.deserializeFixedBytes(32));
                const y = bytesToNumberLE(deserializer.deserializeFixedBytes(32));
                const baseBytes = deserializer.deserializeFixedBytes(G1_COMPRESSED_BYTES);
                const B = bls12_381.G1.Point.fromBytes(baseBytes) as unknown as WeierstrassPoint<bigint>;
                return new SecretShare({ n, t }, seed, x, y, B);
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
                const share = SecretShare.deserialize(deserializer).unwrapOrThrow("Bls12381G1.SecretShare.fromBytes deserialize");
                if (deserializer.remaining() !== 0) throw "SecretShare.fromBytes: trailing bytes";
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
            task: () => SecretShare.fromBytes(hexToBytes(hex)).unwrapOrThrow("Bls12381G1.SecretShare.fromHex failed"),
        });
    }
}

export function shareWireLengthG1(): number {
    return 1 + 8 + 8 + SSS_SEED_BYTES + 32 + 32 + G1_COMPRESSED_BYTES;
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

export function keygen(): { secret: Secret; publicCommitment: PublicCommitment } {
    const B = bls12_381.G1.hashToCurve(randomBytes(32)) as unknown as WeierstrassPoint<bigint>;
    const rBE = bls12_381.utils.randomSecretKey();
    const s = frMod(bytesToNumberBE(rBE));
    const secret = new Secret(B, s);
    return { secret, publicCommitment: derivePublicCommitment({ secret }) };
}

export function derivePublicCommitment({ secret }: { secret: Secret }): PublicCommitment {
    const s = frMod(secret.scalar);
    const sTimesBase = secret.base.multiply(s) as WeierstrassPoint<bigint>;
    return new PublicCommitment(secret.base, sTimesBase);
}

function splitInner(secret: Secret, n: number, t: number, seed: Uint8Array): SecretShare[] {
    if (t < 1 || n < t) throw "split: require 1 <= t <= n";
    if (seed.length !== SSS_SEED_BYTES) throw "split: seed must be SSS_SEED_BYTES";
    const splitConfig: SplitConfig = { n: BigInt(n), t: BigInt(t) };
    const Bc = secret.base.toBytes(true) as Uint8Array;
    const s = frMod(secret.scalar);
    const draws = deriveDealingFrs({ splitConfig, seed, baseCompressed: Bc });
    const tNum = Number(splitConfig.t);
    const coeffs = [s, ...draws.slice(0, tNum - 1)];
    const xs = draws.slice(tNum - 1);
    const shares: SecretShare[] = [];
    for (let j = 0; j < n; j++) {
        const x = xs[j];
        const y = evalPoly(coeffs, x);
        shares.push(new SecretShare(splitConfig, Uint8Array.from(seed), x, y, secret.base));
    }
    return shares;
}

export function split({ secret, n, t }: { secret: Secret; n: number; t: number }): Result<SecretShare[]> {
    return Result.capture({
        recordsExecutionTimeMs: false,
        task: () => {
            const seed = new Uint8Array(SSS_SEED_BYTES);
            crypto.getRandomValues(seed);
            return splitInner(secret, n, t, seed);
        },
    });
}

/** Deterministic split for tests (same inputs produce the same shares). */
export function splitWithSeed({
    secret,
    n,
    t,
    seed,
}: {
    secret: Secret;
    n: number;
    t: number;
    seed: Uint8Array;
}): Result<SecretShare[]> {
    return Result.capture({
        recordsExecutionTimeMs: false,
        task: () => splitInner(secret, n, t, seed),
    });
}

export function reconstruct({ secretShares }: { secretShares: SecretShare[] }): Result<Secret> {
    return Result.capture({
        recordsExecutionTimeMs: false,
        task: () => {
            if (secretShares.length < 1) throw "reconstruct: no shares";
            const first = secretShares[0];
            const { splitConfig, seed } = first;
            const Bc = first.base.toBytes(true) as Uint8Array;
            for (const sh of secretShares) {
                if (!splitConfigEquals(sh.splitConfig, splitConfig)) throw "reconstruct: SplitConfig mismatch";
                if (!bytesEqual(sh.seed, seed)) throw "reconstruct: seed mismatch";
                if (!bytesEqual(sh.base.toBytes(true) as Uint8Array, Bc)) throw "reconstruct: base B mismatch";
            }
            const draws = deriveDealingFrs({ splitConfig, seed, baseCompressed: Bc });
            const tNum = Number(splitConfig.t);
            const allowed = draws.slice(tNum - 1);
            for (const sh of secretShares) {
                if (!xInAllowedSet(sh.x, allowed)) throw "reconstruct: x not in derived evaluation set";
            }
            const byKey = new Map<string, { x: bigint; y: bigint }>();
            for (const sh of secretShares) {
                const k = frPointKey(sh.x);
                if (!byKey.has(k)) byKey.set(k, { x: sh.x, y: sh.y });
            }
            if (BigInt(byKey.size) < splitConfig.t) {
                throw `reconstruct: need at least t distinct x values, got ${byKey.size}`;
            }
            const points = [...byKey.values()];
            const sRec = lagrangeAtZero(points);
            const coeffsCheck = [frMod(sRec), ...draws.slice(0, tNum - 1)];
            for (const sh of secretShares) {
                const yExp = evalPoly(coeffsCheck, sh.x);
                if (frPointKey(yExp) !== frPointKey(sh.y)) throw "reconstruct: inconsistent y for derived polynomial";
            }
            return new Secret(first.base, sRec);
        },
    });
}

export { type SplitConfig } from "./dealing";
