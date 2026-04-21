// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Fr-only Shamir dealing: polynomial coefficients derived from (SplitConfig, seed, baseCompressed).
 * Evaluation points are fixed: s(0) = secret, s(i) = share for holder i (1-indexed).
 * Shared by G1 and G2 variants.
 *
 * Wire format constants and helpers used by `SecretShare` / tests.
 */

import { sha3_512 } from "@noble/hashes/sha3";
import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils";
import { bytesToHex } from "@noble/hashes/utils";
import { frAdd, frInv, frMod, frMul } from "../group/bls12381g1";

/** First byte of `Secret` / `PublicCommitment` / `SecretShare` payloads. Bump when layout changes. */
export const SSS_WIRE_VERSION = 4;

/** Seed length in bytes (CSPRNG in `split`, fixed on the wire). */
export const SSS_SEED_BYTES = 32;

export interface SplitConfig {
    /** Number of shares / evaluation points. */
    n: bigint;
    /** Reconstruction threshold (polynomial degree is `t - 1`). */
    t: bigint;
}

export function splitConfigEquals(a: SplitConfig, b: SplitConfig): boolean {
    return a.n === b.n && a.t === b.t;
}

function u32le(n: number): Uint8Array {
    const b = new Uint8Array(4);
    new DataView(b.buffer).setUint32(0, n >>> 0, true);
    return b;
}

/** 8-byte little-endian `u64` for transcript domain separation (matches BCS `u64`). */
function u64le(v: bigint): Uint8Array {
    const w = BigInt.asUintN(64, v);
    const b = new Uint8Array(8);
    const dv = new DataView(b.buffer);
    dv.setUint32(0, Number(w & 0xffffffffn), true);
    dv.setUint32(4, Number((w >> 32n) & 0xffffffffn), true);
    return b;
}

function concatBytes(parts: Uint8Array[]): Uint8Array {
    const len = parts.reduce((acc, p) => acc + p.length, 0);
    const out = new Uint8Array(len);
    let o = 0;
    for (const p of parts) {
        out.set(p, o);
        o += p.length;
    }
    return out;
}

const te = new TextEncoder();

/**
 * Derive `t - 1` pseudorandom Fr values for Shamir polynomial coefficients.
 * (Evaluation points are fixed: holder i uses x = i, 1-indexed.)
 *
 * For each slot `i` in `0 .. t-2`: `sha3_512("ace-sss-dealing-v2" ‖ seed ‖ n ‖ t ‖ u32le(i) ‖ baseCompressed)`,
 * 64-byte digest as unsigned LE integer, then `frMod` to Fr.
 *
 * Callers form:
 * - `coeffs = [frMod(s), ...draws]` (length `t`): degree-(t-1) polynomial with s = coeffs[0] = f(0).
 * - Holder i receives share f(i) for i = 1..n.
 */
export function deriveDealingFrs(args: {
    splitConfig: SplitConfig;
    seed: Uint8Array;
    baseCompressed: Uint8Array;
}): bigint[] {
    const { splitConfig, seed, baseCompressed } = args;
    const { n, t } = splitConfig;
    if (n < 1n || t < 1n || n < t) throw "deriveDealingFrs: require 1 <= t <= n";
    if (seed.length !== SSS_SEED_BYTES) throw "deriveDealingFrs: invalid seed length";

    const numDraws = Number(t - 1n);
    const draws: bigint[] = [];
    for (let i = 0; i < numDraws; i++) {
        const transcript = concatBytes([
            te.encode("ace-sss-dealing-v2"),
            seed,
            u64le(n),
            u64le(t),
            u32le(i),
            baseCompressed,
        ]);
        const digest = sha3_512(transcript);
        draws.push(frMod(bytesToNumberLE(digest)));
    }
    return draws;
}

export function evalPoly(coeffs: bigint[], x: bigint): bigint {
    const xr = frMod(x);
    let y = 0n;
    let xp = 1n;
    for (const c of coeffs) {
        y = frAdd(y, frMul(frMod(c), xp));
        xp = frMul(xp, xr);
    }
    return frMod(y);
}

/** Lagrange interpolation: recover f(0) given points (x_i, y_i) with distinct x_i in Fr. */
export function lagrangeAtZero(points: { x: bigint; y: bigint }[]): bigint {
    const m = points.length;
    if (m < 1) throw "lagrangeAtZero: need at least one point";
    const xs = points.map((p) => frMod(p.x));
    const ys = points.map((p) => frMod(p.y));
    for (let i = 0; i < m; i++) {
        for (let j = i + 1; j < m; j++) {
            if (xs[i] === xs[j]) throw "lagrangeAtZero: duplicate x";
        }
    }
    let result = 0n;
    for (let i = 0; i < m; i++) {
        let lambda = 1n;
        for (let j = 0; j < m; j++) {
            if (i === j) continue;
            const num = frMod(-xs[j]);
            const den = frMod(xs[i] - xs[j]);
            lambda = frMul(lambda, frMul(num, frInv(den)));
        }
        result = frAdd(result, frMul(ys[i], lambda));
    }
    return frMod(result);
}

export function frPointKey(x: bigint): string {
    return bytesToHex(numberToBytesLE(frMod(x), 32));
}

export function xInAllowedSet(x: bigint, allowed: bigint[]): boolean {
    const k = frPointKey(x);
    for (const a of allowed) {
        if (frPointKey(a) === k) return true;
    }
    return false;
}
