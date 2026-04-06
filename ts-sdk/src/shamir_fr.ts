// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

// Shamir's Secret Sharing over BLS12-381 Fr field.
// Used for splitting the IBE master scalar in threshold IBE.

import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils";
import { Result } from "./result";

export const FR_MODULUS = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;

// ============================================================================
// Fr field arithmetic
// ============================================================================

export function frMod(a: bigint): bigint {
    return ((a % FR_MODULUS) + FR_MODULUS) % FR_MODULUS;
}

export function frAdd(a: bigint, b: bigint): bigint {
    return frMod(a + b);
}

export function frMul(a: bigint, b: bigint): bigint {
    return frMod(a * b);
}

export function frInv(a: bigint): bigint {
    // Fermat's little theorem: a^{-1} = a^{p-2} mod p
    return modPow(frMod(a), FR_MODULUS - 2n, FR_MODULUS);
}

function modPow(base: bigint, exp: bigint, mod: bigint): bigint {
    let result = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp & 1n) result = (result * base) % mod;
        exp >>= 1n;
        base = (base * base) % mod;
    }
    return result;
}

// ============================================================================
// Public API: split and combine
// ============================================================================

/**
 * Split a secret (32-byte LE Fr element) into Shamir shares over BLS12-381 Fr.
 *
 * Generates a random polynomial f of degree threshold-1 with f(0)=secret,
 * evaluates at x=1..total, and returns 32-byte LE share encodings.
 */
export function split(secret: Uint8Array, threshold: number, total: number): Result<Uint8Array[]> {
    const task = (extra: Record<string, any>) => {
        extra['threshold'] = threshold;
        extra['total'] = total;
        if (threshold < 1 || threshold > total) {
            throw 'shamir_fr.split: invalid threshold or total';
        }

        const s = frMod(bytesToNumberLE(secret));

        // Build polynomial f: coeffs[0]=s, coeffs[1..threshold-1]=random
        const coeffs: bigint[] = [s];
        for (let i = 1; i < threshold; i++) {
            const rand = new Uint8Array(32);
            crypto.getRandomValues(rand);
            coeffs.push(frMod(bytesToNumberLE(rand)));
        }

        // Evaluate f(x) for x = 1..total using Horner's method
        return Array.from({ length: total }, (_, i) => {
            const x = BigInt(i + 1);
            let y = 0n;
            let xPow = 1n;
            for (const c of coeffs) {
                y = frAdd(y, frMul(c, xPow));
                xPow = frMul(xPow, x);
            }
            return numberToBytesLE(y, 32);
        });
    };
    return Result.capture({ task, recordsExecutionTimeMs: false });
}

/**
 * Lagrange interpolation at x=0 to recover f(0) from a subset of shares.
 *
 * @param shares - Map from 1-based index to 32-byte LE share payload
 */
export function combine(shares: Map<number, Uint8Array>): Result<Uint8Array> {
    const task = (_extra: Record<string, any>) => {
        if (shares.size < 1) throw 'shamir_fr.combine: at least one share required';
        const entries = Array.from(shares.entries());
        const xs = entries.map(([idx]) => BigInt(idx));
        const ys = entries.map(([, share]) => frMod(bytesToNumberLE(share)));

        // f(0) = Σ_i y_i * L_i(0)
        // L_i(0) = Π_{j≠i} (0 - x_j) / (x_i - x_j)
        let result = 0n;
        for (let i = 0; i < entries.length; i++) {
            let lambda = 1n;
            for (let j = 0; j < entries.length; j++) {
                if (i === j) continue;
                const num = frMod(-xs[j]);           // 0 - x_j
                const den = frMod(xs[i] - xs[j]);    // x_i - x_j
                lambda = frMul(lambda, frMul(num, frInv(den)));
            }
            result = frAdd(result, frMul(ys[i], lambda));
        }
        return numberToBytesLE(result, 32);
    };
    return Result.capture({ task, recordsExecutionTimeMs: false });
}
