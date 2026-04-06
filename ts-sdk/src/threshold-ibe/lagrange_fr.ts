// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

// Fr field arithmetic for Lagrange combination of partial G2 identity keys.
// BLS12-381 Fr modulus (same as the curve's group order).

export const FR_MODULUS = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;

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
