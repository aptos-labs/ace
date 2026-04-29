// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { mkdirSync, existsSync, readFileSync, writeFileSync } from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const ROOT = path.join(__dirname, '..');
export const CIRCUIT_DIR = path.join(ROOT, 'circuit');
export const CONTRACT_DIR = path.join(ROOT, 'contract');
export const DATA_DIR = path.join(ROOT, 'data');

export const LOCALNET_URL = 'http://localhost:8080/v1';
export const CHAIN_ID = 4; // Aptos localnet

export function ensureDataDir(): void {
    if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
}

export function readJson<T>(filePath: string): T {
    return JSON.parse(readFileSync(filePath, 'utf8')) as T;
}

export function writeJson(filePath: string, data: unknown): void {
    writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
}

/** Convert a bigint (0 ≤ v < 2^256) to a 32-byte little-endian Uint8Array. */
export function uint256ToLeBytes(n: bigint): Uint8Array {
    const bytes = new Uint8Array(32);
    let v = n;
    for (let i = 0; i < 32; i++) {
        bytes[i] = Number(v & 0xffn);
        v >>= 8n;
    }
    return bytes;
}

/** Encode a BN254 G1 affine point as 64 bytes (x_le32 || y_le32).
 *  point = [x_decimal, y_decimal, "1"]. */
export function g1ToBytes(point: string[]): Uint8Array {
    const out = new Uint8Array(64);
    out.set(uint256ToLeBytes(BigInt(point[0]!)), 0);
    out.set(uint256ToLeBytes(BigInt(point[1]!)), 32);
    return out;
}

/** Encode a BN254 G2 affine point as 128 bytes.
 *  Layout (FormatG2Uncompr): x0_le32 || x1_le32 || y0_le32 || y1_le32
 *  point = [[x0, x1], [y0, y1], ["1","0"]]. */
export function g2ToBytes(point: string[][]): Uint8Array {
    const out = new Uint8Array(128);
    out.set(uint256ToLeBytes(BigInt(point[0]![0]!)), 0);
    out.set(uint256ToLeBytes(BigInt(point[0]![1]!)), 32);
    out.set(uint256ToLeBytes(BigInt(point[1]![0]!)), 64);
    out.set(uint256ToLeBytes(BigInt(point[1]![1]!)), 96);
    return out;
}

/** Encode a Groth16 proof as 256 bytes: pi_a (64) || pi_b (128) || pi_c (64). */
export function proofToBytes(proof: {
    pi_a: string[];
    pi_b: string[][];
    pi_c: string[];
}): Uint8Array {
    const out = new Uint8Array(256);
    out.set(g1ToBytes(proof.pi_a), 0);
    out.set(g2ToBytes(proof.pi_b), 64);
    out.set(g1ToBytes(proof.pi_c), 192);
    return out;
}

/** Pack enc_pk[67] into 3 BN254 Fr scalars (mirrors the circuit constraints). */
export function packEncPk(encPk: Uint8Array): [bigint, bigint, bigint] {
    if (encPk.length !== 67) throw new Error(`enc_pk must be 67 bytes, got ${encPk.length}`);
    let p0 = 0n, p1 = 0n, p2 = 0n, c = 1n;
    for (let i = 0; i < 31; i++) {
        p0 += BigInt(encPk[i]!) * c;
        p1 += BigInt(encPk[31 + i]!) * c;
        c *= 256n;
    }
    c = 1n;
    for (let i = 0; i < 5; i++) {
        p2 += BigInt(encPk[62 + i]!) * c;
        c *= 256n;
    }
    return [p0, p1, p2];
}
