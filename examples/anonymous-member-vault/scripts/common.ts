// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { mkdirSync, existsSync, readFileSync, writeFileSync } from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { buildPoseidon } from 'circomlibjs';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const ROOT = path.join(__dirname, '..');
export const CIRCUIT_DIR = path.join(ROOT, 'circuit');
export const CONTRACT_DIR = path.join(ROOT, 'contract');
export const DATA_DIR = path.join(ROOT, 'data');

export const LOCALNET_URL = 'http://localhost:8080/v1';
export const CHAIN_ID = 4; // Aptos localnet
export const TREE_DEPTH = 3;
export const MAX_LABEL_LEN = 30;
export const MAX_ENC_PK_LEN = 90;
const FIELD_CHUNK_LEN = 30;

export interface MemberRecord {
    name: string;
    index: number;
    secret: string;
    commitment: string;
    pathElements: string[];
    pathIndices: number[];
}

export interface PublicMemberRecord {
    name: string;
    index: number;
    commitment: string;
}

export interface GroupData {
    depth: number;
    root: string;
    members?: PublicMemberRecord[];
    leaves?: string[];
}

export interface GeneratedGroupData extends GroupData {
    members: MemberRecord[];
    leaves: string[];
}

export interface MemberCredential {
    name: string;
    index: number;
    secret: string;
    commitment: string;
    pathElements: string[];
    pathIndices: number[];
}

export function ensureDataDir(): void {
    if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
}

export function readJson<T>(filePath: string): T {
    return JSON.parse(readFileSync(filePath, 'utf8')) as T;
}

export function writeJson(filePath: string, data: unknown): void {
    writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
}

export function hexToBytes(hex: string): Uint8Array {
    const clean = hex.replace(/^0x/, '');
    return new Uint8Array(Buffer.from(clean, 'hex'));
}

export function bytesToHex(bytes: Uint8Array): string {
    return Buffer.from(bytes).toString('hex');
}

/** Convert a bigint (0 <= v < 2^256) to a 32-byte little-endian Uint8Array. */
export function uint256ToLeBytes(n: bigint): Uint8Array {
    const bytes = new Uint8Array(32);
    let v = n;
    for (let i = 0; i < 32; i++) {
        bytes[i] = Number(v & 0xffn);
        v >>= 8n;
    }
    return bytes;
}

/** Encode a BN254 G1 affine point as 64 bytes (x_le32 || y_le32). */
export function g1ToBytes(point: string[]): Uint8Array {
    const out = new Uint8Array(64);
    out.set(uint256ToLeBytes(BigInt(point[0]!)), 0);
    out.set(uint256ToLeBytes(BigInt(point[1]!)), 32);
    return out;
}

/** Encode a BN254 G2 affine point as 128 bytes. */
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

export function randomFr(): bigint {
    while (true) {
        const bytes = new Uint8Array(31);
        crypto.getRandomValues(bytes);
        const v = BigInt('0x' + Buffer.from(bytes).toString('hex'));
        if (v !== 0n) return v;
    }
}

export async function poseidonHash(inputs: bigint[]): Promise<bigint> {
    const poseidon = await buildPoseidon();
    const out = poseidon(inputs);
    return BigInt(poseidon.F.toObject(out).toString());
}

export async function buildPoseidonHasher(): Promise<(inputs: bigint[]) => bigint> {
    const poseidon = await buildPoseidon();
    return (inputs: bigint[]) => BigInt(poseidon.F.toObject(poseidon(inputs)).toString());
}

/** Pack labels exactly as member_vault.move does: bytes || one length byte. */
export function labelToFr(label: Uint8Array): bigint {
    if (label.length > MAX_LABEL_LEN) {
        throw new Error(`label must be <= ${MAX_LABEL_LEN} bytes, got ${label.length}`);
    }
    let v = 0n;
    let c = 1n;
    for (const byte of label) {
        v += BigInt(byte) * c;
        c *= 256n;
    }
    v += BigInt(label.length) * c;
    return v;
}

/** Pack enc_pk into 3 BN254 Fr scalars. Each chunk is bytes || length. */
export function packEncPk(encPk: Uint8Array): [bigint, bigint, bigint] {
    if (encPk.length === 0 || encPk.length > MAX_ENC_PK_LEN) {
        throw new Error(`enc_pk must be 1..${MAX_ENC_PK_LEN} bytes, got ${encPk.length}`);
    }
    return [
        packByteChunk(encPk, 0),
        packByteChunk(encPk, FIELD_CHUNK_LEN),
        packByteChunk(encPk, FIELD_CHUNK_LEN * 2),
    ];
}

function packByteChunk(bytes: Uint8Array, start: number): bigint {
    const chunkLen = Math.max(0, Math.min(FIELD_CHUNK_LEN, bytes.length - start));
    let v = 0n;
    let c = 1n;
    for (let i = 0; i < chunkLen; i++) {
        v += BigInt(bytes[start + i]!) * c;
        c *= 256n;
    }
    return v + BigInt(chunkLen) * c;
}

export async function buildGroup(names: string[]): Promise<GeneratedGroupData> {
    const hash = await buildPoseidonHasher();
    const leafCount = 1 << TREE_DEPTH;
    if (names.length > leafCount) {
        throw new Error(`TREE_DEPTH=${TREE_DEPTH} supports at most ${leafCount} members`);
    }

    const secrets = names.map(() => randomFr());
    const commitments = secrets.map(secret => hash([secret]));
    const levels: bigint[][] = [Array.from({ length: leafCount }, (_, i) => commitments[i] ?? 0n)];

    for (let level = 0; level < TREE_DEPTH; level++) {
        const prev = levels[level]!;
        const next: bigint[] = [];
        for (let i = 0; i < prev.length; i += 2) {
            next.push(hash([prev[i]!, prev[i + 1]!]));
        }
        levels.push(next);
    }

    const root = levels[TREE_DEPTH]![0]!;
    const members = names.map((name, index) => {
        const { pathElements, pathIndices } = merklePath(levels, index);
        return {
            name,
            index,
            secret: secrets[index]!.toString(),
            commitment: commitments[index]!.toString(),
            pathElements: pathElements.map(v => v.toString()),
            pathIndices,
        };
    });

    return {
        depth: TREE_DEPTH,
        root: root.toString(),
        members,
        leaves: levels[0]!.map(v => v.toString()),
    };
}

function merklePath(levels: bigint[][], leafIndex: number): {
    pathElements: bigint[];
    pathIndices: number[];
} {
    let idx = leafIndex;
    const pathElements: bigint[] = [];
    const pathIndices: number[] = [];
    for (let level = 0; level < TREE_DEPTH; level++) {
        const sibling = idx ^ 1;
        pathElements.push(levels[level]![sibling]!);
        pathIndices.push(idx & 1);
        idx >>= 1;
    }
    return { pathElements, pathIndices };
}

export function buildCircuitInput({
    group,
    credential,
    label,
    encPk,
}: {
    group: GroupData;
    credential: MemberCredential;
    label: Uint8Array;
    encPk: Uint8Array;
}): Record<string, string | string[] | number[]> {
    if (group.depth !== TREE_DEPTH) {
        throw new Error(`expected group depth ${TREE_DEPTH}, got ${group.depth}`);
    }
    const [p0, p1, p2] = packEncPk(encPk);
    return {
        root: group.root,
        label_fr: labelToFr(label).toString(),
        enc_pk_p0: p0.toString(),
        enc_pk_p1: p1.toString(),
        enc_pk_p2: p2.toString(),
        member_secret: credential.secret,
        path_elements: credential.pathElements,
        path_indices: credential.pathIndices,
    };
}
