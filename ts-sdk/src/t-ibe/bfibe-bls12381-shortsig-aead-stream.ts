// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Streaming + seekable DEM for the shortsig-aead IBE half (the `StreamIBE_*` scopes).
 *
 * The IBE half is byte-for-byte identical to the block scheme (`./bfibe-bls12381-shortsig-aead`):
 * same G2 master key, `H_G1(id)`, per-message seed `e(Q_id, pk^r)`, `c0 = r·basePoint`, and the
 * same G1 IDK share. Streaming reuses those objects verbatim; only the DEM changes — from a single
 * ChaCha20-Poly1305 call to a **seekable segmented AEAD** (STREAM construction, à la age / Tink):
 *
 *   - 32-byte ChaCha20 key = HKDF-SHA256(seed, salt=∅, info=STREAM DST, L=32).
 *   - 64 KiB plaintext segments; segment i nonce = 11-byte BE counter i ‖ 1-byte last-flag.
 *
 * There is **no ciphertext object** — output is a stream of **ciphertext chunks**:
 *
 *   header chunk  = 0x03 ‖ c0            (1-byte stream marker = the on-chain primitive, then
 *                                         96-byte G2-compressed c0)
 *   segment chunk = ct_i ‖ 16B tag       (one per 64 KiB of plaintext)
 *
 * Non-final segment chunks are exactly `chunkSize + 16` bytes; the final one is the remainder.
 * Segment count + plaintext length are derivable from the total chunk-bytes length (no header
 * field), which is what makes `readRange` seeking possible.
 */

import { bls12_381 } from "@noble/curves/bls12-381";
import { Fp2 } from "@noble/curves/abstract/tower";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
import { bytesToNumberBE, numberToBytesLE } from "@noble/curves/utils";
import { concatBytes } from "@noble/hashes/utils";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha2";
import { chacha20poly1305 } from "@noble/ciphers/chacha";
import {
    MasterPublicKey,
    IdentityDecryptionKeyShare,
    ibeEncryptSeedAndC0,
    ibeReconstructSeed,
} from "./bfibe-bls12381-shortsig-aead";

/** First byte of the header chunk — the on-chain primitive id, used purely as a 1-byte
 *  self-identifying stream marker so a decryptor can confirm "these are stream chunks". */
export const STREAM_MARKER = 3;

export const DEFAULT_CHUNK_SIZE = 64 * 1024;
const AEAD_TAG_BYTES = 16;
const AEAD_KEY_BYTES = 32;
const NONCE_BYTES = 12;
const COUNTER_BYTES = 11; // nonce = 11-byte BE counter ‖ 1-byte last-flag
const C0_BYTES = 96; // G2 compressed
const HEADER_BYTES = 1 + C0_BYTES; // marker ‖ c0

const DST_KDF = new TextEncoder().encode("BONEH_FRANKLIN_BLS12381_SHORTSIG_AEADSTREAM/KDF");

// ── Primitives ─────────────────────────────────────────────────────────────

function deriveStreamKey(seed: Uint8Array): Uint8Array {
    return hkdf(sha256, seed, new Uint8Array(0), DST_KDF, AEAD_KEY_BYTES);
}

/** nonce = 11-byte big-endian segment counter ‖ 1-byte last-flag (0x00 non-final, 0x01 final). */
function segmentNonce(index: number, isLast: boolean): Uint8Array {
    if (!Number.isSafeInteger(index) || index < 0) throw `stream: bad segment index ${index}`;
    const nonce = new Uint8Array(NONCE_BYTES);
    let idx = BigInt(index);
    for (let i = COUNTER_BYTES - 1; i >= 0; i--) {
        nonce[i] = Number(idx & 0xffn);
        idx >>= 8n;
    }
    if (idx !== 0n) throw "stream: segment index overflow";
    nonce[COUNTER_BYTES] = isLast ? 0x01 : 0x00;
    return nonce;
}

function segmentEncrypt(key: Uint8Array, index: number, isLast: boolean, plainChunk: Uint8Array): Uint8Array {
    return chacha20poly1305(key, segmentNonce(index, isLast)).encrypt(plainChunk);
}

function segmentDecrypt(key: Uint8Array, index: number, isLast: boolean, cipherChunk: Uint8Array): Uint8Array {
    // ChaCha20-Poly1305 .decrypt() throws on tag mismatch; propagate (fails closed).
    return chacha20poly1305(key, segmentNonce(index, isLast)).decrypt(cipherChunk);
}

function c0ToBytes(c0: WeierstrassPoint<Fp2>): Uint8Array {
    return (c0 as any).toBytes();
}

function c0FromBytes(bytes: Uint8Array): WeierstrassPoint<Fp2> {
    return bls12_381.G2.Point.fromBytes(bytes) as unknown as WeierstrassPoint<Fp2>;
}

function randomScalarLE(): Uint8Array {
    return numberToBytesLE(bytesToNumberBE(bls12_381.utils.randomSecretKey()), 32);
}

// ── Layout math (seek support) ───────────────────────────────────────────────

/**
 * Recover segment count and plaintext length from the length of the concatenated segment chunks
 * (total chunk bytes minus the `HEADER_BYTES` header chunk).
 * `numSegments = max(1, ceil((bodyLen − 16) / (chunkSize + 16)))`,
 * `plaintextLength = bodyLen − 16·numSegments`.
 */
export function streamLayout(bodyLen: number, chunkSize = DEFAULT_CHUNK_SIZE): {
    numSegments: number;
    plaintextLength: number;
    chunkSize: number;
} {
    const cipherSeg = chunkSize + AEAD_TAG_BYTES;
    if (bodyLen < AEAD_TAG_BYTES) throw `stream: body too short (${bodyLen} < ${AEAD_TAG_BYTES})`;
    const numSegments = Math.max(1, Math.ceil((bodyLen - AEAD_TAG_BYTES) / cipherSeg));
    const plaintextLength = bodyLen - AEAD_TAG_BYTES * numSegments;
    if (plaintextLength < 0) throw `stream: inconsistent body length ${bodyLen}`;
    const finalSegLen = bodyLen - (numSegments - 1) * cipherSeg;
    if (finalSegLen < AEAD_TAG_BYTES || finalSegLen > cipherSeg) {
        throw `stream: inconsistent final segment length ${finalSegLen}`;
    }
    return { numSegments, plaintextLength, chunkSize };
}

// ── Whole-buffer, byte-exact (concatenated ciphertext chunks, for vectors only) ──

/** Segmented-encrypt an entire plaintext buffer into the concatenated segment chunks (no header). */
export function encodeSegments(key: Uint8Array, plaintext: Uint8Array, chunkSize = DEFAULT_CHUNK_SIZE): Uint8Array {
    const numSegments = plaintext.length === 0 ? 1 : Math.ceil(plaintext.length / chunkSize);
    const parts: Uint8Array[] = [];
    for (let j = 0; j < numSegments; j++) {
        const start = j * chunkSize;
        const chunk = plaintext.subarray(start, Math.min(start + chunkSize, plaintext.length));
        parts.push(segmentEncrypt(key, j, j === numSegments - 1, chunk));
    }
    return concatBytes(...parts);
}

/** Inverse of `encodeSegments`. Throws (fails closed) on any segment tag mismatch. */
export function decodeSegments(key: Uint8Array, body: Uint8Array, chunkSize = DEFAULT_CHUNK_SIZE): Uint8Array {
    const { numSegments } = streamLayout(body.length, chunkSize);
    const cipherSeg = chunkSize + AEAD_TAG_BYTES;
    const parts: Uint8Array[] = [];
    for (let j = 0; j < numSegments; j++) {
        const start = j * cipherSeg;
        const end = j === numSegments - 1 ? body.length : start + cipherSeg;
        parts.push(segmentDecrypt(key, j, j === numSegments - 1, body.subarray(start, end)));
    }
    return concatBytes(...parts);
}

/**
 * Byte-exact whole-buffer encrypt producing the **concatenated ciphertext chunks**
 * (`header ‖ segments`). For cross-impl test vectors; production callers use the streaming /
 * seekable APIs, which never assemble a single buffer.
 */
export function encryptToConcatChunksWithRandomness(
    mpk: MasterPublicKey,
    id: Uint8Array,
    plaintext: Uint8Array,
    randomness: Uint8Array,
    chunkSize = DEFAULT_CHUNK_SIZE,
): Uint8Array {
    const { seed, c0 } = ibeEncryptSeedAndC0(mpk, id, randomness);
    const body = encodeSegments(deriveStreamKey(seed), plaintext, chunkSize);
    return concatBytes(Uint8Array.of(STREAM_MARKER), c0ToBytes(c0), body);
}

/** Byte-exact whole-buffer decrypt of concatenated ciphertext chunks (`header ‖ segments`). */
export function decryptFromConcatChunks(
    idkShares: IdentityDecryptionKeyShare[],
    chunks: Uint8Array,
    chunkSize = DEFAULT_CHUNK_SIZE,
): Uint8Array {
    if (chunks.length < HEADER_BYTES + AEAD_TAG_BYTES) throw "stream: ciphertext chunks too short";
    if (chunks[0] !== STREAM_MARKER) throw `stream: expected marker ${STREAM_MARKER}, got ${chunks[0]}`;
    const c0 = c0FromBytes(chunks.subarray(1, HEADER_BYTES));
    const seed = ibeReconstructSeed(idkShares, c0);
    return decodeSegments(deriveStreamKey(seed), chunks.subarray(HEADER_BYTES), chunkSize);
}

// ── Bounded-memory streaming (async iterable of chunks) ──────────────────────

type ByteChunks = AsyncIterable<Uint8Array> | Iterable<Uint8Array>;

async function* asAsync(chunks: ByteChunks): AsyncGenerator<Uint8Array> {
    for await (const c of chunks as AsyncIterable<Uint8Array>) yield c;
}

/**
 * Encrypt an (async) iterable of plaintext byte chunks into an (async) iterable of **ciphertext
 * chunks** (header chunk, then one segment chunk per 64 KiB), in bounded memory. A segment is only
 * emitted as non-final once at least one further byte is known to follow, so the last segment is
 * flagged correctly without buffering the whole input.
 */
export async function* encryptChunks(
    mpk: MasterPublicKey,
    id: Uint8Array,
    plaintext: ByteChunks,
    opts?: { chunkSize?: number; randomness?: Uint8Array },
): AsyncGenerator<Uint8Array> {
    const chunkSize = opts?.chunkSize ?? DEFAULT_CHUNK_SIZE;
    const { seed, c0 } = ibeEncryptSeedAndC0(mpk, id, opts?.randomness ?? randomScalarLE());
    const key = deriveStreamKey(seed);

    yield concatBytes(Uint8Array.of(STREAM_MARKER), c0ToBytes(c0)); // header chunk

    let buf: Uint8Array = new Uint8Array(0);
    let index = 0;
    for await (const incoming of asAsync(plaintext)) {
        if (incoming.length === 0) continue;
        buf = buf.length === 0 ? incoming : concatBytes(buf, incoming);
        // Hold back a full chunk (strict `>`) so a chunk landing exactly at EOF is flagged final.
        while (buf.length > chunkSize) {
            yield segmentEncrypt(key, index++, false, buf.subarray(0, chunkSize));
            buf = buf.subarray(chunkSize);
        }
    }
    yield segmentEncrypt(key, index, true, buf); // final segment chunk (0..chunkSize bytes)
}

/**
 * Decrypt an (async) iterable of ciphertext chunks (as produced by `encryptChunks`, in any
 * re-chunking) into plaintext byte chunks, in bounded memory. Fails closed on any segment tag
 * mismatch, truncation past the flagged final segment, or a short stream.
 */
export async function* decryptChunks(
    idkShares: IdentityDecryptionKeyShare[],
    ciphertextChunks: ByteChunks,
    opts?: { chunkSize?: number },
): AsyncGenerator<Uint8Array> {
    const chunkSize = opts?.chunkSize ?? DEFAULT_CHUNK_SIZE;
    const cipherSeg = chunkSize + AEAD_TAG_BYTES;

    let buf: Uint8Array = new Uint8Array(0);
    let key: Uint8Array | null = null;
    let index = 0;

    // Pull manually (not `for await … break`, which would close the shared iterator).
    const reader = asAsync(ciphertextChunks)[Symbol.asyncIterator]();

    while (buf.length < HEADER_BYTES) {
        const { value, done } = await reader.next();
        if (done) break;
        buf = buf.length === 0 ? value : concatBytes(buf, value);
    }
    if (buf.length < HEADER_BYTES) throw "stream: ciphertext chunks ended before header";
    if (buf[0] !== STREAM_MARKER) throw `stream: expected marker ${STREAM_MARKER}, got ${buf[0]}`;
    const c0 = c0FromBytes(buf.subarray(1, HEADER_BYTES));
    key = deriveStreamKey(ibeReconstructSeed(idkShares, c0));
    buf = buf.subarray(HEADER_BYTES);

    const drain = function* (final: boolean): Generator<Uint8Array> {
        while (buf.length > cipherSeg) {
            const seg = buf.subarray(0, cipherSeg);
            buf = buf.subarray(cipherSeg);
            yield segmentDecrypt(key as Uint8Array, index++, false, seg);
        }
        if (final) {
            if (buf.length < AEAD_TAG_BYTES) throw "stream: truncated final segment";
            yield segmentDecrypt(key as Uint8Array, index++, true, buf);
            buf = new Uint8Array(0);
        }
    };

    for (;;) {
        const { value, done } = await reader.next();
        if (done) break;
        buf = buf.length === 0 ? value : concatBytes(buf, value);
        yield* drain(false);
    }
    yield* drain(true);
}

// ── Seekable / random-access decryptor (web video) ───────────────────────────

/** Random-access byte source over the stored ciphertext chunks, supplied by the caller
 *  (HTTP Range, file seek+read, S3 range GET…). Coordinates are in ciphertext bytes. */
export interface CiphertextSource {
    byteLength: number;
    readRange(offset: number, length: number): Promise<Uint8Array> | Uint8Array;
}

export interface SeekableDecryptor {
    /** Total decrypted plaintext length (derived from the stored ciphertext length). */
    plaintextLength: number;
    chunkSize: number;
    /** Decrypt and return plaintext bytes `[offset, offset+length)`, fetching only the segments
     *  that cover the range. Each fetched segment is independently authenticated. */
    readRange(offset: number, length: number): Promise<Uint8Array>;
}

/**
 * Build a seekable decryptor over a random-access ciphertext source. The caller implements
 * `ciphertextSource.readRange` in CIPHERTEXT coordinates (pure transport); the returned
 * `readRange` works in PLAINTEXT coordinates and maps the request to the covering segments.
 */
export async function createSeekableDecryptor({ idkShares, ciphertextSource, chunkSize = DEFAULT_CHUNK_SIZE }: {
    idkShares: IdentityDecryptionKeyShare[];
    ciphertextSource: CiphertextSource;
    chunkSize?: number;
}): Promise<SeekableDecryptor> {
    const total = ciphertextSource.byteLength;
    if (total < HEADER_BYTES + AEAD_TAG_BYTES) throw "stream: ciphertext too short";
    const header = await ciphertextSource.readRange(0, HEADER_BYTES);
    if (header[0] !== STREAM_MARKER) throw `stream: expected marker ${STREAM_MARKER}, got ${header[0]}`;
    const c0 = c0FromBytes(header.subarray(1, HEADER_BYTES));
    const key = deriveStreamKey(ibeReconstructSeed(idkShares, c0));

    const bodyLen = total - HEADER_BYTES;
    const { numSegments, plaintextLength } = streamLayout(bodyLen, chunkSize);
    const cipherSeg = chunkSize + AEAD_TAG_BYTES;

    async function readRange(offset: number, length: number): Promise<Uint8Array> {
        if (offset < 0 || length < 0) throw `stream: bad range offset=${offset} length=${length}`;
        const end = Math.min(offset + length, plaintextLength);
        if (offset >= end) return new Uint8Array(0);

        const firstSeg = Math.floor(offset / chunkSize);
        const lastSeg = Math.floor((end - 1) / chunkSize);
        const cStart = firstSeg * cipherSeg;
        const cEnd = lastSeg === numSegments - 1 ? bodyLen : (lastSeg + 1) * cipherSeg;
        const slice = await ciphertextSource.readRange(HEADER_BYTES + cStart, cEnd - cStart);

        const parts: Uint8Array[] = [];
        for (let j = firstSeg; j <= lastSeg; j++) {
            const s = (j - firstSeg) * cipherSeg;
            const e = j === numSegments - 1 ? cEnd - cStart : s + cipherSeg;
            parts.push(segmentDecrypt(key, j, j === numSegments - 1, slice.subarray(s, e)));
        }
        const plain = concatBytes(...parts);
        const offInFirst = offset - firstSeg * chunkSize;
        return plain.subarray(offInFirst, offInFirst + (end - offset));
    }

    return { plaintextLength, chunkSize, readRange };
}
