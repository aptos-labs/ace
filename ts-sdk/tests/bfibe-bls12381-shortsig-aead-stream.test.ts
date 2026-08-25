// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Unit tests for the streaming + seekable DEM (StreamIBE). Uses a tiny `chunkSize` to exercise
 * multi-segment boundaries with small inputs. The IBE half (keygen / extract / reconstruction) is
 * reused from the shortsig-aead (block) module — streaming reuses those objects verbatim.
 */

import { describe, it, expect } from "vitest";
import { concatBytes } from "@noble/hashes/utils";
import { numberToBytesLE } from "@noble/curves/utils";
import { keygenForTesting, derivePublicKey, extract } from "../src/t-ibe/bfibe-bls12381-shortsig-aead";
import * as stream from "../src/t-ibe/bfibe-bls12381-shortsig-aead-stream";
import * as tibe from "../src/t-ibe";
import * as tibeStream from "../src/t-ibe-stream";

const utf8 = (s: string) => new TextEncoder().encode(s);
const CHUNK = 16; // small, to force many segments
const HEADER = 1 + 96;

function fixture() {
    const msk = keygenForTesting();
    const mpk = derivePublicKey(msk);
    const id = utf8("alice@example.com");
    const share = extract(msk.scalar, id); // single share at evalPoint=1
    return { mpk, id, shares: [share] };
}

function bytesOfLen(n: number): Uint8Array {
    const b = new Uint8Array(n);
    for (let i = 0; i < n; i++) b[i] = (i * 37 + 11) & 0xff;
    return b;
}

async function collect(gen: AsyncIterable<Uint8Array>): Promise<Uint8Array> {
    const parts: Uint8Array[] = [];
    for await (const c of gen) parts.push(c);
    return parts.length ? concatBytes(...parts) : new Uint8Array(0);
}

async function* pieces(bytes: Uint8Array, size: number): AsyncGenerator<Uint8Array> {
    for (let i = 0; i < bytes.length; i += size) yield bytes.subarray(i, Math.min(i + size, bytes.length));
    if (bytes.length === 0) return;
}

const SIZES = [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 3 * CHUNK, 3 * CHUNK + 7];

describe("StreamIBE DEM", () => {
    it("whole-buffer round-trip across boundary sizes", () => {
        const { mpk, id, shares } = fixture();
        for (const n of SIZES) {
            const pt = bytesOfLen(n);
            const r = numberToBytesLE(12345n, 32);
            const chunks = stream.encryptToConcatChunksWithRandomness(mpk, id, pt, r, CHUNK);
            expect(chunks[0]).toBe(stream.STREAM_MARKER);
            expect(stream.decryptFromConcatChunks(shares, chunks, CHUNK)).toEqual(pt);
        }
    });

    it("streamLayout recovers plaintext length from ciphertext length", () => {
        const { mpk, id } = fixture();
        for (const n of SIZES) {
            const r = numberToBytesLE(7n, 32);
            const chunks = stream.encryptToConcatChunksWithRandomness(mpk, id, bytesOfLen(n), r, CHUNK);
            expect(stream.streamLayout(chunks.length - HEADER, CHUNK).plaintextLength).toBe(n);
        }
    });

    it("async streaming path is byte-identical to the whole-buffer path", async () => {
        const { mpk, id } = fixture();
        const pt = bytesOfLen(3 * CHUNK + 7);
        const r = numberToBytesLE(999n, 32);
        const expected = stream.encryptToConcatChunksWithRandomness(mpk, id, pt, r, CHUNK);
        const got = await collect(stream.encryptChunks(mpk, id, pieces(pt, 5), { chunkSize: CHUNK, randomness: r }));
        expect(got).toEqual(expected);
    });

    it("bounded-memory encrypt→decrypt round-trip with re-chunking", async () => {
        const { mpk, id, shares } = fixture();
        for (const n of SIZES) {
            const pt = bytesOfLen(n);
            const ctChunks = await collect(stream.encryptChunks(mpk, id, pieces(pt, 7), { chunkSize: CHUNK }));
            const got = await collect(stream.decryptChunks(shares, pieces(ctChunks, 13), { chunkSize: CHUNK }));
            expect(got).toEqual(pt);
        }
    });

    it("seekable readRange matches plaintext slices and fetches only covered segments", async () => {
        const { mpk, id, shares } = fixture();
        const pt = bytesOfLen(5 * CHUNK + 3);
        const r = numberToBytesLE(42n, 32);
        const ctChunks = stream.encryptToConcatChunksWithRandomness(mpk, id, pt, r, CHUNK);

        let dataFetches: Array<{ offset: number; length: number }> = [];
        const source: stream.CiphertextSource = {
            byteLength: ctChunks.length,
            readRange(offset, length) {
                dataFetches.push({ offset, length });
                return ctChunks.subarray(offset, offset + length);
            },
        };
        const dec = await stream.createSeekableDecryptor({ idkShares: shares, ciphertextSource: source, chunkSize: CHUNK });
        expect(dec.plaintextLength).toBe(pt.length);

        const ranges: Array<[number, number]> = [
            [0, 4], [CHUNK - 2, 5], [CHUNK, CHUNK], [2 * CHUNK + 1, 3], [0, pt.length], [5 * CHUNK, 3],
        ];
        for (const [off, len] of ranges) {
            dataFetches = [];
            const got = await dec.readRange(off, len);
            expect(got).toEqual(pt.subarray(off, Math.min(off + len, pt.length)));
            if (off + len < pt.length && off > 0) {
                const fetched = dataFetches.reduce((a, f) => a + f.length, 0);
                expect(fetched).toBeLessThan(ctChunks.length - HEADER);
            }
        }
    });

    it("fails closed on tamper, truncation, reorder, and dropped segment", () => {
        const { mpk, id, shares } = fixture();
        const pt = bytesOfLen(3 * CHUNK + 5);
        const r = numberToBytesLE(1n, 32);
        const ct = stream.encryptToConcatChunksWithRandomness(mpk, id, pt, r, CHUNK);
        const cipherSeg = CHUNK + 16;

        const tampered = ct.slice();
        tampered[HEADER + 3] ^= 0x01;
        expect(() => stream.decryptFromConcatChunks(shares, tampered, CHUNK)).toThrow();

        expect(() => stream.decryptFromConcatChunks(shares, ct.subarray(0, ct.length - 4), CHUNK)).toThrow();

        const reordered = ct.slice();
        reordered.set(ct.subarray(HEADER + cipherSeg, HEADER + 2 * cipherSeg), HEADER);
        reordered.set(ct.subarray(HEADER, HEADER + cipherSeg), HEADER + cipherSeg);
        expect(() => stream.decryptFromConcatChunks(shares, reordered, CHUNK)).toThrow();

        const dropped = concatBytes(ct.subarray(0, HEADER), ct.subarray(HEADER + cipherSeg));
        expect(() => stream.decryptFromConcatChunks(shares, dropped, CHUNK)).toThrow();
    });
});

describe("t-ibe-stream generic API (reuses shortsig-aead objects)", () => {
    const SHORTSIG = tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD;

    function genericFixture() {
        const msk = tibe.keygenForTesting(SHORTSIG).unwrapOrThrow("keygen");
        const mpk = tibe.derivePublicKey(msk).unwrapOrThrow("derivePublicKey");
        const id = utf8("stream@example.com");
        const share = tibe.extract({ scheme: SHORTSIG, mskScalar: (msk.inner as any).scalar, id }).unwrapOrThrow("extract");
        return { mpk, id, shares: [share] };
    }

    // The generic API fixes the segment size at the 64 KiB default (no chunkSize param), so these
    // use a >64 KiB payload to still cross segment boundaries through the public path. Boundary
    // edge cases are covered above via the low-level module.
    const P = stream.DEFAULT_CHUNK_SIZE;

    it("generic encryptStream → decryptStream round-trip", async () => {
        const { mpk, id, shares } = genericFixture();
        const pt = bytesOfLen(3 * P + 7);
        const ct = await collect(tibeStream.encryptStream({ mpk, id, plaintext: pieces(pt, 4096) }));
        const got = await collect(tibeStream.decryptStream({ idkShares: shares, ciphertextChunks: pieces(ct, 5000) }));
        expect(got).toEqual(pt);
    });

    it("generic seekable readRange over stored ciphertext chunks", async () => {
        const { mpk, id, shares } = genericFixture();
        const pt = bytesOfLen(3 * P + 2);
        const r = numberToBytesLE(5n, 32);
        const ctChunks = tibeStream.encryptToConcatChunksWithRandomness({ mpk, id, plaintext: pt, randomness: r });
        const source: stream.CiphertextSource = { byteLength: ctChunks.length, readRange: (o, l) => ctChunks.subarray(o, o + l) };
        const dec = await tibeStream.createSeekableDecryptor({ idkShares: shares, ciphertextSource: source });
        expect(await dec.readRange(P + 1, P)).toEqual(pt.subarray(P + 1, 2 * P + 1));
    });

    it("rejects a non-shortsig mpk", () => {
        const otpMsk = tibe.keygenForTesting(tibe.SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC).unwrapOrThrow("otp msk");
        const otpMpk = tibe.derivePublicKey(otpMsk).unwrapOrThrow("otp mpk");
        expect(() => tibeStream.encryptStream({ mpk: otpMpk, id: utf8("x"), plaintext: [utf8("hi")] })).toThrow();
    });
});
