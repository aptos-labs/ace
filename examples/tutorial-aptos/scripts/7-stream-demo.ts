// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 7 — Streaming + seekable encryption (StreamIBE), self-contained demo.
 *
 * Unlike steps 1–6, this script needs no localnet or ACE deployment: it uses a locally-generated
 * key to demonstrate the streaming *mechanics* — chunk-in / chunk-out encryption, bounded-memory
 * decryption, and random-access (`readRange`) seeking that powers web-video playback.
 *
 * In a real app you use the network-backed scope instead — `ACE.StreamIBE_Aptos.encryptStream`
 * and `ACE.StreamIBE_Aptos.createStreamDecryptorBasicFlow(...)` — which speak to the ACE nodes
 * exactly like `ACE.IBE_Aptos` does, but yield/consume ciphertext CHUNKS and expose a seekable
 * decryptor. Those need a keypair provisioned with the streaming usage. See
 * docs/developers/app-developer-guide/ibe-aptos-stream.md for the end-to-end app flow.
 */

import * as ACE from '@aptos-labs/ace-sdk';
import { log } from './common.js';

const CHUNK = 64 * 1024; // production default; the whole demo is one config knob

async function* chunked(bytes: Uint8Array, size: number): AsyncGenerator<Uint8Array> {
    for (let i = 0; i < bytes.length; i += size) yield bytes.subarray(i, Math.min(i + size, bytes.length));
}

async function collect(gen: AsyncIterable<Uint8Array>): Promise<Uint8Array[]> {
    const out: Uint8Array[] = [];
    for await (const c of gen) out.push(c);
    return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
    const total = parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    let o = 0;
    for (const p of parts) { out.set(p, o); o += p.length; }
    return out;
}

async function main() {
    // Local key material (stands in for the on-chain DKG keypair + a threshold IDK share).
    // Production code never does this — it fetches the pk and the share from the ACE network.
    const SCHEME = ACE.tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD; // streaming reuses shortsig objects
    const msk = ACE.tibe.keygenForTesting(SCHEME).unwrapOrThrow('keygen');
    const mpk = ACE.tibe.derivePublicKey(msk).unwrapOrThrow('derivePublicKey');
    const id = new TextEncoder().encode('demo/big-video.mp4');
    const share = ACE.tibe.extract({ scheme: SCHEME, mskScalar: (msk.inner as { scalar: bigint }).scalar, id })
        .unwrapOrThrow('extract');

    // A ~300 KiB "media file" (spans several 64 KiB segments).
    const plaintext = new Uint8Array(300 * 1024);
    for (let i = 0; i < plaintext.length; i++) plaintext[i] = (i * 131 + 7) & 0xff;
    log(`Plaintext: ${plaintext.length} bytes`);

    // 1) Encrypt as a stream of ciphertext CHUNKS (bounded memory; nothing fully buffered).
    const cipherChunks = await collect(
        ACE.tibeStream.encryptStream({ mpk, id, plaintext: chunked(plaintext, CHUNK), chunkSize: CHUNK }),
    );
    log(`Encrypted into ${cipherChunks.length} ciphertext chunks (1 header + segments)`);

    // 2) Forward-decrypt the chunk stream back to plaintext chunks.
    const roundTrip = concat(await collect(
        ACE.tibeStream.decryptStream({ idkShares: [share], ciphertextChunks: chunked(concat(cipherChunks), 9000), chunkSize: CHUNK }),
    ));
    if (roundTrip.length !== plaintext.length || !roundTrip.every((b, i) => b === plaintext[i])) {
        throw new Error('stream round-trip mismatch');
    }
    log('✓ Forward stream round-trip matches');

    // 3) Seek: decrypt an arbitrary plaintext byte range, fetching only the covered segments.
    const stored = concat(cipherChunks);
    let fetchedBytes = 0;
    const seek = await ACE.tibeStream.createSeekableDecryptor({
        idkShares: [share],
        ciphertextSource: {
            byteLength: stored.length,
            readRange: (offset, length) => { fetchedBytes += length; return stored.subarray(offset, offset + length); },
        },
        chunkSize: CHUNK,
    });
    const start = 200 * 1024 + 123;
    const len = 4096;
    const clip = await seek.readRange(start, len);
    const expected = plaintext.subarray(start, start + len);
    if (clip.length !== expected.length || !clip.every((b, i) => b === expected[i])) {
        throw new Error('seek readRange mismatch');
    }
    log(`✓ Seek readRange(${start}, ${len}) matches — fetched only ${fetchedBytes} of ${stored.length} ciphertext bytes`);
    log('');
    log('This is the mechanic behind encrypted <video> seeking: each scrub → one readRange().');
    log('For the network-backed flow, see docs/developers/app-developer-guide/ibe-aptos-stream.md');
}

main().catch(err => { console.error(err); process.exit(1); });
