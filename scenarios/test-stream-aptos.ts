// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * CI scenario: stand up the ACE local network with a **streaming** keypair
 * (primitive 3 / usage bit 8), then exercise `StreamIBE_Aptos` end-to-end
 * against real workers using the `check_acl_demo` custom-flow contract.
 *
 * Streaming (block/stream) is orthogonal to the auth flow (basic/custom): this
 * scenario drives the custom flow, mirroring `test-custom-flow-aptos.ts`, but
 * with chunk-in/chunk-out encryption and a seekable decryptor.
 *
 * Test cases:
 *   - encryptStream a multi-segment payload → ciphertext chunks.
 *   - Custom-flow stream-decrypt with the correct payload → round-trips.
 *   - Seek: readRange a mid-stream slice → matches, fetching only covered segments.
 *   - Custom-flow with wrong payload → rejected (fails closed).
 */

import * as ACE from '@aptos-labs/ace-sdk';
import { pathToFileURL } from 'url';
import { pke } from '@aptos-labs/ace-sdk';

import { CHAIN_ID, LOCALNET_URL } from './common/config';
import { assert, log, submitTxn } from './common/helpers';
import {
    type AptosCustomFlowSetup,
    bringUpAceAndDeployCheckAclDemo,
} from './custom-flow-aptos/helpers';

const INPUT_CHUNK = 64 * 1024; // how we slice the input stream; the SDK re-segments internally

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
    let setup: AptosCustomFlowSetup | undefined;
    const cleanup = () => {
        if (setup) for (const p of setup.nodeProcs) p.kill();
        setup?.localnetProc.kill();
    };
    process.on('SIGINT', () => { cleanup(); process.exit(1); });
    process.on('SIGTERM', () => { cleanup(); process.exit(1); });

    let exitCode = 0;
    try {
        // DKG a STREAMING keypair (primitive 3 → usage bit 8).
        setup = await bringUpAceAndDeployCheckAclDemo(ACE.network.PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEADSTREAM);
        await runStreamTestCases(setup);
        log('\n✅ Aptos StreamIBE tests passed!\n');
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        cleanup();
        process.exit(exitCode);
    }
}

async function runStreamTestCases(setup: AptosCustomFlowSetup): Promise<void> {
    const { adminAccount, adminAddr, aceContract, keypairId } = setup;
    const aceDeployment = new ACE.AceDeployment({ apiEndpoint: LOCALNET_URL, contractAddr: adminAddr });
    const label = new TextEncoder().encode('stream-test-content');
    const correctCode = new TextEncoder().encode('open-sesame');
    const wrongCode = new TextEncoder().encode('wrong-password');

    (await submitTxn({
        signer: adminAccount,
        entryFunction: `${aceContract}::check_acl_demo::set_access_code`,
        args: [Array.from(label), Array.from(correctCode)],
    })).unwrapOrThrow('set_access_code failed').asSuccessOrThrow();
    log('Access code stored on-chain');

    // A ~200 KiB payload that spans several 64 KiB segments.
    const plaintext = new Uint8Array(200 * 1024);
    for (let i = 0; i < plaintext.length; i++) plaintext[i] = (i * 131 + 7) & 0xff;

    // Encrypt as ciphertext CHUNKS (streaming fetches the pk once).
    const cipherChunks = await collect(ACE.StreamIBE_Aptos.encryptStream({
        aceDeployment, keypairId, chainId: CHAIN_ID, moduleAddr: adminAddr, moduleName: 'check_acl_demo',
        label, plaintext: chunked(plaintext, INPUT_CHUNK),
    }));
    log(`encryptStream produced ${cipherChunks.length} ciphertext chunks`);

    const caller = await pke.keygen();
    const baseDecryptArgs = {
        aceDeployment, keypairId, chainId: CHAIN_ID, moduleAddr: adminAddr, moduleName: 'check_acl_demo',
        label, encPk: caller.encryptionKey.toBytes(), encSk: caller.decryptionKey.toBytes(),
    };

    // Custom-flow stream decrypt with the correct payload → authenticate once, then stream + seek.
    log('Custom-flow stream decrypt with correct payload (should succeed)...');
    const decryptor = (await ACE.StreamIBE_Aptos.createStreamDecryptorCustomFlow({
        ...baseDecryptArgs, payload: correctCode,
    }));

    const roundTrip = concat(await collect(decryptor.decryptStream(chunked(concat(cipherChunks), 7000))));
    assert(
        roundTrip.length === plaintext.length && roundTrip.every((b, i) => b === plaintext[i]),
        'stream round-trip mismatch',
    );
    log('  ✓ Forward stream round-trip matches');

    // Seek: decrypt a mid-stream slice from the stored chunks, fetching only covered segments.
    const stored = concat(cipherChunks);
    let fetched = 0;
    const seek = await decryptor.createSeekableDecryptor({
        byteLength: stored.length,
        readRange: (offset, length) => { fetched += length; return stored.subarray(offset, offset + length); },
    });
    const start = 130 * 1024 + 77;
    const len = 5000;
    const clip = await seek.readRange(start, len);
    const expected = plaintext.subarray(start, start + len);
    assert(clip.length === expected.length && clip.every((b, i) => b === expected[i]), 'seek readRange mismatch');
    assert(fetched < stored.length, 'seek should not fetch the whole ciphertext');
    log(`  ✓ Seek readRange matches (fetched ${fetched} of ${stored.length} ciphertext bytes)`);

    // Wrong payload → the on-chain custom-flow hook returns false → share fetch rejected.
    log('Custom-flow stream decrypt with wrong payload (should fail)...');
    let failed = false;
    try {
        await ACE.StreamIBE_Aptos.createStreamDecryptorCustomFlow({ ...baseDecryptArgs, payload: wrongCode });
    } catch (_e) {
        failed = true;
    }
    assert(failed, 'wrong payload: stream decrypt should have been rejected');
    log('  ✓ wrong payload rejected');
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
    main();
}
