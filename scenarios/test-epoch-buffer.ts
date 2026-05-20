// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * E2E test for the worker's 30-second epoch-buffer window.
 *
 * Workers retain the previous epoch's shares for ~30s after a rotation
 * (`worker-components/network-node/src/lib.rs:573-591` — URH task shutdown
 * schedules eviction `Instant::now() + Duration::from_secs(30)`). This
 * matters for the cross-epoch transition: a decryption request that was
 * built/signed under the old epoch keeps succeeding briefly into the new
 * epoch, instead of breaking abruptly at the rotation boundary. After the
 * buffer elapses the old-epoch share is evicted and the same request
 * fails — that's also part of the contract.
 *
 * This scenario exercises both halves:
 *
 *  1. Stand up ACE with `resharing_interval_secs = 30` (chain minimum, so
 *     auto-rotation fires fast).
 *  2. Run DKG → epoch 1.
 *  3. Bob builds a `DecryptionSession` and signs the pretty-message.
 *     `session.request.epoch` is now pinned to 1.
 *  4. Wait for auto-rotation to epoch 2.
 *  5. **Within buffer**: replay `session.decryptWithProof(...)` immediately.
 *     The cached `session.request` still says epoch=1; workers still have
 *     epoch-1 shares; decrypt succeeds.
 *  6. Sleep past the 30s eviction window + the 5s cleanup tick.
 *  7. **Past buffer**: same replay → workers no longer have epoch-1 shares
 *     for that keypair_id; decrypt fails.
 *
 * Run:
 *   cd scenarios && pnpm test-epoch-buffer
 */

import { Account, AccountAddress, Ed25519PrivateKey } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { ChildProcess } from 'child_process';

import { setupAccessControlAppAndEncryptPing } from './common/access-control-app';
import { setupAceOnLocalnet } from './common/ace-network';
import { CHAIN_ID } from './common/config';
import { assert, cleanupScenario, fundAccount, getNetworkState, sleep } from './common/helpers';

const TOTAL_WORKERS = 3;
const EPOCH0_WORKER_INDICES = [0, 1, 2];
const EPOCH0_THRESHOLD = 2;
const BOB_KEY_SEED = 200;

// Chain's `MIN_RESHARING_INTERVAL_SECS = 30` (contracts/network/sources/network.move:17).
// Use the minimum so auto-rotation triggers fast.
const RESHARE_INTERVAL_SECS = 30;

// Worker's eviction delay after URH shutdown
// (worker-components/network-node/src/lib.rs:586,
// `Duration::from_secs(30)`).
const BUFFER_SECS = 30;

// Worker's share-cleanup tick runs every 5s (lib.rs:377). Add headroom
// so the past-buffer replay lands after eviction has definitely happened.
const POST_BUFFER_GRACE_SECS = 15;

/** Poll the on-chain network state until `epoch >= targetEpoch`. Returns
 *  the wall-clock millisecond when we observed the advance — used as the
 *  reference for "how long since rotation" math. */
async function waitForEpochAdvance(
    targetEpoch: number,
    adminAddr: AccountAddress,
    timeoutMs: number,
): Promise<{ epoch: number; observedAtMs: number }> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const r = await getNetworkState(adminAddr);
        if (r.isOk && Number(r.okValue!.epoch) >= targetEpoch) {
            return { epoch: Number(r.okValue!.epoch), observedAtMs: Date.now() };
        }
        await sleep(2_000);
    }
    throw `Epoch did not advance to ${targetEpoch} within ${timeoutMs / 1000}s`;
}

async function buildAndFundBob(): Promise<Account> {
    const bobKey = new Ed25519PrivateKey(
        Buffer.from(new Uint8Array(32).map((_, i) => i + BOB_KEY_SEED)),
    );
    const bob = Account.fromPrivateKey({ privateKey: bobKey });
    await fundAccount(bob.accountAddress);
    return bob;
}

async function main(): Promise<void> {
    let workers: ChildProcess[] = [];
    let localnetProc: ChildProcess | null = null;
    let exitCode = 0;
    try {
        const setup = await setupAceOnLocalnet({
            totalWorkers: TOTAL_WORKERS,
            epoch0WorkerIndices: EPOCH0_WORKER_INDICES,
            epoch0Threshold: EPOCH0_THRESHOLD,
            fundAccount,
            numKeypairs: 1,
            reshareIntervalSecs: RESHARE_INTERVAL_SECS,
        });
        localnetProc = setup.localnetProc;
        workers = setup.ace.workers;
        const { actors, ace: aceState, keypairIds: [keypair0Id] } = setup;

        const bob = await buildAndFundBob();
        const { correctDomain, pingCiph } = await setupAccessControlAppAndEncryptPing(
            actors, bob.accountAddress,
            aceState.aceDeployment, aceState.adminAccountAddress, keypair0Id,
        );

        // Sanity-check we're still at epoch 1 (not yet rotated). Tight enough
        // that timing slippage causes a clean error rather than a confusing
        // wrong-epoch capture.
        const initial = (await getNetworkState(aceState.adminAccountAddress))
            .unwrapOrThrow('initial getNetworkState');
        const initialEpoch = Number(initial.epoch);
        console.log(`Initial epoch: ${initialEpoch} (expected 1)`);
        assert(initialEpoch === 1, `expected initial epoch=1, got ${initialEpoch}`);

        // Build a session and capture the signed request at epoch 1. The
        // session caches `request` (with epoch=1) + `networkState`, so
        // future `decryptWithProof(...)` calls replay the captured bytes
        // even after the chain rotates.
        const session = await ACE.AptosBasicFlow.DecryptionSession.create({
            aceDeployment: aceState.aceDeployment,
            keypairId: keypair0Id,
            chainId: CHAIN_ID,
            moduleAddr: aceState.adminAccountAddress,
            moduleName: 'access_control',
            functionName: 'check_permission',
            domain: correctDomain,
            ciphertext: pingCiph,
        });
        const msg = await session.getRequestToSign();
        const signature = bob.sign(msg);
        const capturedEpoch = Number(session.request!.epoch);
        console.log(`Session captured at epoch=${capturedEpoch}`);
        assert(capturedEpoch === initialEpoch, `session captured at wrong epoch ${capturedEpoch}`);

        // ── Wait for auto-rotation ────────────────────────────────────────
        console.log(`Waiting for auto-rotation to epoch=${initialEpoch + 1}...`);
        const rotation = await waitForEpochAdvance(
            initialEpoch + 1, aceState.adminAccountAddress, 120_000,
        );
        console.log(`Rotation observed at epoch=${rotation.epoch}.`);

        // ── Within buffer ─────────────────────────────────────────────────
        // Submit immediately. Workers' 5s state-poll may add up to 5s
        // before they signal URH-1 shutdown, but the 30s eviction timer
        // doesn't start until then — so the within-buffer window is
        // comfortably wide right after we observe the rotation.
        console.log('\n── Within-buffer replay (request signed at epoch=N, submitted after N+1) ──');
        const r1 = await session.decryptWithProof({
            userAddr: bob.accountAddress,
            publicKey: bob.publicKey,
            signature,
        });
        assert(r1.isOk, `within-buffer decrypt failed: ${r1.errValue}`);
        assert(
            new TextDecoder().decode(r1.okValue!) === 'PING',
            `within-buffer plaintext mismatch: ${r1.okValue}`,
        );
        console.log('  ✓ Workers retained epoch-1 shares within the 30s buffer; decrypt succeeded.');

        // ── Past buffer ───────────────────────────────────────────────────
        // Wait until well past the 30s eviction deadline (timed from
        // worker's view of the rotation) + the 5s cleanup-tick lag.
        const sinceRotationMs = Date.now() - rotation.observedAtMs;
        const totalWaitMs = (BUFFER_SECS + POST_BUFFER_GRACE_SECS) * 1000;
        const remainingMs = Math.max(0, totalWaitMs - sinceRotationMs);
        console.log(`\nWaiting ${remainingMs / 1000}s past rotation for buffer eviction...`);
        await sleep(remainingMs);

        console.log('── Past-buffer replay (same request, after eviction) ──');
        const r2 = await session.decryptWithProof({
            userAddr: bob.accountAddress,
            publicKey: bob.publicKey,
            signature,
        });
        assert(!r2.isOk, `past-buffer decrypt should have failed but succeeded`);
        console.log(`  ✓ Workers evicted epoch-1 shares; decrypt rejected (${r2.errValue}).`);

        console.log('\n✅ Epoch-buffer test passed!\n');
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        cleanupScenario(workers, localnetProc);
        process.exit(exitCode);
    }
}

main();
