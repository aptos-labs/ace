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
 *  3. Bob builds a `DecryptionSession` and signs the wallet fullMessage.
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

import { Account, AccountAddress, Ed25519PrivateKey, Signature } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { ChildProcess } from 'child_process';

import { setupAccessControlAppAndEncryptPing } from './common/access-control-app';
import { AceNetworkState, setupAceOnLocalnet } from './common/ace-network';
import { CHAIN_ID } from './common/config';
import { assert, cleanupScenario, fundAccount, getNetworkState, sleep } from './common/helpers';
import { buildAptosWalletFullMessage } from './common/aptos-wallet-message';

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

/** Build a `DecryptionSession` at the current epoch and capture Bob's
 *  signature over the wallet fullMessage. The session caches `request` (with
 *  the current epoch) + `networkState`, so future `decryptWithProof(...)`
 *  calls replay the captured bytes even after the chain rotates. */
async function captureSignedSessionAtEpoch(args: {
    aceState: AceNetworkState;
    bob: Account;
    keypair0Id: AccountAddress;
    correctDomain: Uint8Array;
    pingCiph: Uint8Array;
    expectedEpoch: number;
}): Promise<{ session: ACE.AptosBasicFlow.DecryptionSession; signature: Signature; fullMessage: string }> {
    const session = await ACE.AptosBasicFlow.DecryptionSession.create({
        aceDeployment: args.aceState.aceDeployment,
        keypairId: args.keypair0Id,
        chainId: CHAIN_ID,
        moduleAddr: args.aceState.adminAccountAddress,
        moduleName: 'access_control',
        label: args.correctDomain,
        ciphertext: args.pingCiph,
    });
    const msg = await session.getRequestToSign();
    const fullMessage = buildAptosWalletFullMessage({
        accountAddress: args.bob.accountAddress,
        chainId: CHAIN_ID,
        message: msg,
        nonce: 'epoch-buffer-captured-session',
    });
    const signature = args.bob.sign(fullMessage);
    const capturedEpoch = Number(session.request!.epoch);
    console.log(`Session captured at epoch=${capturedEpoch}`);
    assert(
        capturedEpoch === args.expectedEpoch,
        `session captured at wrong epoch (expected ${args.expectedEpoch}, got ${capturedEpoch})`,
    );
    return { session, signature, fullMessage };
}

/** Replay a previously-captured session's `decryptWithProof` and assert
 *  the success/failure outcome the caller expects. On success, also
 *  asserts the PING plaintext. */
async function replayDecryptWithExpectation(args: {
    session: ACE.AptosBasicFlow.DecryptionSession;
    bob: Account;
    signature: Signature;
    fullMessage: string;
    expectOk: boolean;
    label: string;
}): Promise<void> {
    console.log(`\n── ${args.label} ──`);
    const r = await args.session.decryptWithProof({
        userAddr: args.bob.accountAddress,
        publicKey: args.bob.publicKey,
        signature: args.signature,
        fullMessage: args.fullMessage,
    });
    if (args.expectOk) {
        assert(r.isOk, `replay failed: ${r.errValue}`);
        assert(
            new TextDecoder().decode(r.okValue!) === 'PING',
            `plaintext mismatch: ${r.okValue}`,
        );
        console.log('  ✓ Decrypt succeeded.');
    } else {
        assert(!r.isOk, `replay should have failed but succeeded`);
        console.log(`  ✓ Decrypt rejected (${r.errValue}).`);
    }
}

/** Stand up the ACE localnet, fund Bob, deploy access-control + encrypt
 *  PING, sanity-check we're at epoch 1, and capture the signed session.
 *  Returns everything `main()` needs to drive the rotation + replay
 *  phases. */
async function bringUpAndCaptureSession(): Promise<{
    workers: ChildProcess[];
    localnetProc: ChildProcess;
    aceState: AceNetworkState;
    session: ACE.AptosBasicFlow.DecryptionSession;
    bob: Account;
    signature: Signature;
    fullMessage: string;
    initialEpoch: number;
}> {
    const setup = await setupAceOnLocalnet({
        totalWorkers: TOTAL_WORKERS, epoch0WorkerIndices: EPOCH0_WORKER_INDICES,
        epoch0Threshold: EPOCH0_THRESHOLD, fundAccount, numKeypairs: 1,
        reshareIntervalSecs: RESHARE_INTERVAL_SECS,
    });
    const { actors, ace: aceState, keypairIds: [keypair0Id] } = setup;
    const bob = await buildAndFundBob();
    const { correctDomain, pingCiph } = await setupAccessControlAppAndEncryptPing(
        actors, bob.accountAddress,
        aceState.aceDeployment, aceState.adminAccountAddress, keypair0Id,
    );
    const initial = (await getNetworkState(aceState.adminAccountAddress))
        .unwrapOrThrow('initial getNetworkState');
    const initialEpoch = Number(initial.epoch);
    assert(initialEpoch === 1, `expected initial epoch=1, got ${initialEpoch}`);
    const { session, signature, fullMessage } = await captureSignedSessionAtEpoch({
        aceState, bob, keypair0Id, correctDomain, pingCiph, expectedEpoch: initialEpoch,
    });
    return {
        workers: setup.ace.workers, localnetProc: setup.localnetProc,
        aceState, session, bob, signature, fullMessage, initialEpoch,
    };
}

async function main(): Promise<void> {
    let workers: ChildProcess[] = [];
    let localnetProc: ChildProcess | null = null;
    let exitCode = 0;
    try {
        const ctx = await bringUpAndCaptureSession();
        workers = ctx.workers;
        localnetProc = ctx.localnetProc;
        console.log(`Waiting for auto-rotation to epoch=${ctx.initialEpoch + 1}...`);
        const rotation = await waitForEpochAdvance(
            ctx.initialEpoch + 1, ctx.aceState.adminAccountAddress, 120_000,
        );
        console.log(`Rotation observed at epoch=${rotation.epoch}.`);
        await replayDecryptWithExpectation({
            session: ctx.session, bob: ctx.bob, signature: ctx.signature,
            fullMessage: ctx.fullMessage, expectOk: true,
            label: 'Within-buffer replay (request signed at epoch=N, submitted after N+1)',
        });
        const remainingMs = Math.max(
            0,
            (BUFFER_SECS + POST_BUFFER_GRACE_SECS) * 1000 - (Date.now() - rotation.observedAtMs),
        );
        console.log(`\nWaiting ${remainingMs / 1000}s past rotation for buffer eviction...`);
        await sleep(remainingMs);
        await replayDecryptWithExpectation({
            session: ctx.session, bob: ctx.bob, signature: ctx.signature,
            fullMessage: ctx.fullMessage, expectOk: false,
            label: 'Past-buffer replay (same request, after eviction)',
        });
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
