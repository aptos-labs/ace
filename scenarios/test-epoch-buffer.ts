// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * E2E test for serving previous-epoch IBE shares during the configured grace
 * window after an epoch rotation.
 *
 * The request is built and signed in epoch N, then replayed after the network
 * auto-rotates to epoch N+1. It should still decrypt inside the grace window
 * and fail after the same window has elapsed.
 */

import { Account, AccountAddress, Ed25519PrivateKey, Signature } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { rmSync } from 'fs';
import type { ChildProcess } from 'child_process';

import {
    deployAndInitAccessControl,
    domainForBlob,
    registerAllowlistBlob,
} from './common/access-control-app';
import { setupAceOnLocalnet, type AceNetworkState } from './common/ace-network';
import { buildAptosWalletFullMessage } from './common/aptos-wallet-message';
import { CHAIN_ID } from './common/config';
import {
    assert,
    assertTxnSuccess,
    cleanupScenario,
    createAptos,
    fundAccount,
    getNetworkState,
    sleep,
    submitTxn,
} from './common/helpers';

const TOTAL_WORKERS = 3;
const EPOCH0_WORKER_INDICES = [0, 1, 2];
const EPOCH0_THRESHOLD = 2;
const BOB_KEY_SEED = 200;
const RESHARE_INTERVAL_SECS = 30;
const PREVIOUS_EPOCH_GRACE_MICROS = 15_000_000;
const POST_GRACE_HEADROOM_MS = 10_000;

async function updatePreviousEpochGraceMicros(admin: Account, micros: number): Promise<void> {
    const adminAddr = admin.accountAddress.toStringLong();
    assertTxnSuccess(
        await submitTxn({
            signer: admin,
            entryFunction: `${adminAddr}::network::update_previous_epoch_grace_micros`,
            args: [micros],
        }),
        'network::update_previous_epoch_grace_micros',
    );
}

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
        await sleep(1_000);
    }
    throw new Error(`Epoch did not advance to ${targetEpoch} within ${timeoutMs / 1000}s`);
}

async function buildAndFundBob(): Promise<Account> {
    const bobKey = new Ed25519PrivateKey(
        Buffer.from(new Uint8Array(32).map((_, i) => i + BOB_KEY_SEED)),
    );
    const bob = Account.fromPrivateKey({ privateKey: bobKey });
    await fundAccount(bob.accountAddress);
    return bob;
}

async function captureSignedSessionAtEpoch(args: {
    aceState: AceNetworkState;
    bob: Account;
    keypairId: AccountAddress;
    label: Uint8Array;
    ciphertext: Uint8Array;
    expectedEpoch: number;
}): Promise<{ session: ACE.IBE_Aptos.BasicDecryptionSession; signature: Signature; fullMessage: string }> {
    const session = await ACE.IBE_Aptos.BasicDecryptionSession.create({
        aceDeployment: args.aceState.aceDeployment,
        keypairId: args.keypairId,
        chainId: CHAIN_ID,
        moduleAddr: args.aceState.adminAccountAddress,
        moduleName: 'access_control',
        label: args.label,
        ciphertext: args.ciphertext,
    });
    const msg = await session.getRequestToSign();
    const fullMessage = buildAptosWalletFullMessage({
        accountAddress: args.bob.accountAddress,
        chainId: CHAIN_ID,
        message: msg,
        nonce: 'epoch-buffer-captured-session',
    });
    const capturedEpoch = Number(session.request!.epoch);
    assert(
        capturedEpoch === args.expectedEpoch,
        `session captured at wrong epoch (expected ${args.expectedEpoch}, got ${capturedEpoch})`,
    );
    return { session, signature: args.bob.sign(fullMessage), fullMessage };
}

async function replayDecryptWithExpectation(args: {
    session: ACE.IBE_Aptos.BasicDecryptionSession;
    bob: Account;
    signature: Signature;
    fullMessage: string;
    expectOk: boolean;
    label: string;
}): Promise<void> {
    console.log(`\n-- ${args.label} --`);
    const r = await args.session.decryptWithProof({
        userAddr: args.bob.accountAddress,
        publicKey: args.bob.publicKey,
        signature: args.signature,
        fullMessage: args.fullMessage,
    });
    if (args.expectOk) {
        assert(r.isOk, `replay failed: ${r.errValue}`);
        assert(new TextDecoder().decode(r.okValue!) === 'PING', 'PING plaintext mismatch');
    } else {
        assert(!r.isOk, 'replay should have failed but succeeded');
    }
}

async function bringUpAndCaptureSession(): Promise<{
    workers: ChildProcess[];
    localnetProc: ChildProcess;
    vssStoreTmpRoot: string;
    aceState: AceNetworkState;
    session: ACE.IBE_Aptos.BasicDecryptionSession;
    bob: Account;
    signature: Signature;
    fullMessage: string;
    initialEpoch: number;
}> {
    const setup = await setupAceOnLocalnet({
        totalWorkers: TOTAL_WORKERS,
        epoch0WorkerIndices: EPOCH0_WORKER_INDICES,
        epoch0Threshold: EPOCH0_THRESHOLD,
        fundAccount,
        numKeypairs: 1,
        dkgPrimitive: ACE.network.PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEAD,
        reshareIntervalSecs: RESHARE_INTERVAL_SECS,
        postDkgSettleMs: 5_000,
    });
    const { actors, ace: aceState, keypairIds: [keypairId] } = setup;
    await updatePreviousEpochGraceMicros(actors.admin, PREVIOUS_EPOCH_GRACE_MICROS);

    const bob = await buildAndFundBob();
    await deployAndInitAccessControl(actors.admin, actors.adminAddr, actors.adminKeyHex);
    await registerAllowlistBlob(
        createAptos(),
        actors.alice,
        bob.accountAddress,
        actors.adminAddr,
        'ping-blob',
    );
    const label = domainForBlob(actors.alice, 'ping-blob');
    const ciphertext = (await ACE.IBE_Aptos.encrypt({
        aceDeployment: aceState.aceDeployment,
        keypairId,
        chainId: CHAIN_ID,
        moduleAddr: aceState.adminAccountAddress,
        moduleName: 'access_control',
        label,
        plaintext: new TextEncoder().encode('PING'),
    })).unwrapOrThrow('encrypt PING');

    const initial = (await getNetworkState(aceState.adminAccountAddress))
        .unwrapOrThrow('initial getNetworkState');
    const initialEpoch = Number(initial.epoch);
    assert(initialEpoch === 1, `expected initial epoch=1, got ${initialEpoch}`);
    const { session, signature, fullMessage } = await captureSignedSessionAtEpoch({
        aceState,
        bob,
        keypairId,
        label,
        ciphertext,
        expectedEpoch: initialEpoch,
    });

    return {
        workers: setup.ace.workers,
        localnetProc: setup.localnetProc,
        vssStoreTmpRoot: setup.ace.vssStoreTmpRoot,
        aceState,
        session,
        bob,
        signature,
        fullMessage,
        initialEpoch,
    };
}

async function main(): Promise<void> {
    let workers: ChildProcess[] = [];
    let localnetProc: ChildProcess | null = null;
    let vssStoreTmpRoot: string | undefined;
    let exitCode = 0;

    try {
        const ctx = await bringUpAndCaptureSession();
        workers = ctx.workers;
        localnetProc = ctx.localnetProc;
        vssStoreTmpRoot = ctx.vssStoreTmpRoot;

        console.log(`Waiting for auto-rotation to epoch=${ctx.initialEpoch + 1}...`);
        const rotation = await waitForEpochAdvance(
            ctx.initialEpoch + 1,
            ctx.aceState.adminAccountAddress,
            120_000,
        );
        console.log(`Rotation observed at epoch=${rotation.epoch}.`);

        await replayDecryptWithExpectation({
            session: ctx.session,
            bob: ctx.bob,
            signature: ctx.signature,
            fullMessage: ctx.fullMessage,
            expectOk: true,
            label: 'within grace window',
        });

        const graceMs = PREVIOUS_EPOCH_GRACE_MICROS / 1000;
        const remainingMs = Math.max(0, graceMs + POST_GRACE_HEADROOM_MS - (Date.now() - rotation.observedAtMs));
        console.log(`Waiting ${remainingMs / 1000}s for previous-epoch grace to expire...`);
        await sleep(remainingMs);

        await replayDecryptWithExpectation({
            session: ctx.session,
            bob: ctx.bob,
            signature: ctx.signature,
            fullMessage: ctx.fullMessage,
            expectOk: false,
            label: 'after grace window',
        });
        console.log('\nEpoch-buffer scenario passed.\n');
    } catch (err) {
        console.error('\nTest failed:', err);
        exitCode = 1;
    } finally {
        cleanupScenario(workers, localnetProc);
        if (vssStoreTmpRoot) rmSync(vssStoreTmpRoot, { recursive: true, force: true });
        process.exit(exitCode);
    }
}

main();
