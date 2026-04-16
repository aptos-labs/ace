// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * E2E test for automatic epoch change triggered by touch().
 *
 * Scenario:
 *   Committee: [A, B, C]  threshold=2  epoch_duration_secs=5
 *
 * Flow:
 *   1. Deploy pke, worker_config, group, vss, dkg, dkr, network.
 *   2. Register PKE enc keys for all 3 workers.
 *   3. Admin calls initialize(epoch_duration_secs=5) — enables auto-rotation.
 *   4. Admin calls start_initial_epoch([A,B,C], 2).
 *   5. Start network-node for each of A–C.
 *   6. Admin calls new_secret(0)  →  DKG session created; nodes drive it.
 *   7. Poll network::touch until DKG completes (dkgs_in_progress empty, secrets.length==1).
 *   8. Wait — do NOT call start_epoch_change manually.
 *   9. Poll network::touch until epoch advances to 1 (auto-triggered when epoch is stale).
 *  10. Assert epoch==1, same committee [A,B,C], threshold==2, PK unchanged.
 */

import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import * as ace from '@aptos-labs/ace-sdk';
import {
    startLocalnet,
    fundAccount,
    log,
    deployContracts,
    submitTxn,
    sleep,
    getNetworkState,
    getDKGSession,
    getDKRSession,
} from './helpers';
import { buildRustWorkspace, spawnNetworkNode } from './network-clients';

async function main() {
    const localnetProc = await startLocalnet();
    const nodeProcs: ReturnType<typeof spawnNetworkNode>[] = [];

    try {
        // 1 admin + 3 workers: A=0, B=1, C=2
        const numWorkers = 3;
        const accounts: Account[] = Array.from({ length: numWorkers + 1 }, () => Account.generate());
        const encKeypairs = Array.from({ length: numWorkers }, () => ace.pke.keygen());
        for (const account of accounts) {
            await fundAccount(account.accountAddress);
        }

        const adminAccount = accounts[numWorkers];
        const workerAccounts = accounts.slice(0, numWorkers);
        const aceContract = adminAccount.accountAddress.toStringLong();

        const committee = workerAccounts;
        const threshold = 2;

        log('Deploy contracts.');
        await deployContracts(adminAccount, ['pke', 'worker_config', 'group', 'vss', 'dkg', 'dkr', 'network']);

        log('Register PKE enc keys for all workers.');
        for (let i = 0; i < numWorkers; i++) {
            (await submitTxn({
                signer: workerAccounts[i],
                entryFunction: `${aceContract}::worker_config::register_pke_enc_key`,
                args: [encKeypairs[i].encryptionKey.toBytes()],
            })).unwrapOrThrow('Failed to register worker.').asSuccessOrThrow();
        }

        log('Admin: initialize(epoch_duration_secs=5) — enable auto epoch rotation.');
        (await submitTxn({
            signer: adminAccount,
            entryFunction: `${aceContract}::network::initialize`,
            args: [5],
        })).unwrapOrThrow('initialize failed').asSuccessOrThrow();

        log('Build network-node binary and start one process per worker (A–C).');
        await buildRustWorkspace();
        for (let i = 0; i < numWorkers; i++) {
            nodeProcs.push(spawnNetworkNode({
                runAs: workerAccounts[i],
                pkeDkHex: `0x${Buffer.from(encKeypairs[i].decryptionKey.toBytes()).toString('hex')}`,
                aceContract,
            }));
        }

        log('Admin: start_initial_epoch([A,B,C], threshold=2).');
        (await submitTxn({
            signer: adminAccount,
            entryFunction: `${aceContract}::network::start_initial_epoch`,
            args: [
                committee.map(w => w.accountAddress),
                threshold,
            ],
        })).unwrapOrThrow('start_initial_epoch failed').asSuccessOrThrow();

        log('Admin: new_secret(scheme=0) — BLS12-381 G1, randomness on-chain.');
        (await submitTxn({
            signer: adminAccount,
            entryFunction: `${aceContract}::network::new_secret`,
            args: [0],
        })).unwrapOrThrow('new_secret failed').asSuccessOrThrow();

        // ── Wait for DKG to complete ────────────────────────────────────────────

        log('Poll network::touch until DKG completes (workers drive it).');
        const dkgDeadlineMillis = Date.now() + 120_000;
        let networkState: ace.network.State | undefined;
        while (Date.now() < dkgDeadlineMillis) {
            const maybeState = await getNetworkState(adminAccount.accountAddress);
            if (maybeState.isOk) {
                networkState = maybeState.okValue!;
                if (networkState.dkgsInProgress.length === 0 && networkState.secrets.length >= 1) break;
            }
            await sleep(5_000);
        }
        if (!networkState || networkState.dkgsInProgress.length !== 0 || networkState.secrets.length < 1) {
            throw 'DKG did not complete in time.';
        }

        const dkgSessionAddr = networkState.secrets[0]!;
        log(`DKG complete. dkgSession=${dkgSessionAddr.toStringLong()}`);

        const dkgSession = (await getDKGSession(adminAccount.accountAddress, dkgSessionAddr))
            .unwrapOrThrow('Failed to read DKG session.');
        const baselinePk = dkgSession.resultPk;
        if (!baselinePk) throw 'DKG session resultPk is absent despite state=DONE';
        log(`DKG resultPk: ${baselinePk.toHex()}`);

        // ── Wait for auto epoch change (no manual start_epoch_change call) ──────

        log('Waiting for auto epoch change to trigger (epoch_duration=5s, workers keep calling touch()).');
        const dkrDeadlineMillis = Date.now() + 120_000;
        let finalState: ace.network.State | undefined;
        while (Date.now() < dkrDeadlineMillis) {
            const maybeState = await getNetworkState(adminAccount.accountAddress);
            if (maybeState.isOk) {
                finalState = maybeState.okValue!;
                if (finalState.epoch === 1) break;
            }
            await sleep(5_000);
        }
        if (!finalState || finalState.epoch !== 1) {
            throw 'Auto epoch change did not complete in time.';
        }

        log(`Epoch auto-advanced to ${finalState.epoch}.`);

        // ── Correctness assertions ──────────────────────────────────────────────

        if (finalState.curNodes.length !== committee.length) {
            throw `Expected ${committee.length} cur_nodes, got ${finalState.curNodes.length}`;
        }
        const expectedAddrs = new Set(committee.map(w => w.accountAddress.toStringLong()));
        for (const node of finalState.curNodes) {
            if (!expectedAddrs.has(node.toStringLong())) {
                throw `Unexpected cur_node after epoch change: ${node.toStringLong()}`;
            }
        }
        if (finalState.curThreshold !== threshold) {
            throw `Expected curThreshold=${threshold}, got ${finalState.curThreshold}`;
        }
        if (finalState.secrets.length !== 1) {
            throw `Expected 1 secret after epoch change, got ${finalState.secrets.length}`;
        }
        if (finalState.dkgsInProgress.length !== 0) {
            throw `Expected 0 dkgs_in_progress, got ${finalState.dkgsInProgress.length}`;
        }
        if (finalState.epochChangeState !== null) {
            throw 'Expected epoch_change_state to be None after epoch advance';
        }

        // Verify PK is unchanged after resharing.
        const dkrSessionAddr = finalState.secrets[0]!;
        const dkrSession = (await getDKRSession(adminAccount.accountAddress, dkrSessionAddr))
            .unwrapOrThrow('Failed to read DKR session.');

        if (dkrSession.secretlyScaledElement.toHex() !== baselinePk.toHex()) {
            throw `PK mismatch after resharing.\n  before: ${baselinePk.toHex()}\n  after:  ${dkrSession.secretlyScaledElement.toHex()}`;
        }

        log(`Auto epoch change test passed. secretlyScaledElement: ${dkrSession.secretlyScaledElement.toHex()}`);

    } finally {
        for (const proc of nodeProcs) proc.kill();
        localnetProc.kill();
    }
}

main();
