// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Smoke test for max committee size.
 *
 * Scenario: N workers form a committee, run DKG in epoch 0, then reshard
 * (DKR) into the same committee in epoch 1. Adjust NUM_WORKERS and binary-
 * search to find the largest N the current implementation can handle.
 *
 * Known working: 4. Target: 20.
 */

import { Account } from '@aptos-labs/ts-sdk';
import * as ace from '@aptos-labs/ace-sdk';
import {
    startLocalnet, fundAccount, log, deployContracts, submitTxn, sleep,
    getNetworkState, getDKGSession, getDKRSession,
    proposeAndApprove, serializeNewSecretProposal, serializeCommitteeChangeProposal,
} from './common/helpers';
import { buildRustWorkspace, spawnNetworkNode } from './common/network-clients';

const NUM_WORKERS = 20;
const THRESHOLD = Math.floor(NUM_WORKERS / 2) + 1;

async function main() {
    const localnetProc = await startLocalnet();
    const nodeProcs: ReturnType<typeof spawnNetworkNode>[] = [];

    try {
        const accounts = Array.from({ length: NUM_WORKERS + 1 }, () => Account.generate());
        const encKeypairs = await Promise.all(Array.from({ length: NUM_WORKERS }, () => ace.pke.keygen()));
        for (const account of accounts) await fundAccount(account.accountAddress);

        const adminAccount = accounts[NUM_WORKERS];
        const workerAccounts = accounts.slice(0, NUM_WORKERS);
        const aceContract = adminAccount.accountAddress.toStringLong();

        log(`Large-committee smoke test: NUM_WORKERS=${NUM_WORKERS}, THRESHOLD=${THRESHOLD}`);

        log('Deploy contracts.');
        await deployContracts(adminAccount, ['pke', 'worker_config', 'group', 'fiat-shamir-transform', 'sigma-dlog-eq', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network']);

        log('Register PKE enc keys.');
        for (let i = 0; i < NUM_WORKERS; i++) {
            (await submitTxn({
                signer: workerAccounts[i],
                entryFunction: `${aceContract}::worker_config::register_pke_enc_key`,
                args: [encKeypairs[i].encryptionKey.toBytes()],
            })).unwrapOrThrow('register_pke_enc_key failed').asSuccessOrThrow();
        }

        log('Build network-node binary and start one process per worker.');
        await buildRustWorkspace();
        for (let i = 0; i < NUM_WORKERS; i++) {
            nodeProcs.push(spawnNetworkNode({
                runAs: workerAccounts[i],
                pkeDkHex: `0x${Buffer.from(encKeypairs[i].decryptionKey.toBytes()).toString('hex')}`,
                aceDeploymentAddr: aceContract,
            }));
        }

        log(`Admin: start_initial_epoch(all ${NUM_WORKERS} workers, threshold=${THRESHOLD}).`);
        (await submitTxn({
            signer: adminAccount,
            entryFunction: `${aceContract}::network::start_initial_epoch`,
            args: [workerAccounts.map(w => w.accountAddress), THRESHOLD, 600],
        })).unwrapOrThrow('start_initial_epoch failed').asSuccessOrThrow();

        log('Admin: propose new_secret(scheme=0); threshold approvers sign.');
        {
            const approvers = workerAccounts.slice(0, THRESHOLD);
            await proposeAndApprove(approvers[0]!, approvers, aceContract, serializeNewSecretProposal(1));
        }

        log('Poll until DKG epoch change completes (deadline: 5 min).');
        const dkgDeadlineMillis = Date.now() + 300_000;
        let networkState: ace.network.State | undefined;
        while (Date.now() < dkgDeadlineMillis) {
            const maybeState = await getNetworkState(adminAccount.accountAddress);
            if (maybeState.isOk) {
                networkState = maybeState.okValue!;
                if (networkState.epochChangeInfo === null && networkState.secrets.length >= 1) break;
            }
            await sleep(5_000);
        }
        if (!networkState || networkState.secrets.length < 1) {
            throw `DKG did not complete within 5 minutes (NUM_WORKERS=${NUM_WORKERS}).`;
        }

        const dkgSessionAddr = networkState.secrets[0]!.currentSession;
        const dkgSession = (await getDKGSession(adminAccount.accountAddress, dkgSessionAddr))
            .unwrapOrThrow('Failed to read DKG session.');
        const baselinePk = dkgSession.resultPk;
        if (!baselinePk) throw 'DKG resultPk absent despite state=DONE';
        log(`DKG complete. resultPk=${baselinePk.toHex()}`);

        // After new_secret, cur_nodes = same workers, cur_epoch = 1. Propose CommitteeChange (same workers).
        log(`Admin: propose CommitteeChange(same ${NUM_WORKERS} workers, threshold=${THRESHOLD}); threshold approvers sign.`);
        {
            const approvers = workerAccounts.slice(0, THRESHOLD);
            await proposeAndApprove(
                approvers[0]!,
                approvers,
                aceContract,
                serializeCommitteeChangeProposal(
                    workerAccounts.map(w => w.accountAddress),
                    THRESHOLD,
                ),
            );
        }

        log('Poll until epoch advances to 2 (deadline: 5 min).');
        const dkrDeadlineMillis = Date.now() + 300_000;
        let finalState: ace.network.State | undefined;
        while (Date.now() < dkrDeadlineMillis) {
            const maybeState = await getNetworkState(adminAccount.accountAddress);
            if (maybeState.isOk) {
                finalState = maybeState.okValue!;
                if (finalState.epoch === 2) break;
            }
            await sleep(5_000);
        }
        if (!finalState || finalState.epoch !== 2) {
            throw `Epoch change did not complete within 5 minutes (NUM_WORKERS=${NUM_WORKERS}).`;
        }

        const dkrSessionAddr = finalState.secrets[0]!.currentSession;
        const dkrSession = (await getDKRSession(adminAccount.accountAddress, dkrSessionAddr))
            .unwrapOrThrow('Failed to read DKR session.');

        if (dkrSession.secretlyScaledElement.toHex() !== baselinePk.toHex()) {
            throw `PK mismatch after resharing.\n  before: ${baselinePk.toHex()}\n  after:  ${dkrSession.secretlyScaledElement.toHex()}`;
        }

        log(`PASS: large-committee smoke test with NUM_WORKERS=${NUM_WORKERS}, THRESHOLD=${THRESHOLD}.`);
        log(`secretlyScaledElement: ${dkrSession.secretlyScaledElement.toHex()}`);

    } finally {
        for (const proc of nodeProcs) proc.kill();
        localnetProc.kill();
    }
}

main();
