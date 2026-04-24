// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * E2E test for the network orchestration contract.
 *
 * Scenario:
 *   Old committee: [A, B, C]  threshold=2
 *   New committee: [B, C, D, E]  threshold=3
 *
 * Flow:
 *   1. Deploy pke, worker_config, group, vss, dkg, dkr, network.
 *   2. Register PKE enc keys for all 5 workers.
 *   3. Start network-node for each of A–E (workers watch chain BEFORE admin acts).
 *   4. Admin calls start_initial_epoch([A,B,C], 2, resharing_interval_secs=600).
 *   5. Admin proposes new_secret(0); A,B approve; workers drive epoch change (DKG).
 *   6. Poll until epoch advances to 1 (DKG complete, secrets.length==1).
 *   7. Admin proposes CommitteeChange([B,C,D,E], 3); A,B approve; workers drive DKR.
 *   8. Poll until epoch advances to 2.
 *   9. Assert epoch==2, cur_nodes==[B,C,D,E], cur_threshold==3, PK unchanged.
 */

import { Account } from '@aptos-labs/ts-sdk';
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
    proposeAndApprove,
    serializeNewSecretProposal,
    serializeCommitteeChangeProposal,
} from './common/helpers';
import { buildRustWorkspace, spawnNetworkNode } from './common/network-clients';

async function main() {
    const localnetProc = await startLocalnet();
    const nodeProcs: ReturnType<typeof spawnNetworkNode>[] = [];

    try {
        // 1 admin + 5 workers: A=0, B=1, C=2, D=3, E=4
        const numWorkers = 5;
        const accounts: Account[] = Array.from({ length: numWorkers + 1 }, () => Account.generate());
        const encKeypairs = Array.from({ length: numWorkers }, () => ace.pke.keygen());
        for (const account of accounts) {
            await fundAccount(account.accountAddress);
        }

        const adminAccount = accounts[numWorkers];
        const workerAccounts = accounts.slice(0, numWorkers);
        const aceContract = adminAccount.accountAddress.toStringLong();

        // Old committee: [A, B, C] = workers[0..2], threshold=2
        const oldCommittee = workerAccounts.slice(0, 3);
        const oldThreshold = 2;

        // New committee: [B, C, D, E] = workers[1..4], threshold=3
        const newCommittee = workerAccounts.slice(1, 5);
        const newThreshold = 3;

        log('Deploy contracts.');
        await deployContracts(adminAccount, ['pke', 'worker_config', 'group', 'fiat-shamir-transform', 'sigma-dlog-eq', 'vss', 'dkg', 'dkr', 'network']);

        log('Register PKE enc keys for all workers.');
        for (let i = 0; i < numWorkers; i++) {
            (await submitTxn({
                signer: workerAccounts[i],
                entryFunction: `${aceContract}::worker_config::register_pke_enc_key`,
                args: [encKeypairs[i].encryptionKey.toBytes()],
            })).unwrapOrThrow('Failed to register worker.').asSuccessOrThrow();
        }

        log('Build network-node binary and start one process per worker (A–E).');
        await buildRustWorkspace();
        for (let i = 0; i < numWorkers; i++) {
            nodeProcs.push(spawnNetworkNode({
                runAs: workerAccounts[i],
                pkeDkHex: `0x${Buffer.from(encKeypairs[i].decryptionKey.toBytes()).toString('hex')}`,
                aceDeploymentAddr: aceContract,
            }));
        }

        log('Admin: start_initial_epoch([A,B,C], threshold=2, resharing_interval_secs=600).');
        (await submitTxn({
            signer: adminAccount,
            entryFunction: `${aceContract}::network::start_initial_epoch`,
            args: [
                oldCommittee.map(w => w.accountAddress),
                oldThreshold,
                600,
            ],
        })).unwrapOrThrow('start_initial_epoch failed').asSuccessOrThrow();

        log('Admin: propose new_secret(scheme=0); A,B approve.');
        await proposeAndApprove(
            adminAccount,
            oldCommittee.slice(0, oldThreshold),
            aceContract,
            serializeNewSecretProposal(0),
        );

        // ── Wait for DKG epoch change to complete (epoch 0→1) ──────────────────

        log('Poll network::touch until epoch advances to 1 (DKG complete).');
        const dkgDeadlineMillis = Date.now() + 120_000;
        let networkState: ace.network.State | undefined;
        while (Date.now() < dkgDeadlineMillis) {
            const maybeState = await getNetworkState(adminAccount.accountAddress);
            if (maybeState.isOk) {
                networkState = maybeState.okValue!;
                if (networkState.epoch === 1) break;
            }
            await sleep(5_000);
        }
        if (!networkState || networkState.epoch !== 1) {
            throw 'DKG epoch change did not complete in time.';
        }

        const dkgSessionAddr = networkState.secrets[0]!;
        log(`DKG complete. dkgSession=${dkgSessionAddr.toStringLong()}`);

        const dkgSession = (await getDKGSession(adminAccount.accountAddress, dkgSessionAddr))
            .unwrapOrThrow('Failed to read DKG session.');
        const baselinePk = dkgSession.resultPk;
        if (!baselinePk) throw 'DKG session resultPk is absent despite state=DONE';
        log(`DKG resultPk (secretlyScaledElement): ${baselinePk.toHex()}`);

        // ── Propose CommitteeChange ──────────────────────────────────────────────

        log('Admin: propose CommitteeChange([B,C,D,E], threshold=3); A,B approve.');
        await proposeAndApprove(
            adminAccount,
            oldCommittee.slice(0, oldThreshold),
            aceContract,
            serializeCommitteeChangeProposal(
                newCommittee.map(w => w.accountAddress),
                newThreshold,
            ),
        );

        // ── Wait for epoch change to complete (epoch 1→2) ───────────────────────

        log('Poll network::touch until epoch advances to 2 (workers drive DKR).');
        const dkrDeadlineMillis = Date.now() + 120_000;
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
            throw 'Epoch change did not complete in time.';
        }

        log(`Epoch advanced to ${finalState.epoch}.`);

        // ── Correctness assertions ──────────────────────────────────────────────

        if (finalState.curNodes.length !== newCommittee.length) {
            throw `Expected ${newCommittee.length} cur_nodes, got ${finalState.curNodes.length}`;
        }
        const expectedAddrs = new Set(newCommittee.map(w => w.accountAddress.toStringLong()));
        for (const node of finalState.curNodes) {
            if (!expectedAddrs.has(node.toStringLong())) {
                throw `Unexpected cur_node after epoch change: ${node.toStringLong()}`;
            }
        }
        if (finalState.curThreshold !== newThreshold) {
            throw `Expected cur_threshold=${newThreshold}, got ${finalState.curThreshold}`;
        }
        if (finalState.secrets.length !== 1) {
            throw `Expected 1 secret after epoch change, got ${finalState.secrets.length}`;
        }
        if (finalState.epochChangeState !== null) {
            throw 'Expected epoch_change_state to be None after epoch advance';
        }

        // The DKR session is now stored at secrets[0]. Verify PK is unchanged.
        const dkrSessionAddr = finalState.secrets[0]!;
        const dkrSession = (await getDKRSession(adminAccount.accountAddress, dkrSessionAddr))
            .unwrapOrThrow('Failed to read DKR session.');

        if (dkrSession.secretlyScaledElement.toHex() !== baselinePk.toHex()) {
            throw `PK mismatch after resharing.\n  before: ${baselinePk.toHex()}\n  after:  ${dkrSession.secretlyScaledElement.toHex()}`;
        }

        log(`Network test passed. secretlyScaledElement: ${dkrSession.secretlyScaledElement.toHex()}`);

    } finally {
        for (const proc of nodeProcs) proc.kill();
        localnetProc.kill();
    }
}

main();
