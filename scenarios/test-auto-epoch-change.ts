// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * E2E test for automatic epoch change triggered by touch().
 *
 * Scenario:
 *   Committee: [A, B, C]  threshold=2  resharing_interval_secs=30
 *
 * Flow:
 *   1. Deploy pke, worker_config, group, vss, dkg, dkr, network.
 *   2. Register PKE enc keys for all 3 workers.
 *   3. Admin calls start_initial_epoch([A,B,C], 2, resharing_interval_secs=30).
 *   4. Start network-node for each of A–C.
 *   5. Admin proposes new_secret(0); A,B approve; workers drive epoch change (DKG).
 *   6. Poll until epoch advances to 1 (DKG complete, secrets.length==1).
 *   7. Wait — do NOT propose CommitteeChange manually.
 *   8. Poll until epoch advances to 2 (auto-triggered when epoch is stale).
 *   9. Assert epoch==2, same committee [A,B,C], threshold==2, PK unchanged.
 */

import { Account } from '@aptos-labs/ts-sdk';
import * as ace from '@aptos-labs/ace-sdk';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import * as path from 'path';
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
} from './common/helpers';
import { buildRustWorkspace, spawnNetworkNode } from './common/network-clients';
import { makeNodeMsgEndpoints } from './common/vss-protocol-setup';

async function main() {
    const localnetProc = await startLocalnet();
    const nodeProcs: ReturnType<typeof spawnNetworkNode>[] = [];
    const tmpRoot = mkdtempSync(path.join(tmpdir(), 'ace-auto-epoch-'));

    try {
        // 1 admin + 3 workers: A=0, B=1, C=2
        const numWorkers = 3;
        const accounts: Account[] = Array.from({ length: numWorkers + 1 }, () => Account.generate());
        const encKeypairs = await Promise.all(Array.from({ length: numWorkers }, () => ace.pke.keygen()));
        const sigKeypairs = await Promise.all(Array.from({ length: numWorkers }, () => ace.sig.keygen()));
        for (const account of accounts) {
            await fundAccount(account.accountAddress);
        }

        const adminAccount = accounts[numWorkers];
        const workerAccounts = accounts.slice(0, numWorkers);
        const aceContract = adminAccount.accountAddress.toStringLong();

        const committee = workerAccounts;
        const threshold = 2;
        const storeUrls = workerAccounts.map((_, i) => `sqlite://${path.join(tmpRoot, `node-${i}.db`)}`);
        const nodeMsgEndpoints = makeNodeMsgEndpoints(numWorkers);

        function assertSameCommitment(label: string, expectedHex: string, actualHex: string): void {
            if (actualHex !== expectedHex) {
                throw `${label} commitment mismatch.\n  expected: ${expectedHex}\n  got:      ${actualHex}`;
            }
        }

        log('Deploy contracts.');
        await deployContracts(adminAccount, ['pke', 'sig', 'worker_config', 'group', 'secret-usage', 'fiat-shamir-transform', 'sigma-dlog-linear', 'pedersen-polynomial-commitment', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network']);

        log('Register worker keys and node-msg endpoints.');
        for (let i = 0; i < numWorkers; i++) {
            (await submitTxn({
                signer: workerAccounts[i],
                entryFunction: `${aceContract}::worker_config::register_pke_enc_key`,
                args: [encKeypairs[i].encryptionKey.toBytes()],
            })).unwrapOrThrow('Failed to register worker.').asSuccessOrThrow();
            (await submitTxn({
                signer: workerAccounts[i],
                entryFunction: `${aceContract}::worker_config::register_sig_verification_key`,
                args: [sigKeypairs[i].publicKey.toBytes()],
            })).unwrapOrThrow('Failed to register worker sig key.').asSuccessOrThrow();
            (await submitTxn({
                signer: workerAccounts[i],
                entryFunction: `${aceContract}::worker_config::register_node_msg_endpoint`,
                args: [nodeMsgEndpoints.registeredUrls[i]],
            })).unwrapOrThrow('Failed to register worker node-msg endpoint.').asSuccessOrThrow();
        }

        log('Build network-node binary and start one process per worker (A–C).');
        await buildRustWorkspace();
        for (let i = 0; i < numWorkers; i++) {
            nodeProcs.push(spawnNetworkNode({
                runAs: workerAccounts[i],
                pkeDkHex: `0x${Buffer.from(encKeypairs[i].decryptionKey.toBytes()).toString('hex')}`,
                sigSkHex: sigKeypairs[i].signingKey.toHex(),
                vssStoreUrl: storeUrls[i],
                nodeMsgListen: nodeMsgEndpoints.listens[i],
                aceDeploymentAddr: aceContract,
            }));
        }

        log('Admin: start_initial_epoch([A,B,C], threshold=2, resharing_interval_secs=30).');
        (await submitTxn({
            signer: adminAccount,
            entryFunction: `${aceContract}::network::start_initial_epoch`,
            args: [
                committee.map(w => w.accountAddress),
                threshold,
                30,
            ],
        })).unwrapOrThrow('start_initial_epoch failed').asSuccessOrThrow();

        log('Admin: propose new_secret(primitive=1); A,B approve.');
        {
            const approvers = committee.slice(0, threshold);
            await proposeAndApprove(approvers[0]!, approvers, aceContract, serializeNewSecretProposal(1));
        }

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

        const dkgSessionAddr = networkState.secrets[0]!.currentSession;
        log(`DKG complete. dkgSession=${dkgSessionAddr.toStringLong()}`);

        const dkgSession = (await getDKGSession(adminAccount.accountAddress, dkgSessionAddr))
            .unwrapOrThrow('Failed to read DKG session.');
        if (dkgSession.commitmentPoints.length !== committee.length + 1) {
            throw `expected ${committee.length + 1} DKG commitment points, got ${dkgSession.commitmentPoints.length}`;
        }
        const baselineC0 = dkgSession.commitmentPoints[0]!.toHex();
        log(`DKG C0: ${baselineC0}`);

        // ── Wait for auto epoch change (no manual proposal) ──────────────────────

        log('Waiting for auto epoch change to trigger (epoch_duration=5s, workers keep calling touch()).');
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
        if (finalState.epochChangeInfo !== null) {
            throw 'Expected epoch_change_state to be None after epoch advance';
        }

        // Verify the root Pedersen commitment is unchanged after resharing.
        const dkrSessionAddr = finalState.secrets[0]!.currentSession;
        const dkrSession = (await getDKRSession(adminAccount.accountAddress, dkrSessionAddr))
            .unwrapOrThrow('Failed to read DKR session.');

        assertSameCommitment('auto-reshared secret', baselineC0, dkrSession.commitmentPoints[0]!.toHex());

        log(`Auto epoch change test passed. reshared C0: ${dkrSession.commitmentPoints[0]!.toHex()}`);

    } finally {
        for (const proc of nodeProcs) proc.kill();
        localnetProc.kill();
        rmSync(tmpRoot, { recursive: true, force: true });
    }
}

main();
