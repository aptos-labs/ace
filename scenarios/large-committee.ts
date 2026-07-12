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
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import * as path from 'path';
import {
    startLocalnet, fundAccount, log, deployContracts, submitTxn, sleep,
    getNetworkState, getDKGSession, getDKRSession,
    proposeAndApprove, serializeNewSecretProposal, serializeCommitteeChangeProposal,
} from './common/helpers';
import { buildRustWorkspace, spawnNetworkNode } from './common/network-clients';
import { makeNodeMsgEndpoints } from './common/vss-protocol-setup';

const NUM_WORKERS = 20;
const THRESHOLD = Math.floor(NUM_WORKERS / 2) + 1;
const PHASE_TIMEOUT_MS = Number(process.env.LARGE_COMMITTEE_PHASE_TIMEOUT_MS ?? 900_000);

if (!Number.isFinite(PHASE_TIMEOUT_MS) || PHASE_TIMEOUT_MS <= 0) {
    throw `invalid LARGE_COMMITTEE_PHASE_TIMEOUT_MS=${process.env.LARGE_COMMITTEE_PHASE_TIMEOUT_MS}`;
}

async function main() {
    const localnetProc = await startLocalnet();
    const nodeProcs: ReturnType<typeof spawnNetworkNode>[] = [];
    const tmpRoot = mkdtempSync(path.join(tmpdir(), 'ace-large-committee-'));

    try {
        const accounts = Array.from({ length: NUM_WORKERS + 1 }, () => Account.generate());
        const encKeypairs = await Promise.all(Array.from({ length: NUM_WORKERS }, () => ace.pke.keygen()));
        const sigKeypairs = await Promise.all(Array.from({ length: NUM_WORKERS }, () => ace.sig.keygen()));
        for (const account of accounts) await fundAccount(account.accountAddress);

        const adminAccount = accounts[NUM_WORKERS];
        const workerAccounts = accounts.slice(0, NUM_WORKERS);
        const aceContract = adminAccount.accountAddress.toStringLong();
        const storeUrls = workerAccounts.map((_, i) => `sqlite://${path.join(tmpRoot, `node-${i}.db`)}`);
        const nodeMsgEndpoints = makeNodeMsgEndpoints(NUM_WORKERS);

        log(`Large-committee smoke test: NUM_WORKERS=${NUM_WORKERS}, THRESHOLD=${THRESHOLD}`);

        log('Deploy contracts.');
        await deployContracts(adminAccount, ['pke', 'sig', 'worker_config', 'group', 'secret-usage', 'fiat-shamir-transform', 'sigma-dlog-linear', 'pedersen-polynomial-commitment', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network']);

        log('Register worker keys and node-msg endpoints.');
        for (let i = 0; i < NUM_WORKERS; i++) {
            (await submitTxn({
                signer: workerAccounts[i],
                entryFunction: `${aceContract}::worker_config::register_pke_enc_key`,
                args: [encKeypairs[i].encryptionKey.toBytes()],
            })).unwrapOrThrow('register_pke_enc_key failed').asSuccessOrThrow();
            (await submitTxn({
                signer: workerAccounts[i],
                entryFunction: `${aceContract}::worker_config::register_sig_verification_key`,
                args: [sigKeypairs[i].publicKey.toBytes()],
            })).unwrapOrThrow('register_sig_verification_key failed').asSuccessOrThrow();
            (await submitTxn({
                signer: workerAccounts[i],
                entryFunction: `${aceContract}::worker_config::register_node_msg_endpoint`,
                args: [nodeMsgEndpoints.registeredUrls[i]],
            })).unwrapOrThrow('register_node_msg_endpoint failed').asSuccessOrThrow();
        }

        log('Build network-node binary and start one process per worker.');
        await buildRustWorkspace();
        for (let i = 0; i < NUM_WORKERS; i++) {
            nodeProcs.push(spawnNetworkNode({
                runAs: workerAccounts[i],
                pkeDkHex: `0x${Buffer.from(encKeypairs[i].decryptionKey.toBytes()).toString('hex')}`,
                sigSkHex: sigKeypairs[i].signingKey.toHex(),
                vssStoreUrl: storeUrls[i],
                nodeMsgListen: nodeMsgEndpoints.listens[i],
                aceDeploymentAddr: aceContract,
            }));
        }

        log(`Admin: start_initial_epoch(all ${NUM_WORKERS} workers, threshold=${THRESHOLD}).`);
        (await submitTxn({
            signer: adminAccount,
            entryFunction: `${aceContract}::network::start_initial_epoch`,
            args: [workerAccounts.map(w => w.accountAddress), THRESHOLD, 600],
        })).unwrapOrThrow('start_initial_epoch failed').asSuccessOrThrow();

        log('Admin: propose new_secret(primitive=1); threshold approvers sign.');
        {
            const approvers = workerAccounts.slice(0, THRESHOLD);
            await proposeAndApprove(approvers[0]!, approvers, aceContract, serializeNewSecretProposal(1));
        }

        log(`Poll until DKG epoch change completes (deadline: ${PHASE_TIMEOUT_MS / 1000}s).`);
        const dkgDeadlineMillis = Date.now() + PHASE_TIMEOUT_MS;
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
            throw `DKG did not complete within ${PHASE_TIMEOUT_MS / 1000}s (NUM_WORKERS=${NUM_WORKERS}).`;
        }

        const dkgSessionAddr = networkState.secrets[0]!.currentSession;
        const dkgSession = (await getDKGSession(adminAccount.accountAddress, dkgSessionAddr))
            .unwrapOrThrow('Failed to read DKG session.');
        if (dkgSession.commitmentPoints.length !== NUM_WORKERS + 1) {
            throw `expected ${NUM_WORKERS + 1} DKG commitment points, got ${dkgSession.commitmentPoints.length}`;
        }
        const baselineC0 = dkgSession.commitmentPoints[0]!.toHex();
        log(`DKG complete. C0=${baselineC0}`);

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

        log(`Poll until epoch advances to 2 (deadline: ${PHASE_TIMEOUT_MS / 1000}s).`);
        const dkrDeadlineMillis = Date.now() + PHASE_TIMEOUT_MS;
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
            throw `Epoch change did not complete within ${PHASE_TIMEOUT_MS / 1000}s (NUM_WORKERS=${NUM_WORKERS}).`;
        }

        const dkrSessionAddr = finalState.secrets[0]!.currentSession;
        const dkrSession = (await getDKRSession(adminAccount.accountAddress, dkrSessionAddr))
            .unwrapOrThrow('Failed to read DKR session.');

        if (dkrSession.commitmentPoints[0]!.toHex() !== baselineC0) {
            throw `commitment mismatch after resharing.\n  before: ${baselineC0}\n  after:  ${dkrSession.commitmentPoints[0]!.toHex()}`;
        }

        log(`PASS: large-committee smoke test with NUM_WORKERS=${NUM_WORKERS}, THRESHOLD=${THRESHOLD}.`);
        log(`reshared C0: ${dkrSession.commitmentPoints[0]!.toHex()}`);

    } finally {
        for (const proc of nodeProcs) proc.kill();
        localnetProc.kill();
        rmSync(tmpRoot, { recursive: true, force: true });
    }
}

main();
