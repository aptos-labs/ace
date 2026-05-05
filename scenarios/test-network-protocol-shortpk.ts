// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * E2E test for the network orchestration contract — legacy regression coverage for
 * BLS12-381 G1 / bfibe-bls12381-shortpk-otp-hmac (scheme = 0).
 *
 * The default network-protocol scenario (test-network-protocol.ts) uses G2 + shortsig-aead;
 * this one keeps the G1 / shortpk-otp-hmac path covered.
 *
 * Scenario:
 *   Committee: [A, B, C]  threshold=2  (unchanged throughout)
 *   epoch_duration = 60 s
 *
 * Flow:
 *   1. Deploy pke, worker_config, group, vss, dkg, dkr, epoch-change, network.
 *   2. Register PKE enc keys for A, B, C.
 *   3. Start network-node for each of A, B, C.
 *   4. Admin calls start_initial_epoch([A,B,C], 2, resharing_interval_secs=60).
 *   5. Node A proposes new_secret(0); B approves → DKG → epoch 0→1.
 *   6. Poll until epoch=1. Record baseline PK from the DKG session.
 *   7. Epoch 1 times out (≈60 s) → auto reshare (DKR) → epoch 1→2.
 *   8. Poll until epoch=2.
 *   9. Node A proposes new_secret(0) again; B approves → DKR (reshare) + DKG (new) → epoch 2→3.
 *  10. Poll until epoch=3.
 *  11. Assert epoch=3, cur_nodes=[A,B,C], cur_threshold=2, secrets=[reshared, new].
 *      Verify reshared secret PK matches baseline; new DKG resultPk is present.
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
} from './common/helpers';
import { buildRustWorkspace, spawnNetworkNode } from './common/network-clients';

async function main() {
    const localnetProc = await startLocalnet();
    const nodeProcs: ReturnType<typeof spawnNetworkNode>[] = [];

    try {
        // 1 admin + 3 workers: A=0, B=1, C=2
        const numWorkers = 3;
        const accounts: Account[] = Array.from({ length: numWorkers + 1 }, () => Account.generate());
        const encKeypairs = await Promise.all(Array.from({ length: numWorkers }, () => ace.pke.keygen()));
        for (const account of accounts) {
            await fundAccount(account.accountAddress);
        }

        const adminAccount = accounts[numWorkers]!;
        const workerAccounts = accounts.slice(0, numWorkers);
        const aceContract = adminAccount.accountAddress.toStringLong();

        const committee = workerAccounts; // [A, B, C]
        const threshold = 2;

        log('Deploy contracts.');
        await deployContracts(adminAccount, ['pke', 'worker_config', 'group', 'fiat-shamir-transform', 'sigma-dlog-eq', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network']);

        log('Register PKE enc keys for A, B, C.');
        for (let i = 0; i < numWorkers; i++) {
            (await submitTxn({
                signer: workerAccounts[i]!,
                entryFunction: `${aceContract}::worker_config::register_pke_enc_key`,
                args: [encKeypairs[i]!.encryptionKey.toBytes()],
            })).unwrapOrThrow('Failed to register worker.').asSuccessOrThrow();
        }

        log('Build network-node binary and start one process per worker (A, B, C).');
        await buildRustWorkspace();
        for (let i = 0; i < numWorkers; i++) {
            nodeProcs.push(spawnNetworkNode({
                runAs: workerAccounts[i]!,
                pkeDkHex: `0x${Buffer.from(encKeypairs[i]!.decryptionKey.toBytes()).toString('hex')}`,
                aceDeploymentAddr: aceContract,
            }));
        }

        log('Admin: start_initial_epoch([A,B,C], threshold=2, resharing_interval_secs=60).');
        (await submitTxn({
            signer: adminAccount,
            entryFunction: `${aceContract}::network::start_initial_epoch`,
            args: [
                committee.map(w => w.accountAddress),
                threshold,
                60,
            ],
        })).unwrapOrThrow('start_initial_epoch failed').asSuccessOrThrow();

        // ── Epoch 0→1: new_secret proposal (DKG) ────────────────────────────

        log('Node A: propose new_secret(scheme=0); B approves (A self-approves in new_proposal).');
        const approvers = committee.slice(0, threshold);
        await proposeAndApprove(
            approvers[0]!,
            approvers,
            aceContract,
            serializeNewSecretProposal(0),
        );

        log('Poll until epoch=1 (DKG complete).');
        const epoch1Deadline = Date.now() + 120_000;
        let state1: ace.network.State | undefined;
        while (Date.now() < epoch1Deadline) {
            const r = await getNetworkState(adminAccount.accountAddress);
            if (r.isOk) {
                state1 = r.okValue!;
                if (state1.epoch === 1) break;
            }
            await sleep(5_000);
        }
        if (!state1 || state1.epoch !== 1) throw 'Epoch 0→1 did not complete in time.';

        const dkgSessionAddr = state1.secrets[0]!.currentSession;
        log(`Epoch 1 reached. DKG session: ${dkgSessionAddr.toStringLong()}`);
        const dkgSession = (await getDKGSession(adminAccount.accountAddress, dkgSessionAddr))
            .unwrapOrThrow('Failed to read DKG session.');
        const baselinePk = dkgSession.resultPk;
        if (!baselinePk) throw 'DKG resultPk absent despite epoch advance';
        log(`Baseline PK: ${baselinePk.toHex()}`);

        // ── Epoch 1→2: timeout-triggered auto reshare (DKR, same committee) ──

        log('Waiting for epoch 1 to time out (~60 s) and auto reshare to complete → epoch 2.');
        const epoch2Deadline = Date.now() + 180_000;
        let state2: ace.network.State | undefined;
        while (Date.now() < epoch2Deadline) {
            const r = await getNetworkState(adminAccount.accountAddress);
            if (r.isOk) {
                state2 = r.okValue!;
                if (state2.epoch === 2) break;
            }
            await sleep(5_000);
        }
        if (!state2 || state2.epoch !== 2) throw 'Epoch 1→2 (timeout) did not complete in time.';
        log('Epoch 2 reached via timeout-triggered auto reshare.');

        // ── Epoch 2→3: new_secret proposal (DKR reshare + DKG for new secret) ─

        log('Node A: propose new_secret(scheme=0) in epoch 2; B approves.');
        await proposeAndApprove(
            approvers[0]!,
            approvers,
            aceContract,
            serializeNewSecretProposal(0),
        );

        log('Poll until epoch=3 (DKR + DKG complete).');
        const epoch3Deadline = Date.now() + 120_000;
        let finalState: ace.network.State | undefined;
        while (Date.now() < epoch3Deadline) {
            const r = await getNetworkState(adminAccount.accountAddress);
            if (r.isOk) {
                finalState = r.okValue!;
                if (finalState.epoch === 3) break;
            }
            await sleep(5_000);
        }
        if (!finalState || finalState.epoch !== 3) throw 'Epoch 2→3 did not complete in time.';
        log(`Epoch 3 reached.`);

        // ── Correctness assertions ───────────────────────────────────────────

        if (finalState.curNodes.length !== committee.length)
            throw `Expected ${committee.length} cur_nodes, got ${finalState.curNodes.length}`;

        const expectedAddrs = new Set(committee.map(w => w.accountAddress.toStringLong()));
        for (const node of finalState.curNodes) {
            if (!expectedAddrs.has(node.toStringLong()))
                throw `Unexpected cur_node after epoch change: ${node.toStringLong()}`;
        }

        if (finalState.curThreshold !== threshold)
            throw `Expected cur_threshold=${threshold}, got ${finalState.curThreshold}`;

        if (finalState.secrets.length !== 2)
            throw `Expected 2 secrets after epoch 2→3, got ${finalState.secrets.length}`;

        if (finalState.epochChangeInfo !== null)
            throw 'Expected epochChangeInfo to be None after epoch advance';

        // secrets[0]: reshared original secret (two DKR hops: 0→1 then 2→3). PK must be preserved.
        const resharedAddr = finalState.secrets[0]!.currentSession;
        const resharedSession = (await getDKRSession(adminAccount.accountAddress, resharedAddr))
            .unwrapOrThrow('Failed to read reshared DKR session.');
        if (resharedSession.secretlyScaledElement.toHex() !== baselinePk.toHex())
            throw `PK mismatch on reshared secret.\n  baseline: ${baselinePk.toHex()}\n  got:      ${resharedSession.secretlyScaledElement.toHex()}`;

        // secrets[1]: freshly created DKG secret. PK must be present.
        const newDkgAddr = finalState.secrets[1]!.currentSession;
        const newDkgSession = (await getDKGSession(adminAccount.accountAddress, newDkgAddr))
            .unwrapOrThrow('Failed to read new DKG session.');
        if (!newDkgSession.resultPk)
            throw 'New DKG session resultPk absent';

        log(`Network test passed.`);
        log(`  reshared PK:  ${resharedSession.secretlyScaledElement.toHex()}`);
        log(`  new DKG PK:   ${newDkgSession.resultPk.toHex()}`);

    } finally {
        for (const proc of nodeProcs) proc.kill();
        localnetProc.kill();
    }
}

main();
