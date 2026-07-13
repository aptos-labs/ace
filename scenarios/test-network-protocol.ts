// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * E2E for the network orchestration contract with offchain VSS shares.
 *
 * Verifies that the full epoch flow (DKG -> DKR reshare -> DKR reshare + another
 * DKG) works end-to-end with G2 PCS commitments across Move + TS SDK + the
 * network-node Rust workers.
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

function assertSameCommitment(label: string, expectedHex: string, actualHex: string): void {
    if (actualHex !== expectedHex) {
        throw `${label} commitment mismatch.\n  expected: ${expectedHex}\n  got:      ${actualHex}`;
    }
}

async function main() {
    const localnetProc = await startLocalnet();
    const nodeProcs: ReturnType<typeof spawnNetworkNode>[] = [];
    const tmpRoot = mkdtempSync(path.join(tmpdir(), 'ace-network-'));

    try {
        const numWorkers = 3;
        const accounts: Account[] = Array.from({ length: numWorkers + 1 }, () => Account.generate());
        const encKeypairs = await Promise.all(Array.from({ length: numWorkers }, () => ace.pke.keygen()));
        const sigKeypairs = await Promise.all(Array.from({ length: numWorkers }, () => ace.sig.keygen()));
        for (const account of accounts) {
            await fundAccount(account.accountAddress);
        }

        const adminAccount = accounts[numWorkers]!;
        const workerAccounts = accounts.slice(0, numWorkers);
        const aceContract = adminAccount.accountAddress.toStringLong();

        const committee = workerAccounts;
        const threshold = 2;
        const storeUrls = workerAccounts.map((_, i) => `sqlite://${path.join(tmpRoot, `node-${i}.db`)}`);
        const nodeMsgEndpoints = makeNodeMsgEndpoints(numWorkers);

        log('Deploy contracts.');
        await deployContracts(adminAccount, ['pke', 'sig', 'worker_config', 'group', 'secret-usage', 'fiat-shamir-transform', 'sigma-dlog-linear', 'pedersen-polynomial-commitment', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network']);

        log('Register worker keys and node-msg endpoints.');
        for (let i = 0; i < numWorkers; i++) {
            (await submitTxn({
                signer: workerAccounts[i]!,
                entryFunction: `${aceContract}::worker_config::register_pke_enc_key`,
                args: [encKeypairs[i]!.encryptionKey.toBytes()],
            })).unwrapOrThrow('Failed to register worker.').asSuccessOrThrow();

            (await submitTxn({
                signer: workerAccounts[i]!,
                entryFunction: `${aceContract}::worker_config::register_sig_verification_key`,
                args: [sigKeypairs[i]!.publicKey.toBytes()],
            })).unwrapOrThrow('Failed to register worker sig key.').asSuccessOrThrow();

            (await submitTxn({
                signer: workerAccounts[i]!,
                entryFunction: `${aceContract}::worker_config::register_node_msg_endpoint`,
                args: [nodeMsgEndpoints.nodeMsgUrls[i]],
            })).unwrapOrThrow('Failed to register worker node-msg endpoint.').asSuccessOrThrow();
        }

        log('Build network-node and start one process per worker.');
        await buildRustWorkspace();
        for (let i = 0; i < numWorkers; i++) {
            nodeProcs.push(spawnNetworkNode({
                runAs: workerAccounts[i]!,
                pkeDkHex: `0x${Buffer.from(encKeypairs[i]!.decryptionKey.toBytes()).toString('hex')}`,
                sigSkHex: sigKeypairs[i]!.signingKey.toHex(),
                vssStoreUrl: storeUrls[i]!,
                nodeMsgListen: nodeMsgEndpoints.nodeMsgListens[i]!,
                aceDeploymentAddr: aceContract,
            }));
        }

        log('start_initial_epoch.');
        (await submitTxn({
            signer: adminAccount,
            entryFunction: `${aceContract}::network::start_initial_epoch`,
            args: [committee.map(w => w.accountAddress), threshold, 60],
        })).unwrapOrThrow('start_initial_epoch failed').asSuccessOrThrow();

        // ── Epoch 0→1: new threshold-VRF secret — DKG over G2 ─

        log('Propose new threshold-VRF secret — DKG over BLS12-381 G2.');
        const approvers = committee.slice(0, threshold);
        await proposeAndApprove(
            approvers[0]!,
            approvers,
            aceContract,
            serializeNewSecretProposal(ace.network.PRIMITIVE_BLS12381_THRESHOLD_VRF),
        );

        log('Poll until epoch=1 (DKG-G2 complete).');
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
        const dkgSession = (await getDKGSession(adminAccount.accountAddress, dkgSessionAddr))
            .unwrapOrThrow('Failed to read DKG session.');
        if (dkgSession.basePoint.scheme !== ace.vss.SCHEME_BLS12381G2) {
            throw `expected DKG base_point scheme=${ace.vss.SCHEME_BLS12381G2}, got ${dkgSession.basePoint.scheme}`;
        }
        if (dkgSession.commitmentPoints.length !== committee.length + 1) {
            throw `expected ${committee.length + 1} DKG commitment points, got ${dkgSession.commitmentPoints.length}`;
        }
        const originalC0 = dkgSession.commitmentPoints[0]!.toHex();
        log(`Original DKG C0: ${originalC0}`);

        // ── Epoch 1→2: timeout-triggered auto reshare ────────────────────────

        log('Wait for epoch 1 to time out and auto reshare → epoch 2.');
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
        if (state2.secrets.length !== 1) throw `Expected 1 secret after first DKR, got ${state2.secrets.length}`;

        const firstDkrAddr = state2.secrets[0]!.currentSession;
        const firstDkrSession = (await getDKRSession(adminAccount.accountAddress, firstDkrAddr))
            .unwrapOrThrow('Failed to read first DKR session.');
        if (!firstDkrSession.isCompleted()) throw 'First DKR session is not completed despite epoch advance.';
        if (firstDkrSession.pcsContext.generatorG.scheme !== ace.vss.SCHEME_BLS12381G2) {
            throw `first DKR PCS generator G scheme expected G2, got ${firstDkrSession.pcsContext.generatorG.scheme}`;
        }
        assertSameCommitment('first DKR reshared original secret', originalC0, firstDkrSession.commitmentPoints[0]!.toHex());

        // ── Epoch 2→3: new_secret proposal (DKR reshare + DKG for new secret) ─

        log('Propose new G2 test-only secret again in epoch 2.');
        await proposeAndApprove(
            approvers[0]!,
            approvers,
            aceContract,
            serializeNewSecretProposal(ace.network.PRIMITIVE_BLS12381_G2_TEST_ONLY),
        );

        log('Poll until epoch=3.');
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

        if (finalState.secrets.length !== 2) throw `Expected 2 secrets, got ${finalState.secrets.length}`;

        // secrets[0]: reshared original G2 secret. Its root Pedersen commitment
        // must be preserved across DKG -> DKR -> DKR.
        const resharedAddr = finalState.secrets[0]!.currentSession;
        const resharedSession = (await getDKRSession(adminAccount.accountAddress, resharedAddr))
            .unwrapOrThrow('Failed to read reshared DKR session.');
        if (!resharedSession.isCompleted()) throw 'Second DKR session is not completed despite epoch advance.';
        if (resharedSession.pcsContext.generatorG.scheme !== ace.vss.SCHEME_BLS12381G2) {
            throw `reshared session PCS generator G scheme expected G2, got ${resharedSession.pcsContext.generatorG.scheme}`;
        }
        assertSameCommitment('second DKR reshared original secret', originalC0, resharedSession.commitmentPoints[0]!.toHex());

        // secrets[1]: freshly created DKG-G2 secret.
        const newDkgAddr = finalState.secrets[1]!.currentSession;
        const newDkgSession = (await getDKGSession(adminAccount.accountAddress, newDkgAddr))
            .unwrapOrThrow('Failed to read new DKG session.');
        if (newDkgSession.basePoint.scheme !== ace.vss.SCHEME_BLS12381G2) {
            throw `new DKG basePoint scheme expected G2, got ${newDkgSession.basePoint.scheme}`;
        }
        if (newDkgSession.commitmentPoints.length !== committee.length + 1) {
            throw `expected ${committee.length + 1} new DKG commitment points, got ${newDkgSession.commitmentPoints.length}`;
        }

        log('Network test passed.');
        log(`  preserved original C0: ${originalC0}`);
        log(`  new DKG C0:            ${newDkgSession.commitmentPoints[0]!.toHex()}`);
    } finally {
        for (const proc of nodeProcs) proc.kill();
        localnetProc.kill();
        rmSync(tmpRoot, { recursive: true, force: true });
    }
}

main();
