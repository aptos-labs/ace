// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * E2E for the network orchestration contract over BLS12-381 G2 / shortsig-aead.
 *
 * Mirror of test-network-protocol.ts with the proposed DKG group flipped from G1
 * (scheme=0, → bfibe-bls12381-shortpk-otp-hmac) to G2 (scheme=1, →
 * bfibe-bls12381-shortsig-aead). Verifies that the full epoch flow (DKG → reshare
 * via DKR → another DKG) works end-to-end with G2 base points across Move +
 * TS SDK + the network-node Rust workers (which dispatch IDK-share extraction
 * on the t-IBE scheme byte derived from the DKG basepoint group).
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
        const numWorkers = 3;
        const accounts: Account[] = Array.from({ length: numWorkers + 1 }, () => Account.generate());
        const encKeypairs = await Promise.all(Array.from({ length: numWorkers }, () => ace.pke.keygen()));
        for (const account of accounts) {
            await fundAccount(account.accountAddress);
        }

        const adminAccount = accounts[numWorkers]!;
        const workerAccounts = accounts.slice(0, numWorkers);
        const aceContract = adminAccount.accountAddress.toStringLong();

        const committee = workerAccounts;
        const threshold = 2;

        log('Deploy contracts.');
        await deployContracts(adminAccount, ['pke', 'worker_config', 'group', 'fiat-shamir-transform', 'sigma-dlog-eq', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network']);

        log('Register PKE enc keys.');
        for (let i = 0; i < numWorkers; i++) {
            (await submitTxn({
                signer: workerAccounts[i]!,
                entryFunction: `${aceContract}::worker_config::register_pke_enc_key`,
                args: [encKeypairs[i]!.encryptionKey.toBytes()],
            })).unwrapOrThrow('Failed to register worker.').asSuccessOrThrow();
        }

        log('Build network-node and start one process per worker.');
        await buildRustWorkspace();
        for (let i = 0; i < numWorkers; i++) {
            nodeProcs.push(spawnNetworkNode({
                runAs: workerAccounts[i]!,
                pkeDkHex: `0x${Buffer.from(encKeypairs[i]!.decryptionKey.toBytes()).toString('hex')}`,
                aceDeploymentAddr: aceContract,
            }));
        }

        log('start_initial_epoch.');
        (await submitTxn({
            signer: adminAccount,
            entryFunction: `${aceContract}::network::start_initial_epoch`,
            args: [committee.map(w => w.accountAddress), threshold, 60],
        })).unwrapOrThrow('start_initial_epoch failed').asSuccessOrThrow();

        // ── Epoch 0→1: new_secret(scheme=1) — DKG over G2, t-IBE = shortsig-aead ─

        log('Propose new_secret(scheme=1) — DKG over BLS12-381 G2 → t-IBE = shortsig-aead.');
        const approvers = committee.slice(0, threshold);
        await proposeAndApprove(
            approvers[0]!,
            approvers,
            aceContract,
            serializeNewSecretProposal(1),
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
        const baselinePk = dkgSession.resultPk;
        if (!baselinePk) throw 'DKG resultPk absent despite epoch advance';
        if (baselinePk.scheme !== ace.vss.SCHEME_BLS12381G2) {
            throw `expected DKG resultPk scheme=${ace.vss.SCHEME_BLS12381G2}, got ${baselinePk.scheme}`;
        }
        log(`Baseline G2 PK: ${baselinePk.toHex()}`);

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

        // ── Epoch 2→3: new_secret proposal (DKR reshare + DKG for new secret) ─

        log('Propose new_secret(scheme=1) again in epoch 2.');
        await proposeAndApprove(
            approvers[0]!,
            approvers,
            aceContract,
            serializeNewSecretProposal(1),
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

        // secrets[0]: reshared original G2 secret. PK must be preserved across two DKR hops.
        const resharedAddr = finalState.secrets[0]!.currentSession;
        const resharedSession = (await getDKRSession(adminAccount.accountAddress, resharedAddr))
            .unwrapOrThrow('Failed to read reshared DKR session.');
        if (resharedSession.publicBaseElement.scheme !== ace.vss.SCHEME_BLS12381G2) {
            throw `reshared session publicBaseElement scheme expected G2, got ${resharedSession.publicBaseElement.scheme}`;
        }
        if (resharedSession.secretlyScaledElement.toHex() !== baselinePk.toHex()) {
            throw `PK mismatch on reshared secret.\n  baseline: ${baselinePk.toHex()}\n  got:      ${resharedSession.secretlyScaledElement.toHex()}`;
        }

        // secrets[1]: freshly created DKG-G2 secret.
        const newDkgAddr = finalState.secrets[1]!.currentSession;
        const newDkgSession = (await getDKGSession(adminAccount.accountAddress, newDkgAddr))
            .unwrapOrThrow('Failed to read new DKG session.');
        if (newDkgSession.basePoint.scheme !== ace.vss.SCHEME_BLS12381G2) {
            throw `new DKG basePoint scheme expected G2, got ${newDkgSession.basePoint.scheme}`;
        }
        if (!newDkgSession.resultPk) throw 'New DKG resultPk absent';
        if (newDkgSession.resultPk.scheme !== ace.vss.SCHEME_BLS12381G2) {
            throw `new DKG resultPk scheme expected G2, got ${newDkgSession.resultPk.scheme}`;
        }

        log(`Network test (shortsig) passed.`);
        log(`  reshared G2 PK:  ${resharedSession.secretlyScaledElement.toHex()}`);
        log(`  new DKG G2 PK:   ${newDkgSession.resultPk.toHex()}`);
    } finally {
        for (const proc of nodeProcs) proc.kill();
        localnetProc.kill();
    }
}

main();
