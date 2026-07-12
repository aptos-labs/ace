// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * DKR (re-sharing) protocol e2e — default group: BLS12-381 G2 (scheme = 1).
 *
 * Exercises the full DKG → DKR re-sharing flow with the G2 group scheme. For
 * G1 regression coverage see test-dkr-protocol-g1.ts.
 */

import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import * as ace from '@aptos-labs/ace-sdk';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import * as path from 'path';
import { startLocalnet, fundAccount, log, deployContracts, submitTxn, sleep, getDKGSession, getDKRSession } from './common/helpers';
import { spawnDKGRun } from './common/dkg-clients';
import { buildRustWorkspace, spawnDKRSrcRun, spawnDKRDstRun } from './common/dkr-clients';
import { makeNodeMsgEndpoints } from './common/vss-protocol-setup';
import { readVSSHolderShareFromStore } from './common/vss/store-checks';

async function main() {
    const localnetProc = await startLocalnet();
    const tmpRoot = mkdtempSync(path.join(tmpdir(), 'ace-dkr-'));
    try {
        // 1 admin + 5 workers: A=0, B=1, C=2, D=3, E=4
        // Old committee: [A, B, C] with old_threshold=2
        // New committee: [B, C, D, E] with new_threshold=3
        const numWorkers = 5;
        const accounts: Account[] = Array.from({ length: numWorkers + 1 }, () => Account.generate());
        const encKeypairs = await Promise.all(Array.from({ length: numWorkers }, () => ace.pke.keygen()));
        const sigKeypairs = await Promise.all(Array.from({ length: numWorkers }, () => ace.sig.keygen()));
        for (const account of accounts) {
            await fundAccount(account.accountAddress);
        }

        const adminAccount = accounts[numWorkers];
        const workerAccounts = accounts.slice(0, numWorkers);

        const oldCommittee = workerAccounts.slice(0, 3);
        const oldThreshold = 2;
        const newCommittee = workerAccounts.slice(1, 5);
        const newThreshold = 3;
        const newCommitteeWorkerIndices = [1, 2, 3, 4];
        const storeUrls = workerAccounts.map((_, i) => `sqlite://${path.join(tmpRoot, `node-${i}.db`)}`);

        log('Deploy contracts.');
        await deployContracts(adminAccount, ['pke', 'sig', 'worker_config', 'group', 'secret-usage', 'fiat-shamir-transform', 'sigma-dlog-linear', 'pedersen-polynomial-commitment', 'vss', 'dkg', 'dkr']);

        log('Register workers.');
        const nodeMsgEndpoints = makeNodeMsgEndpoints(numWorkers);
        for (let i = 0; i < numWorkers; i++) {
            (await submitTxn({
                signer: workerAccounts[i],
                entryFunction: `${adminAccount.accountAddress}::worker_config::register_pke_enc_key`,
                args: [encKeypairs[i].encryptionKey.toBytes()],
            })).unwrapOrThrow('Failed to register worker.').asSuccessOrThrow();

            (await submitTxn({
                signer: workerAccounts[i],
                entryFunction: `${adminAccount.accountAddress}::worker_config::register_sig_verification_key`,
                args: [sigKeypairs[i].publicKey.toBytes()],
            })).unwrapOrThrow('Failed to register worker sig key.').asSuccessOrThrow();

            (await submitTxn({
                signer: workerAccounts[i],
                entryFunction: `${adminAccount.accountAddress}::worker_config::register_node_msg_endpoint`,
                args: [nodeMsgEndpoints.registeredUrls[i]],
            })).unwrapOrThrow('Failed to register worker node-msg endpoint.').asSuccessOrThrow();
        }

        // ── DKG Phase ───────────────────────────────────────────────────────────────

        log('Start DKG session over G2 (old committee [A,B,C], threshold=2).');
        const dkgMaybeCommittedTxn = await submitTxn({
            signer: adminAccount,
            entryFunction: `${adminAccount.accountAddress}::dkg::new_session_entry`,
            awaitEventType: `${adminAccount.accountAddress.toStringLong()}::dkg::SessionCreated`,
            args: [
                oldCommittee.map(w => w.accountAddress),
                oldThreshold,
                ace.vss.SCHEME_BLS12381G2,
                ace.network.USAGE_BLS12381_G2_TEST_ONLY,
                '',
            ],
        });
        const dkgCommittedTxn = dkgMaybeCommittedTxn.unwrapOrThrow('Failed to get committed DKG transaction.').asSuccessOrThrow();
        const aceContract = adminAccount.accountAddress.toStringLong();
        const dkgSessionAddrStr = dkgCommittedTxn.findEvent(`${aceContract}::dkg::SessionCreated`)?.data.session_addr;
        if (!dkgSessionAddrStr) throw 'Failed to get DKG session address.';
        const dkgSessionAddr = AccountAddress.fromString(dkgSessionAddrStr);

        log('Start DKG worker clients (one per old-committee member).');
        await buildRustWorkspace();
        const dkgProcs = oldCommittee.map((w, i) => spawnDKGRun({
            runAs: w,
            pkeDkHex: `0x${Buffer.from(encKeypairs[i].decryptionKey.toBytes()).toString('hex')}`,
            sigSkHex: sigKeypairs[i].signingKey.toHex(),
            vssStoreUrl: storeUrls[i],
            nodeMsgListen: nodeMsgEndpoints.listens[i],
            dkgSessionAddr,
            aceDeploymentAddr: aceContract,
        }));

        let dkgResultPk: ace.vss.PublicPoint | undefined;
        try {
            log('Wait for DKG session to complete.');
            const dkgDeadlineMillis = Date.now() + 120_000;
            let dkgSession: ace.dkg.Session | undefined;
            while (Date.now() < dkgDeadlineMillis) {
                const maybeSession = await getDKGSession(adminAccount.accountAddress, dkgSessionAddr);
                if (maybeSession.isOk) {
                    dkgSession = maybeSession.okValue!;
                    if (dkgSession.isCompleted()) break;
                }
                await sleep(5_000);
            }
            if (!dkgSession?.isCompleted()) throw 'DKG session did not complete in time.';
            if (dkgSession.scheme !== ace.vss.SCHEME_BLS12381G2) {
                throw `expected DKG scheme = ${ace.vss.SCHEME_BLS12381G2}, got ${dkgSession.scheme}`;
            }
            dkgResultPk = dkgSession.resultPk;
            if (dkgResultPk === undefined) throw 'DKG result PK is missing.';
            log(`DKG complete (G2). aggregate C0: ${dkgSession.commitmentPoints[0].toHex()}`);
        } finally {
            for (const proc of dkgProcs) proc.kill();
        }

        // ── DKR Phase ───────────────────────────────────────────────────────────────

        log('Start DKR session (new committee [B,C,D,E], threshold=3).');
        const dkrMaybeCommittedTxn = await submitTxn({
            signer: adminAccount,
            entryFunction: `${aceContract}::dkr::new_session_entry`,
            awaitEventType: `${aceContract}::dkr::SessionCreated`,
            args: [
                dkgSessionAddr,
                newCommittee.map(w => w.accountAddress),
                newThreshold,
            ],
        });
        const dkrCommittedTxn = dkrMaybeCommittedTxn.unwrapOrThrow('Failed to get committed DKR transaction.').asSuccessOrThrow();
        const dkrSessionAddrStr = dkrCommittedTxn.findEvent(`${aceContract}::dkr::SessionCreated`)?.data.session_addr;
        if (!dkrSessionAddrStr) throw 'Failed to get DKR session address.';
        const dkrSessionAddr = AccountAddress.fromString(dkrSessionAddrStr);

        log('Start DKR client processes (3 dkr-src for old committee, 4 dkr-dst for new committee).');
        const dkrSrcProcs = oldCommittee.map((w, i) => spawnDKRSrcRun({
            runAs: w,
            pkeDkHex: `0x${Buffer.from(encKeypairs[i].decryptionKey.toBytes()).toString('hex')}`,
            sigSkHex: sigKeypairs[i].signingKey.toHex(),
            vssStoreUrl: storeUrls[i],
            nodeMsgListen: nodeMsgEndpoints.listens[i],
            dkrSessionAddr,
            aceDeploymentAddr: aceContract,
        }));
        const dkrDstProcs = newCommittee.map((w, m) => spawnDKRDstRun({
            runAs: w,
            pkeDkHex: `0x${Buffer.from(encKeypairs[newCommitteeWorkerIndices[m]].decryptionKey.toBytes()).toString('hex')}`,
            sigSkHex: sigKeypairs[newCommitteeWorkerIndices[m]].signingKey.toHex(),
            vssStoreUrl: storeUrls[newCommitteeWorkerIndices[m]],
            dkrSessionAddr,
            aceDeploymentAddr: aceContract,
        }));
        const allDkrProcs = [...dkrSrcProcs, ...dkrDstProcs];

        try {
            log('Wait for DKR session to complete.');
            const dkrDeadlineMillis = Date.now() + 120_000;
            let dkrSession: ace.dkr.Session | undefined;
            while (Date.now() < dkrDeadlineMillis) {
                const maybeSession = await getDKRSession(adminAccount.accountAddress, dkrSessionAddr);
                if (maybeSession.isOk) {
                    dkrSession = maybeSession.okValue!;
                    if (dkrSession.isCompleted()) break;
                }
                await sleep(5_000);
            }
            if (!dkrSession?.isCompleted()) throw 'DKR session did not complete in time.';
            if (dkrSession.pcsContext.generatorG.scheme !== ace.vss.SCHEME_BLS12381G2) {
                throw `expected DKR PCS generator G scheme = ${ace.vss.SCHEME_BLS12381G2}, got ${dkrSession.pcsContext.generatorG.scheme}`;
            }
            if (dkrSession.commitmentPoints.length !== newCommittee.length + 1) {
                throw `expected ${newCommittee.length + 1} DKR commitment points, got ${dkrSession.commitmentPoints.length}`;
            }
            if (dkrSession.publicKeys.length !== newCommittee.length + 1) {
                throw `expected ${newCommittee.length + 1} DKR public keys, got ${dkrSession.publicKeys.length}`;
            }
            if (!dkrSession.resultPk.equals(dkgResultPk!)) {
                throw 'DKR changed the result public key.';
            }
            log(`DKR complete (G2). aggregate C0: ${dkrSession.commitmentPoints[0].toHex()}`);

            log('Fetch contributing DKR holder DB shares and verify correctness.');
            const contributingIndices: number[] = dkrSession.vssContributionFlags
                .map((flag, j) => (flag ? j : -1))
                .filter(j => j >= 0);
            log(`Contributing old-committee indices: ${contributingIndices}`);
            if (contributingIndices.length < oldThreshold) {
                throw `Not enough contributing VSS sessions: got ${contributingIndices.length}, need ${oldThreshold}`;
            }

            const subOpenings: ace.pedersenPolynomialCommitment.Opening[][] = [];
            for (const j of contributingIndices) {
                const openingsForVss: ace.pedersenPolynomialCommitment.Opening[] = [];
                for (let m = 0; m < newCommittee.length; m++) {
                    const newMemberWorkerIdx = newCommitteeWorkerIndices[m];
                    const msgBytes = readVSSHolderShareFromStore({
                        vssStoreUrl: storeUrls[newMemberWorkerIdx],
                        sessionAddr: dkrSession.vssSessions[j],
                        holderIndex: m,
                    });
                    const msg = ace.vss.PrivateShareMessage.fromBytes(msgBytes)
                        .unwrapOrThrow(`Failed to parse holder DB share (vss=${j}, new_member=${m}).`);
                    openingsForVss.push(msg.opening);
                }
                subOpenings.push(openingsForVss);
            }

            const dkrCombinedOpenings: ace.pedersenPolynomialCommitment.Opening[] = newCommittee.map((_, m) => {
                const evalValueP = ace.vss.reconstructScalars({
                    indexedScalars: contributingIndices.map((j, vi) => ({
                        index: j + 1,
                        scalar: subOpenings[vi][m].evalValueP,
                    })),
                }).unwrapOrThrow(`Failed to Lagrange-combine DKR sub-shares for new member ${m}.`);
                const evalValueR = ace.vss.reconstructScalars({
                    indexedScalars: contributingIndices.map((j, vi) => ({
                        index: j + 1,
                        scalar: subOpenings[vi][m].evalValueR,
                    })),
                }).unwrapOrThrow(`Failed to Lagrange-combine DKR sub-blindings for new member ${m}.`);
                return new ace.pedersenPolynomialCommitment.Opening(m + 1, evalValueP, evalValueR);
            });

            for (let m = 0; m < newCommittee.length; m++) {
                const expected = dkrSession.commitmentPoints[m + 1];
                const actual = dkrSession.pcsContext.generatorG
                    .scale(dkrCombinedOpenings[m].evalValueP)
                    .add(dkrSession.pcsContext.generatorH.scale(dkrCombinedOpenings[m].evalValueR));
                if (!actual.equals(expected)) {
                    throw `DKR aggregate holder commitment mismatch at new member ${m}`;
                }
                const expectedSharePk = dkrSession.basePoint.scale(dkrCombinedOpenings[m].evalValueP);
                if (!expectedSharePk.equals(dkrSession.sharePks[m])) {
                    throw `DKR aggregate holder public key mismatch at new member ${m}`;
                }
            }

            const reconstructedSecret = ace.vss.reconstructScalars({
                indexedScalars: dkrCombinedOpenings.slice(0, newThreshold).map(opening => ({
                    index: opening.evalPosition,
                    scalar: opening.evalValueP,
                })),
            }).unwrapOrThrow('Failed to reconstruct combined secret from DKR shares.');
            if (reconstructedSecret.scheme !== ace.vss.SCHEME_BLS12381G2) {
                throw `expected reconstructed scheme = ${ace.vss.SCHEME_BLS12381G2}, got ${reconstructedSecret.scheme}`;
            }
            const reconstructedBlinding = ace.vss.reconstructScalars({
                indexedScalars: dkrCombinedOpenings.slice(0, newThreshold).map(opening => ({
                    index: opening.evalPosition,
                    scalar: opening.evalValueR,
                })),
            }).unwrapOrThrow('Failed to reconstruct combined blinding from DKR shares.');

            const computedC0 = dkrSession.pcsContext.generatorG
                .scale(reconstructedSecret)
                .add(dkrSession.pcsContext.generatorH.scale(reconstructedBlinding));
            if (!computedC0.equals(dkrSession.commitmentPoints[0])) {
                throw 'Reconstructed secret/blinding does not match DKR aggregate C0 (G2).';
            }
            if (!dkrSession.basePoint.scale(reconstructedSecret).equals(dkrSession.resultPk)) {
                throw 'Reconstructed secret does not match DKR result PK (G2).';
            }

            log(`DKR correctness verified (G2). aggregate C0: ${dkrSession.commitmentPoints[0].toHex()}`);
        } finally {
            for (const proc of allDkrProcs) proc.kill();
        }
    } finally {
        localnetProc.kill();
        rmSync(tmpRoot, { recursive: true, force: true });
    }
}

main();
