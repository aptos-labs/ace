// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * DKR (re-sharing) protocol e2e — default group: BLS12-381 G2 (scheme = 1).
 *
 * Exercises the full DKG → DKR re-sharing flow with a G2 base point, the project
 * default. For G1 regression coverage see test-dkr-protocol-g1.ts.
 */

import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import * as ace from '@aptos-labs/ace-sdk';
import { startLocalnet, fundAccount, log, deployContracts, submitTxn, sleep, getDKGSession, getVssSession, getDKRSession } from './common/helpers';
import { spawnDKGRun } from './common/dkg-clients';
import { buildRustWorkspace, spawnDKRSrcRun, spawnDKRDstRun } from './common/dkr-clients';

async function main() {
    const localnetProc = await startLocalnet();
    try {
        // 1 admin + 5 workers: A=0, B=1, C=2, D=3, E=4
        // Old committee: [A, B, C] with old_threshold=2
        // New committee: [B, C, D, E] with new_threshold=3
        const numWorkers = 5;
        const accounts: Account[] = Array.from({ length: numWorkers + 1 }, () => Account.generate());
        const encKeypairs = await Promise.all(Array.from({ length: numWorkers }, () => ace.pke.keygen()));
        for (const account of accounts) {
            await fundAccount(account.accountAddress);
        }

        const adminAccount = accounts[numWorkers];
        const workerAccounts = accounts.slice(0, numWorkers);

        const oldCommittee = workerAccounts.slice(0, 3);
        const oldThreshold = 2;
        const newCommittee = workerAccounts.slice(1, 5);
        const newThreshold = 3;
        const newCommitteeEncKeypairIndices = [1, 2, 3, 4];

        log('Deploy contracts.');
        await deployContracts(adminAccount, ['pke', 'worker_config', 'group', 'fiat-shamir-transform', 'sigma-dlog-eq', 'vss', 'dkg', 'dkr']);

        log('Register workers.');
        for (let i = 0; i < numWorkers; i++) {
            (await submitTxn({
                signer: workerAccounts[i],
                entryFunction: `${adminAccount.accountAddress}::worker_config::register_pke_enc_key`,
                args: [encKeypairs[i].encryptionKey.toBytes()],
            })).unwrapOrThrow('Failed to register worker.').asSuccessOrThrow();
        }

        // Build base_point bytes: G2 generator as [u8 scheme=0x01][uleb128(96)][96B].
        const g2Inner = ace.group.bls12381G2.g2Generator();
        const basePointBytes = ace.group.Element.fromBls12381G2(g2Inner).toBytes();

        // ── DKG Phase ───────────────────────────────────────────────────────────────

        log('Start DKG session over G2 (old committee [A,B,C], threshold=2).');
        const dkgMaybeCommittedTxn = await submitTxn({
            signer: adminAccount,
            entryFunction: `${adminAccount.accountAddress}::dkg::new_session_entry`,
            awaitEventType: `${adminAccount.accountAddress.toStringLong()}::dkg::SessionCreated`,
            args: [
                oldCommittee.map(w => w.accountAddress),
                oldThreshold,
                basePointBytes,
            ],
        });
        const dkgCommittedTxn = dkgMaybeCommittedTxn.unwrapOrThrow('Failed to get committed DKG transaction.').asSuccessOrThrow();
        const aceContract = adminAccount.accountAddress.toStringLong();
        const dkgSessionAddrStr = dkgCommittedTxn.events.find(e => e.type === `${aceContract}::dkg::SessionCreated`)?.data.session_addr;
        if (!dkgSessionAddrStr) throw 'Failed to get DKG session address.';
        const dkgSessionAddr = AccountAddress.fromString(dkgSessionAddrStr);

        log('Start DKG worker clients (one per old-committee member).');
        await buildRustWorkspace();
        const dkgProcs = oldCommittee.map((w, i) => spawnDKGRun({
            runAs: w,
            pkeDkHex: `0x${Buffer.from(encKeypairs[i].decryptionKey.toBytes()).toString('hex')}`,
            dkgSessionAddr,
            aceDeploymentAddr: aceContract,
        }));

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
            if (dkgSession.basePoint.scheme !== ace.vss.SCHEME_BLS12381G2) {
                throw `expected DKG base_point scheme = ${ace.vss.SCHEME_BLS12381G2}, got ${dkgSession.basePoint.scheme}`;
            }
            log(`DKG complete (G2). resultPk: ${dkgSession.resultPk?.toHex()}`);
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
        const dkrSessionAddrStr = dkrCommittedTxn.events.find(e => e.type === `${aceContract}::dkr::SessionCreated`)?.data.session_addr;
        if (!dkrSessionAddrStr) throw 'Failed to get DKR session address.';
        const dkrSessionAddr = AccountAddress.fromString(dkrSessionAddrStr);

        log('Start DKR client processes (3 dkr-src for old committee, 4 dkr-dst for new committee).');
        const dkrSrcProcs = oldCommittee.map((w, i) => spawnDKRSrcRun({
            runAs: w,
            pkeDkHex: `0x${Buffer.from(encKeypairs[i].decryptionKey.toBytes()).toString('hex')}`,
            dkrSessionAddr,
            aceDeploymentAddr: aceContract,
        }));
        const dkrDstProcs = newCommittee.map((w, m) => spawnDKRDstRun({
            runAs: w,
            pkeDkHex: `0x${Buffer.from(encKeypairs[newCommitteeEncKeypairIndices[m]].decryptionKey.toBytes()).toString('hex')}`,
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
            if (dkrSession.publicBaseElement.scheme !== ace.vss.SCHEME_BLS12381G2) {
                throw `expected DKR publicBaseElement scheme = ${ace.vss.SCHEME_BLS12381G2}, got ${dkrSession.publicBaseElement.scheme}`;
            }
            log(`DKR complete (G2). secretlyScaledElement: ${dkrSession.secretlyScaledElement.toHex()}`);

            log('Fetch contributing DKR VSS sessions and verify correctness.');
            const contributingIndices: number[] = dkrSession.vssContributionFlags
                .map((flag, j) => (flag ? j : -1))
                .filter(j => j >= 0);
            log(`Contributing old-committee indices: ${contributingIndices}`);
            if (contributingIndices.length < oldThreshold) {
                throw `Not enough contributing VSS sessions: got ${contributingIndices.length}, need ${oldThreshold}`;
            }

            const subShares: ace.vss.SecretShare[][] = [];
            for (const j of contributingIndices) {
                const vssSession = (await getVssSession(adminAccount.accountAddress, dkrSession.vssSessions[j]))
                    .unwrapOrThrow(`Failed to fetch DKR VSS session ${j}.`);
                const sharesForVss: ace.vss.SecretShare[] = [];
                for (let m = 0; m < newCommittee.length; m++) {
                    const newMemberEncKeypairIdx = newCommitteeEncKeypairIndices[m];
                    const msgBytes = (await ace.pke.decrypt({
                        decryptionKey: encKeypairs[newMemberEncKeypairIdx].decryptionKey,
                        ciphertext: vssSession.dealerContribution0!.privateShareMessages[m],
                    })).unwrapOrThrow(`Failed to decrypt sub-share (vss=${j}, new_member=${m}).`);
                    const msg = ace.vss.PrivateShareMessage.fromBytes(msgBytes)
                        .unwrapOrThrow(`Failed to parse PrivateShareMessage (vss=${j}, new_member=${m}).`);
                    sharesForVss.push(msg.share);
                }
                subShares.push(sharesForVss);
            }

            // Step 1: Per new member m, Lagrange-combine sub-shares at x=0 using OLD eval points {j+1 : j ∈ H}.
            const dkrCombinedShares: ace.vss.SecretShare[] = newCommittee.map((_, m) => {
                const combinedScalar = ace.vss.reconstruct({
                    indexedShares: contributingIndices.map((j, vi) => ({
                        index: j + 1,
                        share: subShares[vi][m],
                    })),
                }).unwrapOrThrow(`Failed to Lagrange-combine DKR sub-shares for new member ${m}.`);
                // Convert group.Scalar (G2) → vss.SecretShare for the outer reconstruction step.
                const ps = combinedScalar.asBls12381G2();
                const innerShare = new ace.group.bls12381G2.SecretShare(ps.scalar);
                return new ace.vss.SecretShare(ace.vss.SCHEME_BLS12381G2, innerShare);
            });

            // Step 2: Reconstruct the secret from newThreshold combined DKR shares using NEW eval points.
            const reconstructedSecret = ace.vss.reconstruct({
                indexedShares: dkrCombinedShares.slice(0, newThreshold).map((share, m) => ({
                    index: m + 1,
                    share,
                })),
            }).unwrapOrThrow('Failed to reconstruct combined secret from DKR shares.');
            if (reconstructedSecret.scheme !== ace.vss.SCHEME_BLS12381G2) {
                throw `expected reconstructed scheme = ${ace.vss.SCHEME_BLS12381G2}, got ${reconstructedSecret.scheme}`;
            }

            // Step 3: Verify s * publicBaseElement == secretlyScaledElement.
            const computedPk = dkrSession.publicBaseElement.scale(reconstructedSecret);
            if (!computedPk.equals(dkrSession.secretlyScaledElement)) {
                throw 'Reconstructed secret does not match DKR secretlyScaledElement (G2).';
            }

            log(`DKR correctness verified (G2). secretlyScaledElement: ${dkrSession.secretlyScaledElement.toHex()}`);
        } finally {
            for (const proc of allDkrProcs) proc.kill();
        }
    } finally {
        localnetProc.kill();
    }
}

main();
