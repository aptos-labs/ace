// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

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

        // old committee = [A, B, C] = workers[0..2], threshold=2
        const oldCommittee = workerAccounts.slice(0, 3);
        const oldThreshold = 2;

        // new committee = [B, C, D, E] = workers[1..4], threshold=3
        const newCommittee = workerAccounts.slice(1, 5);
        const newThreshold = 3;

        // Enc keypair index for new committee member m (0-based in newCommittee):
        // B=workers[1]->encKeypairs[1], C=workers[2]->encKeypairs[2],
        // D=workers[3]->encKeypairs[3], E=workers[4]->encKeypairs[4]
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

        // Build base_point bytes: G1 generator as [u8 scheme][uleb128(48)][48B].
        const g1Inner = ace.group.bls12381G1.g1Generator();
        const basePointBytes = ace.group.Element.fromBls12381G1(g1Inner).toBytes();

        // ── DKG Phase ───────────────────────────────────────────────────────────────

        log('Start DKG session (old committee [A,B,C], threshold=2).');
        const dkgMaybeCommittedTxn = await submitTxn({
            signer: adminAccount,
            entryFunction: `${adminAccount.accountAddress}::dkg::new_session_entry`,
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
            log('Wait for DKG session to complete (workers call touch_entry internally).');
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
            log(`DKG complete. resultPk: ${dkgSession.resultPk?.toHex()}`);
        } finally {
            for (const proc of dkgProcs) proc.kill();
        }

        // ── DKR Phase ───────────────────────────────────────────────────────────────

        log('Start DKR session (new committee [B,C,D,E], threshold=3).');
        const dkrMaybeCommittedTxn = await submitTxn({
            signer: adminAccount,
            entryFunction: `${aceContract}::dkr::new_session_entry`,
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
        // dkr-src: one per old-committee member (A=0, B=1, C=2)
        const dkrSrcProcs = oldCommittee.map((w, i) => spawnDKRSrcRun({
            runAs: w,
            pkeDkHex: `0x${Buffer.from(encKeypairs[i].decryptionKey.toBytes()).toString('hex')}`,
            dkrSessionAddr,
            aceDeploymentAddr: aceContract,
        }));

        // dkr-dst: one per new-committee member (B=1, C=2, D=3, E=4 in workerAccounts)
        const dkrDstProcs = newCommittee.map((w, m) => spawnDKRDstRun({
            runAs: w,
            pkeDkHex: `0x${Buffer.from(encKeypairs[newCommitteeEncKeypairIndices[m]].decryptionKey.toBytes()).toString('hex')}`,
            dkrSessionAddr,
            aceDeploymentAddr: aceContract,
        }));

        const allDkrProcs = [...dkrSrcProcs, ...dkrDstProcs];

        try {
            log('Wait for DKR session to complete (clients call touch_entry internally).');
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

            log(`DKR complete. secretlyScaledElement: ${dkrSession.secretlyScaledElement.toHex()}`);

            // ── Correctness check ──────────────────────────────────────────────────────
            // Per https://alinush.github.io/2024/04/26/How-to-reshare-a-secret.html:
            //
            // Old committee [A,B,C] with eval points A→1, B→2, C→3.
            // New committee [B,C,D,E] with eval points B→1, C→2, D→3, E→4.
            //
            // Contributing set H = {j : vssContributionFlags[j]} (indices into old committee).
            // For each j ∈ H, VSS session j has dealer=oldCommittee[j] and recipients=newCommittee.
            //
            // Step 1: For each new committee member m, Lagrange-combine the sub-shares
            //         z_{j,m} = r_j(m+1) at x=0 using OLD eval points {j+1 : j ∈ H}:
            //           dkrCombinedShare[m] = Σ_{j ∈ H} L_{j+1}^{H}(0) * z_{j,m}
            //         This equals f(m+1) — new committee member m's share of the original secret.
            //
            // Step 2: Reconstruct the secret from newThreshold combined shares:
            //           s = Lagrange({(1, dkrCombinedShare[0]), ..., (newThreshold, dkrCombinedShare[newThreshold-1])}, x=0)
            //
            // Step 3: Assert s * publicBaseElement == secretlyScaledElement (PK unchanged).

            log('Fetch contributing DKR VSS sessions and verify correctness.');

            const contributingIndices: number[] = dkrSession.vssContributionFlags
                .map((flag, j) => (flag ? j : -1))
                .filter(j => j >= 0);

            log(`Contributing old-committee indices: ${contributingIndices}`);
            if (contributingIndices.length < oldThreshold) {
                throw `Not enough contributing VSS sessions: got ${contributingIndices.length}, need ${oldThreshold}`;
            }

            // For each contributing old-committee member j, fetch their VSS session and
            // decrypt each new committee member m's sub-share.
            // subShares[vi][m] = z_{j,m} for j = contributingIndices[vi], m = 0..newCommittee.length-1
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

            // Step 1: For each new committee member m, Lagrange-combine sub-shares at x=0
            //         using OLD evaluation points {j+1 : j ∈ H}.
            //
            // reconstruct() returns a Scalar; to feed it into the outer reconstruct() we
            // convert: Scalar → PrivateScalar → Bls12381Fr.SecretShare → vss.SecretShare.
            const dkrCombinedShares: ace.vss.SecretShare[] = newCommittee.map((_, m) => {
                const combinedScalar = ace.vss.reconstruct({
                    indexedShares: contributingIndices.map((j, vi) => ({
                        index: j + 1,            // old eval point for old member j
                        share: subShares[vi][m], // z_{j,m}
                    })),
                }).unwrapOrThrow(`Failed to Lagrange-combine DKR sub-shares for new member ${m}.`);
                // Convert group.Scalar → vss.SecretShare for the outer reconstruction step.
                const ps = combinedScalar.asBls12381G1();
                const bls12381Share = new ace.group.bls12381G1.SecretShare(ps.scalar);
                return new ace.vss.SecretShare(ace.vss.SCHEME_BLS12381G1, bls12381Share);
            });

            // Step 2: Reconstruct the secret from newThreshold combined DKR shares
            //         using NEW evaluation points {m+1 : m = 0..newThreshold-1}.
            const reconstructedSecret = ace.vss.reconstruct({
                indexedShares: dkrCombinedShares.slice(0, newThreshold).map((share, m) => ({
                    index: m + 1,  // new eval point for new member m
                    share,
                })),
            }).unwrapOrThrow('Failed to reconstruct combined secret from DKR shares.');

            // Step 3: Verify s * publicBaseElement == secretlyScaledElement.
            const computedPk = dkrSession.publicBaseElement.scale(reconstructedSecret);
            if (!computedPk.equals(dkrSession.secretlyScaledElement)) {
                throw 'Reconstructed secret does not match DKR secretlyScaledElement (PK mismatch).';
            }

            log(`DKR correctness verified. secretlyScaledElement: ${dkrSession.secretlyScaledElement.toHex()}`);

        } finally {
            for (const proc of allDkrProcs) proc.kill();
        }

    } finally {
        localnetProc.kill();
    }
}

main();
