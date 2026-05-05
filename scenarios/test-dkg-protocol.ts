// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import * as ace from '@aptos-labs/ace-sdk';
import { startLocalnet, fundAccount, log, deployContracts, submitTxn, sleep, getDKGSession, getVssSession } from './common/helpers';
import { buildRustWorkspace, spawnDKGRun } from './common/dkg-clients';

async function main() {
    const localnetProc = await startLocalnet();
    try {
        // 1 admin account and 4 worker accounts.
        const numWorkers = 4;
        const accounts: Account[] = Array.from({ length: numWorkers + 1 }, () => Account.generate());
        const encKeypairs = await Promise.all(Array.from({ length: numWorkers }, () => ace.pke.keygen()));
        for (const account of accounts) {
            await fundAccount(account.accountAddress);
        }

        const adminAccount = accounts[numWorkers];
        const workerAccounts = accounts.slice(0, numWorkers);

        log('Deploy contracts.');
        await deployContracts(adminAccount, ['pke', 'worker_config', 'group', 'fiat-shamir-transform', 'sigma-dlog-eq', 'vss', 'dkg']);

        log('Register workers.');
        for (let i = 0; i < numWorkers; i++) {
            (await submitTxn({
                signer: accounts[i],
                entryFunction: `${adminAccount.accountAddress}::worker_config::register_pke_enc_key`,
                args: [encKeypairs[i].encryptionKey.toBytes()],
            })).unwrapOrThrow('Failed to register worker.').asSuccessOrThrow();
        }

        // Build base_point bytes: G1 generator as [u8 scheme][uleb128(48)][48B].
        const g1Inner = ace.group.bls12381G1.g1Generator();
        const basePointBytes = ace.group.Element.fromBls12381G1(g1Inner).toBytes();

        log('Start DKG session.');
        const maybeCommittedTxn = await submitTxn({
            signer: adminAccount,
            entryFunction: `${adminAccount.accountAddress}::dkg::new_session_entry`,
            args: [
                workerAccounts.map(w => w.accountAddress),
                3, // threshold
                basePointBytes,
            ],
        });
        const committedTxn = maybeCommittedTxn.unwrapOrThrow('Failed to get committed transaction.').asSuccessOrThrow();
        const aceContract = adminAccount.accountAddress.toStringLong();
        const sessionAddrStr = committedTxn.events.find(e => e.type === `${aceContract}::dkg::SessionCreated`)?.data.session_addr;
        if (!sessionAddrStr) throw 'Failed to get DKG session address.';
        const sessionAddr = AccountAddress.fromString(sessionAddrStr);

        log('Start DKG worker clients.');
        await buildRustWorkspace();
        const dkgProcs = workerAccounts.map((w, i) => spawnDKGRun({
            runAs: w,
            pkeDkHex: `0x${Buffer.from(encKeypairs[i].decryptionKey.toBytes()).toString('hex')}`,
            dkgSessionAddr: sessionAddr,
            aceDeploymentAddr: aceContract,
        }));

        try {
            log('Wait for DKG session to complete.');
            const deadlineMillis = Date.now() + 120_000;
            let session: ace.dkg.Session | undefined;
            while (Date.now() < deadlineMillis) {
                const maybeSession = await getDKGSession(adminAccount.accountAddress, sessionAddr);
                if (maybeSession.isOk) {
                    session = maybeSession.okValue!;
                    if (session.isCompleted()) break;
                }
                await sleep(5_000);
            }
            if (!session?.isCompleted()) throw 'DKG session did not complete in time.';

            if (!session.resultPk) throw 'DKG session completed but resultPk is missing.';
            log(`DKG complete. resultPk: ${session.resultPk.toHex()}`);

            log('Fetch contributing VSS sessions and reconstruct combined secret.');

            // Which VSS sessions contributed to the result.
            const contributingIndices = session.doneFlags
                .map((done, i) => (done ? i : -1))
                .filter(i => i >= 0);

            // For each contributing VSS session, decrypt every worker's sub-share.
            // subShares[vi][j] = SecretShare from dealer contributingIndices[vi] for worker j.
            const subShares: ace.vss.SecretShare[][] = [];
            for (const i of contributingIndices) {
                const vssSession = (await getVssSession(adminAccount.accountAddress, session.vssSessions[i]))
                    .unwrapOrThrow(`Failed to fetch VSS session ${i}.`);
                const sharesForVss: ace.vss.SecretShare[] = [];
                for (let j = 0; j < numWorkers; j++) {
                    const msgBytes = (await ace.pke.decrypt({
                        decryptionKey: encKeypairs[j].decryptionKey,
                        ciphertext: vssSession.dealerContribution0!.privateShareMessages[j],
                    })).unwrapOrThrow(`Failed to decrypt sub-share (vss=${i}, worker=${j}).`);
                    const msg = ace.vss.PrivateShareMessage.fromBytes(msgBytes)
                        .unwrapOrThrow(`Failed to parse PrivateShareMessage (vss=${i}, worker=${j}).`);
                    sharesForVss.push(msg.share);
                }
                subShares.push(sharesForVss);
            }

            // Combine sub-shares per worker using SecretShare.add (Fr arithmetic).
            const combinedShares: ace.vss.SecretShare[] = workerAccounts.map((_, j) =>
                subShares.slice(1).reduce((acc, sharesForVss) => acc.add(sharesForVss[j]), subShares[0][j])
            );

            // Reconstruct the combined secret from the first `threshold` combined shares.
            const reconstructedSecret = ace.vss.reconstruct({
                indexedShares: combinedShares.slice(0, session.threshold).map((share, j) => ({ index: j + 1, share })),
            }).unwrapOrThrow('Failed to reconstruct combined secret.');

            // Verify s * B == resultPk.
            const computedPk = session.basePoint.scale(reconstructedSecret);
            if (!computedPk.equals(session.resultPk)) throw 'Reconstructed secret does not match DKG result PK.';
            log(`DKG correctness verified. resultPk: ${session.resultPk.toHex()}`);
        } finally {
            for (const proc of dkgProcs) {
                proc.kill();
                //TODO: save logs to file and print the path.
            }
        }

    } finally {
        localnetProc.kill();
    }
}

main();
