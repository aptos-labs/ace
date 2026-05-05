// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * DKG protocol e2e — default group: BLS12-381 G2 (scheme = 1).
 *
 * Exercises the full DKG protocol with a G2 base point, which is the project default
 * (paired with the bfibe-bls12381-shortsig-aead t-IBE variant). For G1 regression
 * coverage see test-dkg-protocol-g1.ts.
 */

import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import * as ace from '@aptos-labs/ace-sdk';
import { startLocalnet, fundAccount, log, deployContracts, submitTxn, sleep, getDKGSession, getVssSession } from './common/helpers';
import { buildRustWorkspace, spawnDKGRun } from './common/dkg-clients';

async function main() {
    const localnetProc = await startLocalnet();
    try {
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

        // Build base_point bytes: G2 generator as [u8 scheme=0x01][uleb128(96)][96B].
        const g2Inner = ace.group.bls12381G2.g2Generator();
        const basePointBytes = ace.group.Element.fromBls12381G2(g2Inner).toBytes();

        log('Start DKG session over BLS12-381 G2.');
        const maybeCommittedTxn = await submitTxn({
            signer: adminAccount,
            entryFunction: `${adminAccount.accountAddress}::dkg::new_session_entry`,
            awaitEventType: `${adminAccount.accountAddress.toStringLong()}::dkg::SessionCreated`,
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

            log('Confirm session is over G2 (scheme = 1).');
            if (session.basePoint.scheme !== ace.vss.SCHEME_BLS12381G2) {
                throw `expected base_point scheme = ${ace.vss.SCHEME_BLS12381G2}, got ${session.basePoint.scheme}`;
            }
            if (session.resultPk.scheme !== ace.vss.SCHEME_BLS12381G2) {
                throw `expected resultPk scheme = ${ace.vss.SCHEME_BLS12381G2}, got ${session.resultPk.scheme}`;
            }
            log(`DKG complete (G2). resultPk: ${session.resultPk.toHex()}`);

            log('Fetch contributing VSS sessions and reconstruct combined secret.');
            const contributingIndices = session.doneFlags
                .map((done, i) => (done ? i : -1))
                .filter(i => i >= 0);

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

            const combinedShares: ace.vss.SecretShare[] = workerAccounts.map((_, j) =>
                subShares.slice(1).reduce((acc, sharesForVss) => acc.add(sharesForVss[j]), subShares[0][j])
            );

            const reconstructedSecret = ace.vss.reconstruct({
                indexedShares: combinedShares.slice(0, session.threshold).map((share, j) => ({ index: j + 1, share })),
            }).unwrapOrThrow('Failed to reconstruct combined secret.');
            if (reconstructedSecret.scheme !== ace.vss.SCHEME_BLS12381G2) {
                throw `expected reconstructed scheme = ${ace.vss.SCHEME_BLS12381G2}, got ${reconstructedSecret.scheme}`;
            }

            const computedPk = session.basePoint.scale(reconstructedSecret);
            if (!computedPk.equals(session.resultPk)) throw 'Reconstructed secret does not match DKG result PK (G2).';
            log(`DKG correctness verified (G2). resultPk: ${session.resultPk.toHex()}`);
        } finally {
            for (const proc of dkgProcs) {
                proc.kill();
            }
        }
    } finally {
        localnetProc.kill();
    }
}

main();
