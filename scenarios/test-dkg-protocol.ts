// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * DKG protocol e2e — default group: BLS12-381 G2 (scheme = 1).
 *
 * Exercises the full DKG protocol with a G2 base point. For G1 regression
 * coverage see test-dkg-protocol-g1.ts.
 */

import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import * as ace from '@aptos-labs/ace-sdk';
import { mkdtempSync } from 'fs';
import { tmpdir } from 'os';
import * as path from 'path';
import { startLocalnet, fundAccount, log, deployContracts, submitTxn, sleep, getDKGSession } from './common/helpers';
import { buildRustWorkspace, spawnDKGRun } from './common/dkg-clients';
import { makeNodeMsgEndpoints } from './common/vss-protocol-setup';
import { readVSSHolderShareFromStore } from './common/vss/store-checks';

async function main() {
    const localnetProc = await startLocalnet();
    try {
        const numWorkers = 4;
        const accounts: Account[] = Array.from({ length: numWorkers + 1 }, () => Account.generate());
        const encKeypairs = await Promise.all(Array.from({ length: numWorkers }, () => ace.pke.keygen()));
        const sigKeypairs = await Promise.all(Array.from({ length: numWorkers }, () => ace.sig.keygen()));
        for (const account of accounts) {
            await fundAccount(account.accountAddress);
        }

        const adminAccount = accounts[numWorkers];
        const workerAccounts = accounts.slice(0, numWorkers);

        log('Deploy contracts.');
        await deployContracts(adminAccount, ['pke', 'sig', 'worker_config', 'group', 'secret-usage', 'fiat-shamir-transform', 'sigma-dlog-linear', 'pedersen-polynomial-commitment', 'vss', 'dkg']);

        log('Register workers.');
        const nodeMsgEndpoints = makeNodeMsgEndpoints(numWorkers);
        for (let i = 0; i < numWorkers; i++) {
            (await submitTxn({
                signer: accounts[i],
                entryFunction: `${adminAccount.accountAddress}::worker_config::register_pke_enc_key`,
                args: [encKeypairs[i].encryptionKey.toBytes()],
            })).unwrapOrThrow('Failed to register worker.').asSuccessOrThrow();

            (await submitTxn({
                signer: accounts[i],
                entryFunction: `${adminAccount.accountAddress}::worker_config::register_sig_verification_key`,
                args: [sigKeypairs[i].publicKey.toBytes()],
            })).unwrapOrThrow('Failed to register worker sig key.').asSuccessOrThrow();

            (await submitTxn({
                signer: accounts[i],
                entryFunction: `${adminAccount.accountAddress}::worker_config::register_node_msg_endpoint`,
                args: [nodeMsgEndpoints.nodeMsgUrls[i]],
            })).unwrapOrThrow('Failed to register worker node-msg endpoint.').asSuccessOrThrow();
        }

        log('Start DKG session over BLS12-381 G2.');
        const maybeCommittedTxn = await submitTxn({
            signer: adminAccount,
            entryFunction: `${adminAccount.accountAddress}::dkg::new_session_entry`,
            awaitEventType: `${adminAccount.accountAddress.toStringLong()}::dkg::SessionCreated`,
            args: [
                workerAccounts.map(w => w.accountAddress),
                3, // threshold
                ace.vss.SCHEME_BLS12381G2,
                ace.network.USAGE_BLS12381_G2_TEST_ONLY,
                '',
            ],
        });
        const committedTxn = maybeCommittedTxn.unwrapOrThrow('Failed to get committed transaction.').asSuccessOrThrow();
        const aceContract = adminAccount.accountAddress.toStringLong();
        const sessionAddrStr = committedTxn.findEvent(`${aceContract}::dkg::SessionCreated`)?.data.session_addr;
        if (!sessionAddrStr) throw 'Failed to get DKG session address.';
        const sessionAddr = AccountAddress.fromString(sessionAddrStr);

        log('Start DKG worker clients.');
        await buildRustWorkspace();
        const tmpRoot = mkdtempSync(path.join(tmpdir(), 'ace-dkg-'));
        const storeUrls = workerAccounts.map((_, i) => `sqlite://${path.join(tmpRoot, `node-${i}.db`)}`);
        const dkgProcs = workerAccounts.map((w, i) => spawnDKGRun({
            runAs: w,
            pkeDkHex: `0x${Buffer.from(encKeypairs[i].decryptionKey.toBytes()).toString('hex')}`,
            sigSkHex: sigKeypairs[i].signingKey.toHex(),
            vssStoreUrl: storeUrls[i],
            nodeMsgListen: nodeMsgEndpoints.nodeMsgListens[i],
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
            if (session.commitmentPoints.length !== numWorkers + 1) {
                throw `expected ${numWorkers + 1} aggregate commitment points, got ${session.commitmentPoints.length}`;
            }
            if (session.publicKeys.length !== numWorkers + 1) {
                throw `expected ${numWorkers + 1} aggregate public keys, got ${session.publicKeys.length}`;
            }

            log('Confirm session is over G2 (scheme = 1).');
            if (session.scheme !== ace.vss.SCHEME_BLS12381G2) {
                throw `expected DKG scheme = ${ace.vss.SCHEME_BLS12381G2}, got ${session.scheme}`;
            }
            if (session.pcsContext.generatorG.scheme !== ace.vss.SCHEME_BLS12381G2) {
                throw `expected PCS generator G scheme = ${ace.vss.SCHEME_BLS12381G2}, got ${session.pcsContext.generatorG.scheme}`;
            }
            log(`DKG complete (G2). aggregate C0: ${session.commitmentPoints[0].toHex()}`);

            log('Fetch holder DB shares and reconstruct combined secret.');
            const contributingIndices = session.doneFlags
                .map((done, i) => (done ? i : -1))
                .filter(i => i >= 0);

            const combinedOpenings: { p: ace.vss.PrivateScalar; r: ace.vss.PrivateScalar }[] = [];
            for (let j = 0; j < numWorkers; j++) {
                for (const i of contributingIndices) {
                    const msgBytes = readVSSHolderShareFromStore({
                        vssStoreUrl: storeUrls[j],
                        sessionAddr: session.vssSessions[i],
                        holderIndex: j,
                    });
                    const msg = ace.vss.PrivateShareMessage.fromBytes(msgBytes)
                        .unwrapOrThrow(`Failed to parse holder DB share (vss=${i}, worker=${j}).`);
                    if (combinedOpenings[j] === undefined) {
                        combinedOpenings[j] = {
                            p: msg.opening.evalValueP,
                            r: msg.opening.evalValueR,
                        };
                    } else {
                        combinedOpenings[j] = {
                            p: combinedOpenings[j].p.add(msg.opening.evalValueP),
                            r: combinedOpenings[j].r.add(msg.opening.evalValueR),
                        };
                    }
                }
            }

            for (let j = 0; j < numWorkers; j++) {
                const expected = session.commitmentPoints[j + 1];
                const actual = session.pcsContext.generatorG
                    .scale(combinedOpenings[j].p)
                    .add(session.pcsContext.generatorH.scale(combinedOpenings[j].r));
                if (!actual.equals(expected)) {
                    throw `aggregate holder commitment mismatch at worker ${j}`;
                }
                const expectedSharePk = session.basePoint.scale(combinedOpenings[j].p);
                if (!expectedSharePk.equals(session.sharePks[j])) {
                    throw `aggregate holder public key mismatch at worker ${j}`;
                }
            }

            const combinedShares: ace.vss.SecretShare[] = combinedOpenings.map(opening =>
                ace.vss.SecretShare.fromBytes(opening.p.toBytes()).unwrapOrThrow('failed to wrap DKG share scalar'),
            );
            const combinedBlindingShares: ace.vss.SecretShare[] = combinedOpenings.map(opening =>
                ace.vss.SecretShare.fromBytes(opening.r.toBytes()).unwrapOrThrow('failed to wrap DKG blinding scalar'),
            );

            const reconstructedSecret = ace.vss.reconstruct({
                indexedShares: combinedShares.slice(0, session.threshold).map((share, j) => ({ index: j + 1, share })),
            }).unwrapOrThrow('Failed to reconstruct combined secret.');
            if (reconstructedSecret.scheme !== ace.vss.SCHEME_BLS12381G2) {
                throw `expected reconstructed scheme = ${ace.vss.SCHEME_BLS12381G2}, got ${reconstructedSecret.scheme}`;
            }
            const reconstructedBlinding = ace.vss.reconstruct({
                indexedShares: combinedBlindingShares.slice(0, session.threshold).map((share, j) => ({ index: j + 1, share })),
            }).unwrapOrThrow('Failed to reconstruct combined blinding.');

            const computedC0 = session.pcsContext.generatorG
                .scale(reconstructedSecret)
                .add(session.pcsContext.generatorH.scale(reconstructedBlinding));
            if (!computedC0.equals(session.commitmentPoints[0])) {
                throw 'Reconstructed secret/blinding does not match DKG aggregate C0 (G2).';
            }
            if (!session.basePoint.scale(reconstructedSecret).equals(session.resultPk!)) {
                throw 'Reconstructed secret does not match DKG result PK (G2).';
            }
            log(`DKG correctness verified (G2). aggregate C0: ${session.commitmentPoints[0].toHex()}`);
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
