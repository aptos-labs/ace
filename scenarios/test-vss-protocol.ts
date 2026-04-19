// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import * as ace from '@aptos-labs/ace-sdk';
import { startLocalnet, fundAccount, log, deployContracts, submitTxn, sleep, getVssSession } from './common/helpers';
import {
    buildRustWorkspace,
    spawnVSSDealerRun,
    spawnVSSRecipientRun,
} from './common/vss-clients';

async function main() {
    const localnetProc = await startLocalnet();
    try {
        // 1 admin account and 4 worker accounts.
        const numWorkers = 4;
        const accounts: Account[] = Array.from({ length: numWorkers + 1 }, () => Account.generate());
        const encKeypairs = Array.from({ length: numWorkers }, () => ace.pke.keygen());
        for (const account of accounts) {
            await fundAccount(account.accountAddress);
        }

        const adminAccount = accounts[numWorkers];
        const dealerAccount = accounts[0];
        const recipientAccounts = accounts.slice(0, numWorkers);

        log('Deploy contracts.');
        await deployContracts(adminAccount, ['pke', 'worker_config', 'group', 'vss']);

        log('Register workers.');
        for (let i = 0; i < numWorkers; i++) {
            const maybeCommittedTxn = await submitTxn({
                signer: accounts[i],
                entryFunction: `${adminAccount.accountAddress}::worker_config::register_pke_enc_key`,
                args: [encKeypairs[i].encryptionKey.toBytes()],
            });
            maybeCommittedTxn.unwrapOrThrow('Failed to get committed transaction.').asSuccessOrThrow();
        }
        
        // Build base_point bytes: G1 generator as [u8 scheme][uleb128(48)][48B].
        const g1Inner = ace.group.bls12381G1.g1Generator();
        const basePointBytes = ace.group.Element.fromBls12381G1(g1Inner).toBytes();

        log('Start VSS session.');
        const maybeCommittedTxn = await submitTxn({
            signer: adminAccount,
            entryFunction: `${adminAccount.accountAddress}::vss::new_session_entry`,
            args: [
                dealerAccount.accountAddress,
                recipientAccounts.map(w => w.accountAddress),
                3, // threshold
                basePointBytes, // base_point: vector<u8>
            ],
        });
        const committedTxn = maybeCommittedTxn.unwrapOrThrow('Failed to get committed transaction.').asSuccessOrThrow();
        const aceContract = adminAccount.accountAddress.toStringLong();
        const sessionAddrStr = committedTxn.events.find(e => e.type === `${aceContract}::vss::SessionCreated`)?.data.session_addr;
        if (!sessionAddrStr) throw 'Failed to get session address.';
        const sessionAddr = AccountAddress.fromString(sessionAddrStr);

        log('Start dealer and recipient clients.');
        await buildRustWorkspace();
        const dealerProc = spawnVSSDealerRun({
            runAs: dealerAccount,
            pkeDkHex: `0x${Buffer.from(encKeypairs[0].decryptionKey.toBytes()).toString('hex')}`,
            sessionAddr,
            aceContract,
        });
        const recipientProcs = recipientAccounts.map((account, i) =>
            spawnVSSRecipientRun({
                runAs: account,
                pkeDkHex: `0x${Buffer.from(encKeypairs[i].decryptionKey.toBytes()).toString('hex')}`,
                sessionAddr,
                aceContract,
            }),
        );

        try {
            log('Wait for VSS session to complete.');
            const deadlineMillis = Date.now() + 60000;
            var session: ace.vss.Session | undefined;
            while (Date.now() < deadlineMillis) {
                const maybeSession = await getVssSession(adminAccount.accountAddress, sessionAddr);
                if (maybeSession.isOk) {
                    session = maybeSession.okValue!;
                    if (session.isCompleted()) break;
                }
                await sleep(1000);
            }
            if (!(session?.isCompleted())) throw 'VSS session did not complete in time.';
            

            log('Secret reconstruction should work and match on-chain public key.');
            const shares = session!.dealerContribution0!.privateShareMessages.slice(0, session!.threshold).map((ciphertext: ace.pke.Ciphertext, i: number) => {
                let msgBytes = ace.pke.decrypt({
                    decryptionKey: encKeypairs[i].decryptionKey,
                    ciphertext,
                }).unwrapOrThrow('Failed to decrypt share.');
                
                const msg = ace.vss.PrivateShareMessage.fromBytes(msgBytes).unwrapOrThrow('Failed to parse private share message.');
                return msg.share;
            });

            const reconstructedSecret = ace.vss.reconstruct({ indexedShares: shares.map((share, i) => ({ index: i + 1, share })) }).unwrapOrThrow('Failed to reconstruct secret.');

            log('Verify s*B == pcsCommitment.points[0].');
            const computedPk = session!.basePoint.scale(reconstructedSecret);
            const expectedPk = session!.dealerContribution0!.pcsCommitment.points[0];
            if (!computedPk.equals(expectedPk)) throw 'Reconstructed secret does not match on-chain public key.';
            console.log(`Reconstructed PK: ${computedPk.toHex()}`);
        } finally {
            for (const proc of [dealerProc, ...recipientProcs]) {
                proc.kill();
                //TODO: save logs to file and print the path.
            }
        }

    } finally {
        localnetProc.kill();
    }

}

main();
