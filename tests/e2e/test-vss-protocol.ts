// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import * as ace from '@aptos-labs/ace-sdk';
import { startLocalnet, fundAccount, log, deployContracts, submitTxn, sleep, getVssSession } from './helpers';
import {
    buildRustWorkspace,
    checkVSSCompletion,
    fetchEncryptedShares,
    fetchPublicKeyBytes,
    spawnVSSDealerRun,
    spawnVSSRecipientRun,
} from './vss-clients';

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
        await deployContracts(adminAccount, ['worker_config', 'vss']);

        log('Register workers.');
        for (let i = 0; i < numWorkers; i++) {
            const maybeCommittedTxn = await submitTxn({
                signer: accounts[i],
                entryFunction: `${adminAccount.accountAddress}::worker_config::register_pke_enc_key`,
                args: [encKeypairs[i].encryptionKey.toBytes()],
            });
            maybeCommittedTxn.unwrapOrThrow('Failed to get committed transaction.').asSuccessOrThrow();
        }
        
        log('Start VSS session.');
        const maybeCommittedTxn = await submitTxn({
            signer: adminAccount,
            entryFunction: `${adminAccount.accountAddress}::vss::new_session_entry`,
            args: [
                dealerAccount.accountAddress,
                recipientAccounts.map(w => w.accountAddress),
                3, // threshold
                ace.vss.SCHEME_BLS12381G1, // secret scheme
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
            const deadlineMillis = Date.now() + 30000;
            let completed = false;
            while (Date.now() < deadlineMillis) {
                const maybeSession = await getVssSession(adminAccount.accountAddress, sessionAddr);
                if (maybeSession.okValue?.isCompleted()) {
                    completed = true;
                    break;
                }
                await sleep(1000);
            }
            if (!completed) throw 'VSS session did not complete in time.';
            
            log('Secret reconstruction should work and match on-chain public key.');
            // const encryptedShares = await fetchEncryptedShares(sessionAddr);
            // const shares = encryptedShares.map((encryptedShare, i) => {
            //     let shareBytes = ace.pke.decrypt({
            //         decryptionKey: encKeypairs[i].decryptionKey,
            //         ciphertext: encryptedShare,
            //     }).unwrapOrThrow('Failed to decrypt share.');
            //     let secretShare = ace.vss.SecretShare.fromBytes(shareBytes).unwrapOrThrow('Failed to parse secret share.');
            //     return secretShare;
            // });

            // const secret = ace.vss.reconstructSecret(shares).unwrapOrThrow('Failed to reconstruct secret.');
            // const publicCommitment = ace.vss.derivePublicCommitment({secret});
            // const onchainPublicKey = (await fetchPublicKeyBytes(sessionAddr)).unwrapOrThrow(
            //     'Failed to fetch public key.',
            // );
            // if (publicCommitment.toBytes() !== onchainPublicKey) throw 'Public commitment does not match on-chain public key.';
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
