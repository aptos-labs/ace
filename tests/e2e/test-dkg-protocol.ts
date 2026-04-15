// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import * as ace from '@aptos-labs/ace-sdk';
import { startLocalnet, fundAccount, log, deployContracts, submitTxn, sleep, getDKGSession } from './helpers';
import { buildRustWorkspace, spawnDKGRun } from './dkg-clients';

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
        const workerAccounts = accounts.slice(0, numWorkers);

        log('Deploy contracts.');
        await deployContracts(adminAccount, ['pke', 'worker_config', 'group', 'vss', 'dkg']);

        log('Register workers.');
        for (let i = 0; i < numWorkers; i++) {
            (await submitTxn({
                signer: accounts[i],
                entryFunction: `${adminAccount.accountAddress}::worker_config::register_pke_enc_key`,
                args: [encKeypairs[i].encryptionKey.toBytes()],
            })).unwrapOrThrow('Failed to register worker.').asSuccessOrThrow();
        }

        // Build base_point bytes: G1 generator as [u8 scheme][uleb128(48)][48B].
        const g1Inner = ace.vss.bls12381Fr.g1Generator();
        const basePointBytes = ace.vss.PublicPoint.fromBls12381G1(g1Inner).toBytes();

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
            aceContract,
        }));

        try {
            log('Wait for DKG session to complete.');
            const deadlineMillis = Date.now() + 120_000;
            let session: ace.dkg.Session | undefined;
            while (Date.now() < deadlineMillis) {
                // Touch the session to let the contract finalize state when ready.
                await submitTxn({
                    signer: adminAccount,
                    entryFunction: `${aceContract}::dkg::touch_entry`,
                    args: [sessionAddr],
                });
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
