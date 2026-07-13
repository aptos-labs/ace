// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import * as ace from '@aptos-labs/ace-sdk';
import type { ChildProcess } from 'child_process';
import * as path from 'path';

import {
    deployContracts,
    fundAccount,
    getVssSession,
    sleep,
    submitTxn,
} from './helpers';
import {
    spawnVSSDealerRun,
    spawnVSSRecipientRun,
} from './vss-clients';
import { startTempPostgres, type TempPostgres } from './postgres';
import { type PreviousCommitmentFixture, rawFrHex } from './vss-protocol-fixtures';

type PkeKeypair = Awaited<ReturnType<typeof ace.pke.keygen>>;
type SigKeypair = Awaited<ReturnType<typeof ace.sig.keygen>>;

export type VSSActors = {
    adminAccount: Account;
    dealerAccount: Account;
    holderAccounts: Account[];
    encKeypairs: PkeKeypair[];
    sigKeypairs: SigKeypair[];
};

export type NodeMsgEndpoints = {
    basePort: number;
    nodeMsgListens: string[];
    nodeMsgUrls: string[];
    clientPorts: number[];
    clientUrls: string[];
};

export type VSSStoreSetup = {
    externalStores: TempPostgres[];
    storeUrls: string[];
};

export async function createFundedVSSActors(numWorkers: number): Promise<VSSActors> {
    const accounts: Account[] = Array.from({ length: numWorkers + 1 }, () => Account.generate());
    const encKeypairs = await Promise.all(Array.from({ length: numWorkers }, () => ace.pke.keygen()));
    const sigKeypairs = await Promise.all(Array.from({ length: numWorkers }, () => ace.sig.keygen()));
    for (const account of accounts) {
        await fundAccount(account.accountAddress);
    }

    return {
        adminAccount: accounts[numWorkers],
        dealerAccount: accounts[0],
        holderAccounts: accounts.slice(0, numWorkers),
        encKeypairs,
        sigKeypairs,
    };
}

export function makeNodeMsgEndpoints(numWorkers: number): NodeMsgEndpoints {
    const basePort = 20500 + (2 * Math.floor(Math.random() * 1000));
    const nodeMsgListens = Array.from({ length: numWorkers }, (_, i) => `127.0.0.1:${basePort + (2 * i)}`);
    const clientPorts = Array.from({ length: numWorkers }, (_, i) => basePort + (2 * i) + 1);
    return {
        basePort,
        nodeMsgListens,
        nodeMsgUrls: nodeMsgListens.map(listen => `http://${listen}`),
        clientPorts,
        clientUrls: clientPorts.map(port => `http://localhost:${port}`),
    };
}

export async function deployVSSContracts(adminAccount: Account): Promise<void> {
    await deployContracts(adminAccount, [
        'pke',
        'sig',
        'worker_config',
        'group',
        'fiat-shamir-transform',
        'sigma-dlog-linear',
        'pedersen-polynomial-commitment',
        'vss',
    ]);
}

export async function registerVSSWorkers(opts: {
    actors: VSSActors;
    aceContract: string;
    nodeMsgEndpoints: NodeMsgEndpoints;
}): Promise<void> {
    for (let i = 0; i < opts.actors.holderAccounts.length; i++) {
        (await submitTxn({
            signer: opts.actors.holderAccounts[i],
            entryFunction: `${opts.aceContract}::worker_config::register_pke_enc_key`,
            args: [opts.actors.encKeypairs[i].encryptionKey.toBytes()],
        })).unwrapOrThrow('register_pke_enc_key failed').asSuccessOrThrow();

        (await submitTxn({
            signer: opts.actors.holderAccounts[i],
            entryFunction: `${opts.aceContract}::worker_config::register_sig_verification_key`,
            args: [opts.actors.sigKeypairs[i].publicKey.toBytes()],
        })).unwrapOrThrow('register_sig_verification_key failed').asSuccessOrThrow();

        (await submitTxn({
            signer: opts.actors.holderAccounts[i],
            entryFunction: `${opts.aceContract}::worker_config::register_node_msg_endpoint`,
            args: [opts.nodeMsgEndpoints.nodeMsgUrls[i]],
        })).unwrapOrThrow('register_node_msg_endpoint failed').asSuccessOrThrow();
    }
}

export async function startVSSSession(opts: {
    adminAccount: Account;
    dealerAccount: Account;
    holderAccounts: Account[];
    aceContract: string;
    threshold: number;
    scheme: number;
    pcsContextBytes: Uint8Array;
    previousCommitmentBytes: Uint8Array;
}): Promise<AccountAddress> {
    const committedTxn = (await submitTxn({
        signer: opts.adminAccount,
        entryFunction: `${opts.aceContract}::vss::new_session_entry`,
        awaitEventType: `${opts.aceContract}::vss::SessionCreated`,
        args: [
            opts.dealerAccount.accountAddress,
            opts.holderAccounts.map(w => w.accountAddress),
            opts.threshold,
            opts.scheme,
            opts.pcsContextBytes,
            opts.previousCommitmentBytes,
        ],
    })).unwrapOrThrow('new_session_entry failed').asSuccessOrThrow();
    const sessionAddrStr = committedTxn.findEvent(`${opts.aceContract}::vss::SessionCreated`)?.data.session_addr;
    if (!sessionAddrStr) throw 'Failed to get session address.';
    return AccountAddress.fromString(sessionAddrStr);
}

export function startVSSStores(tmpRoot: string): VSSStoreSetup {
    const externalStoreBasePort = 23500 + Math.floor(Math.random() * 2000);
    const externalStores = [
        startTempPostgres(tmpRoot, 'node-2-external-store', externalStoreBasePort),
        startTempPostgres(tmpRoot, 'node-3-external-store', externalStoreBasePort + 1),
    ];
    externalStores.forEach(store => store.createDatabase('vss'));
    return {
        externalStores,
        storeUrls: [
            `sqlite://${path.join(tmpRoot, 'node-0.db')}`,
            `sqlite://${path.join(tmpRoot, 'node-1.db')}`,
            externalStores[0].urlForDatabase('vss'),
            externalStores[1].urlForDatabase('vss'),
        ],
    };
}

export function spawnVSSClients(opts: {
    actors: VSSActors;
    aceContract: string;
    sessionAddr: AccountAddress;
    storeUrls: string[];
    nodeMsgEndpoints: NodeMsgEndpoints;
    previousFixture: PreviousCommitmentFixture | undefined;
}): ChildProcess[] {
    const dealerProc = spawnVSSDealerRun({
        runAs: opts.actors.dealerAccount,
        pkeDkHex: pkeDkHex(opts.actors.encKeypairs[0]),
        secretOverrideHex: opts.previousFixture ? rawFrHex(opts.previousFixture.secretRawFr) : undefined,
        previousBlindingOverrideHex: opts.previousFixture ? rawFrHex(opts.previousFixture.blindingRawFr) : undefined,
        sessionAddr: opts.sessionAddr,
        aceDeploymentAddr: opts.aceContract,
        sigSkHex: opts.actors.sigKeypairs[0].signingKey.toHex(),
        vssStoreUrl: opts.storeUrls[0],
        nodeMsgListen: opts.nodeMsgEndpoints.nodeMsgListens[0],
    });
    const holderProcs = opts.actors.holderAccounts.map((account, i) =>
        spawnVSSRecipientRun({
            runAs: account,
            pkeDkHex: pkeDkHex(opts.actors.encKeypairs[i]),
            sessionAddr: opts.sessionAddr,
            aceDeploymentAddr: opts.aceContract,
            sigSkHex: opts.actors.sigKeypairs[i].signingKey.toHex(),
            vssStoreUrl: opts.storeUrls[i],
        }),
    );
    return [dealerProc, ...holderProcs];
}

export async function waitForCompletedVssSession(
    adminAddress: AccountAddress,
    sessionAddr: AccountAddress,
): Promise<ace.vss.Session> {
    const deadlineMillis = Date.now() + 90000;
    let session: ace.vss.Session | undefined;
    while (Date.now() < deadlineMillis) {
        const maybeSession = await getVssSession(adminAddress, sessionAddr);
        if (maybeSession.isOk) {
            session = maybeSession.okValue!;
            if (session.isCompleted()) return session;
        }
        await sleep(1000);
    }
    throw 'VSS session did not complete in time.';
}

function pkeDkHex(keypair: PkeKeypair): string {
    return `0x${Buffer.from(keypair.decryptionKey.toBytes()).toString('hex')}`;
}
