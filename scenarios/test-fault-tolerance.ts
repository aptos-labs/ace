// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Fault-tolerance scenario: one committee member is offline per epoch.
 *
 * Epoch 1 uses committee [0,1,2,3] with worker 0 offline. Epoch 2 uses
 * committee [1,2,3,4] with worker 4 offline. DKG, DKR, and IBE decryption must
 * all complete with exactly the threshold number of online workers.
 */

import { Account, AccountAddress, Ed25519PrivateKey } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { pke, sig } from '@aptos-labs/ace-sdk';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import * as path from 'path';
import type { ChildProcess } from 'child_process';

import {
    deployAndInitAccessControl,
    domainForBlob,
    registerAllowlistBlob,
} from './common/access-control-app';
import { ACE_CONTRACTS } from './common/ace-network';
import { buildAptosWalletFullMessage } from './common/aptos-wallet-message';
import { CHAIN_ID, LOCALNET_URL } from './common/config';
import {
    assert,
    assertTxnSuccess,
    cleanupScenario,
    createAptos,
    deployContracts,
    ed25519PrivateKeyHex,
    fundAccount,
    getNetworkState,
    proposeAndApprove,
    serializeCommitteeChangeProposal,
    serializeNewSecretProposal,
    setupBaseAceActors,
    sleep,
    startLocalnet,
    submitTxn,
    waitFor,
} from './common/helpers';
import {
    buildRustWorkspace,
    shouldSpawnSplitNetworkNode,
    spawnNetworkNodeMaybeSplit,
} from './common/network-clients';
import { makeNodeMsgEndpoints, type NodeMsgEndpoints } from './common/vss-protocol-setup';

const TOTAL_WORKERS = 5;
const EPOCH1_WORKER_INDICES = [0, 1, 2, 3];
const EPOCH1_THRESHOLD = 3;
const EPOCH2_WORKER_INDICES = [1, 2, 3, 4];
const EPOCH2_THRESHOLD = 3;
const OFFLINE_WORKERS = new Set([0, 4]);
const RESHARE_INTERVAL_SECS = 600;

type PkeKeypair = Awaited<ReturnType<typeof pke.keygen>>;
type SigKeypair = Awaited<ReturnType<typeof sig.keygen>>;

function step(n: string | number, msg: string): void {
    console.log(`\n-- Step ${n}: ${msg} --`);
}

function workerKey(index: number): Ed25519PrivateKey {
    return new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, j) => j + 10 + index)));
}

async function createWorkers(): Promise<{
    workerAccounts: Account[];
    encKeypairs: PkeKeypair[];
    sigKeypairs: SigKeypair[];
}> {
    const workerAccounts: Account[] = [];
    for (let i = 0; i < TOTAL_WORKERS; i++) {
        const account = Account.fromPrivateKey({ privateKey: workerKey(i) });
        await fundAccount(account.accountAddress);
        workerAccounts.push(account);
    }
    return {
        workerAccounts,
        encKeypairs: await Promise.all(Array.from({ length: TOTAL_WORKERS }, () => pke.keygen())),
        sigKeypairs: await Promise.all(Array.from({ length: TOTAL_WORKERS }, () => sig.keygen())),
    };
}

async function registerWorkers(args: {
    adminAddr: string;
    workerAccounts: Account[];
    encKeypairs: PkeKeypair[];
    sigKeypairs: SigKeypair[];
    nodeMsgEndpoints: NodeMsgEndpoints;
}): Promise<void> {
    const { adminAddr, workerAccounts, encKeypairs, sigKeypairs, nodeMsgEndpoints } = args;
    for (let i = 0; i < TOTAL_WORKERS; i++) {
        const clientEndpoint = nodeMsgEndpoints.clientUrls[i]!;
        const nodeMsgEndpoint = shouldSpawnSplitNetworkNode(i, TOTAL_WORKERS)
            ? nodeMsgEndpoints.nodeMsgUrls[i]!
            : clientEndpoint;
        assertTxnSuccess(
            await submitTxn({
                signer: workerAccounts[i]!,
                entryFunction: `${adminAddr}::worker_config::register_pke_enc_key`,
                args: [Array.from(encKeypairs[i]!.encryptionKey.toBytes())],
            }),
            `register_pke_enc_key worker ${i}`,
        );
        assertTxnSuccess(
            await submitTxn({
                signer: workerAccounts[i]!,
                entryFunction: `${adminAddr}::worker_config::register_sig_verification_key`,
                args: [sigKeypairs[i]!.publicKey.toBytes()],
            }),
            `register_sig_verification_key worker ${i}`,
        );
        assertTxnSuccess(
            await submitTxn({
                signer: workerAccounts[i]!,
                entryFunction: `${adminAddr}::worker_config::register_node_msg_endpoint`,
                args: [nodeMsgEndpoint],
            }),
            `register_node_msg_endpoint worker ${i}`,
        );
        assertTxnSuccess(
            await submitTxn({
                signer: workerAccounts[i]!,
                entryFunction: `${adminAddr}::worker_config::register_client_endpoint`,
                args: [clientEndpoint],
            }),
            `register_client_endpoint worker ${i}`,
        );
    }
}

async function startInitialEpoch(args: {
    admin: Account;
    adminAddr: string;
    workerAccounts: Account[];
}): Promise<void> {
    const epoch1Addrs = EPOCH1_WORKER_INDICES.map(
        i => args.workerAccounts[i]!.accountAddress.toStringLong(),
    );
    assertTxnSuccess(
        await submitTxn({
            signer: args.admin,
            entryFunction: `${args.adminAddr}::network::start_initial_epoch`,
            args: [epoch1Addrs, EPOCH1_THRESHOLD, RESHARE_INTERVAL_SECS],
        }),
        'network::start_initial_epoch',
    );
}

async function spawnOnlineWorkers(args: {
    adminAddr: string;
    workerAccounts: Account[];
    encKeypairs: PkeKeypair[];
    sigKeypairs: SigKeypair[];
    storeUrls: string[];
    nodeMsgEndpoints: NodeMsgEndpoints;
}): Promise<ChildProcess[]> {
    await buildRustWorkspace();
    const procs: ChildProcess[] = [];
    for (let i = 0; i < TOTAL_WORKERS; i++) {
        if (OFFLINE_WORKERS.has(i)) {
            console.log(`worker ${i}: offline`);
            continue;
        }
        procs.push(...spawnNetworkNodeMaybeSplit({
            index: i,
            total: TOTAL_WORKERS,
            runAs: args.workerAccounts[i]!,
            pkeDkHex: `0x${Buffer.from(args.encKeypairs[i]!.decryptionKey.toBytes()).toString('hex')}`,
            sigSkHex: args.sigKeypairs[i]!.signingKey.toHex(),
            vssStoreUrl: args.storeUrls[i]!,
            nodeMsgListen: args.nodeMsgEndpoints.nodeMsgListens[i]!,
            aceDeploymentAddr: args.adminAddr,
            aceDeploymentApi: LOCALNET_URL,
            workerBasePort: args.nodeMsgEndpoints.basePort,
        }));
        console.log(`worker ${i}: spawned`);
    }
    await sleep(2_000);
    return procs;
}

async function runDkgWithWorkerZeroOffline(args: {
    adminAddr: string;
    adminAccountAddress: AccountAddress;
    workerAccounts: Account[];
}): Promise<AccountAddress> {
    const onlineEpoch1Workers = [1, 2, 3].map(i => args.workerAccounts[i]!);
    await proposeAndApprove(
        onlineEpoch1Workers[0]!,
        onlineEpoch1Workers,
        args.adminAddr,
        serializeNewSecretProposal(ACE.network.PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEAD),
    );
    await waitFor('keypair DKG with worker 0 offline', async () => {
        const stateResult = await getNetworkState(args.adminAccountAddress);
        if (!stateResult.isOk) return false;
        return stateResult.okValue!.secrets.length >= 1;
    }, 180_000);
    const state = (await getNetworkState(args.adminAccountAddress))
        .unwrapOrThrow('state read failed after fault-tolerance DKG');
    return state.secrets[0]!.keypairId;
}

async function rotateToEpoch2WithWorkerFourOffline(args: {
    adminAddr: string;
    adminAccountAddress: AccountAddress;
    workerAccounts: Account[];
}): Promise<void> {
    const onlineEpoch1Workers = [1, 2, 3].map(i => args.workerAccounts[i]!);
    await proposeAndApprove(
        onlineEpoch1Workers[0]!,
        onlineEpoch1Workers,
        args.adminAddr,
        serializeCommitteeChangeProposal(
            EPOCH2_WORKER_INDICES.map(i => args.workerAccounts[i]!.accountAddress),
            EPOCH2_THRESHOLD,
        ),
    );
    await waitFor('epoch 2 with worker 4 offline', async () => {
        const stateResult = await getNetworkState(args.adminAccountAddress);
        if (!stateResult.isOk) return false;
        return Number(stateResult.okValue!.epoch) === 2;
    }, 180_000);
}

async function decryptPing(args: {
    aceDeployment: ACE.AceDeployment;
    adminAccountAddress: AccountAddress;
    bob: Account;
    keypairId: AccountAddress;
    label: Uint8Array;
    ciphertext: Uint8Array;
}): Promise<void> {
    const session = await ACE.IBE_Aptos.BasicDecryptionSession.create({
        aceDeployment: args.aceDeployment,
        keypairId: args.keypairId,
        chainId: CHAIN_ID,
        moduleAddr: args.adminAccountAddress,
        moduleName: 'access_control',
        label: args.label,
        ciphertext: args.ciphertext,
    });
    const message = await session.getRequestToSign();
    const fullMessage = buildAptosWalletFullMessage({
        accountAddress: args.bob.accountAddress,
        chainId: CHAIN_ID,
        message,
        nonce: 'fault-tolerance-ping',
    });
    const plaintext = await session.decryptWithProof({
        userAddr: args.bob.accountAddress,
        publicKey: args.bob.publicKey,
        signature: args.bob.sign(fullMessage),
        fullMessage,
    });
    assert(plaintext.isOk, `decrypt PING failed: ${plaintext.errValue}`);
    assert(new TextDecoder().decode(plaintext.okValue!) === 'PING', 'PING plaintext mismatch');
}

async function main(): Promise<void> {
    let workers: ChildProcess[] = [];
    let localnetProc: ChildProcess | null = null;
    let vssStoreTmpRoot: string | undefined;
    let exitCode = 0;

    try {
        step(0, 'start localnet and deploy ACE contracts');
        localnetProc = await startLocalnet();
        const actors = await setupBaseAceActors();
        await deployContracts(actors.admin, [...ACE_CONTRACTS]);

        step(1, 'create and register five workers');
        const { workerAccounts, encKeypairs, sigKeypairs } = await createWorkers();
        const nodeMsgEndpoints = makeNodeMsgEndpoints(TOTAL_WORKERS);
        vssStoreTmpRoot = mkdtempSync(path.join(tmpdir(), 'ace-fault-tolerance-'));
        const storeUrls = workerAccounts.map((_, i) => `sqlite://${path.join(vssStoreTmpRoot!, `node-${i}.db`)}`);
        await registerWorkers({
            adminAddr: actors.adminAddr,
            workerAccounts,
            encKeypairs,
            sigKeypairs,
            nodeMsgEndpoints,
        });

        step(2, 'start epoch 1 and spawn online workers only');
        await startInitialEpoch({
            admin: actors.admin,
            adminAddr: actors.adminAddr,
            workerAccounts,
        });
        workers = await spawnOnlineWorkers({
            adminAddr: actors.adminAddr,
            workerAccounts,
            encKeypairs,
            sigKeypairs,
            storeUrls,
            nodeMsgEndpoints,
        });

        step(3, 'run DKG with worker 0 offline');
        const adminAccountAddress = actors.admin.accountAddress;
        const keypairId = await runDkgWithWorkerZeroOffline({
            adminAddr: actors.adminAddr,
            adminAccountAddress,
            workerAccounts,
        });
        await sleep(5_000);

        step(4, 'deploy access-control app and encrypt PING');
        const bob = Account.fromPrivateKey({
            privateKey: new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 200))),
        });
        await fundAccount(bob.accountAddress);
        await deployAndInitAccessControl(actors.admin, actors.adminAddr, ed25519PrivateKeyHex(actors.admin));
        await registerAllowlistBlob(
            createAptos(),
            actors.alice,
            bob.accountAddress,
            actors.adminAddr,
            'ping-blob',
        );
        const label = domainForBlob(actors.alice, 'ping-blob');
        const aceDeployment = new ACE.AceDeployment({
            apiEndpoint: LOCALNET_URL,
            contractAddr: adminAccountAddress,
        });
        const ciphertext = (await ACE.IBE_Aptos.encrypt({
            aceDeployment,
            keypairId,
            chainId: CHAIN_ID,
            moduleAddr: adminAccountAddress,
            moduleName: 'access_control',
            label,
            plaintext: new TextEncoder().encode('PING'),
        })).unwrapOrThrow('encrypt PING');

        step(5, 'rotate to epoch 2 with worker 4 offline');
        await rotateToEpoch2WithWorkerFourOffline({
            adminAddr: actors.adminAddr,
            adminAccountAddress,
            workerAccounts,
        });
        await sleep(10_000);

        step(6, 'decrypt with threshold online workers in epoch 2');
        await decryptPing({
            aceDeployment,
            adminAccountAddress,
            bob,
            keypairId,
            label,
            ciphertext,
        });

        console.log('\nFault-tolerance scenario passed.\n');
    } catch (err) {
        console.error('\nTest failed:', err);
        exitCode = 1;
    } finally {
        cleanupScenario(workers, localnetProc);
        if (vssStoreTmpRoot) rmSync(vssStoreTmpRoot, { recursive: true, force: true });
        process.exit(exitCode);
    }
}

main();
