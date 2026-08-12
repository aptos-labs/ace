// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { pke } from '@aptos-labs/ace-sdk';
import { type ChildProcess } from 'child_process';
import * as path from 'path';

import {
    CHAIN_ID,
    LOCALNET_URL,
    REPO_ROOT,
    WORKER_BASE_PORT,
} from '../common/config';
import {
    assert,
    sleep,
    log,
    fundAccount,
    submitTxn,
    deployContracts,
    startLocalnet,
    getNetworkState,
    proposeAndApprove,
    serializeNewSecretProposal,
    ed25519PrivateKeyHex,
} from '../common/helpers';
import { deployContract } from '../common/infra';
import { buildRustWorkspace, killStaleNetworkNodes, spawnNetworkNodeMaybeSplit } from '../common/network-clients';

const CHECK_ACL_DEMO_CONTRACT_DIR = path.join(REPO_ROOT, 'scenarios', 'custom-flow-aptos', 'contract');
const NUM_WORKERS = 3;
const THRESHOLD = 2;

export interface AptosCustomFlowSetup {
    localnetProc: ChildProcess;
    nodeProcs: ChildProcess[];
    adminAccount: Account;
    adminAddr: AccountAddress;
    aceContract: string;
    keypairId: AccountAddress;
}

export interface CustomFlowFixtures {
    aceDeployment: ACE.AceDeployment;
    keypairId: AccountAddress;
    adminAddr: AccountAddress;
    label: Uint8Array;
    correctCode: Uint8Array;
    wrongCode: Uint8Array;
    baseArgs: Omit<Parameters<typeof ACE.IBE_Aptos.decryptCustomFlow>[0],
        'label' | 'payload' | 'keypairId'>;
}

/** Bring up Aptos localnet + ACE contracts + workers + initial epoch +
 *  DKG, then deploy `check_acl_demo` and initialize it. Returns
 *  everything the test cases need. */
export async function bringUpAceAndDeployCheckAclDemo(): Promise<AptosCustomFlowSetup> {
    const localnetProc = await startLocalnet();
    const accounts: Account[] = Array.from({ length: NUM_WORKERS + 1 }, () => Account.generate());
    const encKeypairs = await Promise.all(Array.from({ length: NUM_WORKERS }, () => pke.keygen()));
    log(`Funding ${NUM_WORKERS + 1} accounts...`);
    for (const account of accounts) await fundAccount(account.accountAddress);
    const adminAccount = accounts[NUM_WORKERS]!;
    const workerAccounts = accounts.slice(0, NUM_WORKERS);
    const aceContract = adminAccount.accountAddress.toStringLong();
    const adminAddr = adminAccount.accountAddress;
    log('Deploying ACE contracts...');
    await deployContracts(adminAccount, [
        'pke', 'worker_config', 'group', 'secret-usage', 'fiat-shamir-transform',
        'sigma-dlog-linear', 'pedersen-polynomial-commitment', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network',
    ]);
    await registerWorkersOnChain(workerAccounts, encKeypairs, aceContract);
    log('Building Rust workspace...');
    await buildRustWorkspace();
    killStaleNetworkNodes();
    const nodeProcs = spawnAceWorkers(workerAccounts, encKeypairs, aceContract);
    const keypairId = await startInitialEpochAndRunDkg(adminAccount, workerAccounts, aceContract);
    await sleep(5_000); // let workers stabilise on the new shares
    await deployAndInitCheckAclDemo(adminAccount, adminAddr, ed25519PrivateKeyHex(adminAccount), aceContract);
    return { localnetProc, nodeProcs, adminAccount, adminAddr, aceContract, keypairId };
}

/** Store an access code on-chain, encrypt a fixed plaintext under
 *  `label`, mint a caller PKE keypair, and bundle everything the test
 *  cases need into a single `CustomFlowFixtures` object. */
export async function prepareEncryptedContent(setup: AptosCustomFlowSetup): Promise<CustomFlowFixtures> {
    const { adminAccount, adminAddr, aceContract, keypairId } = setup;
    const label = new TextEncoder().encode('custom-test-content');
    const correctCode = new TextEncoder().encode('open-sesame');
    const wrongCode = new TextEncoder().encode('wrong-password');
    (await submitTxn({
        signer: adminAccount,
        entryFunction: `${aceContract}::check_acl_demo::set_access_code`,
        args: [Array.from(label), Array.from(correctCode)],
    })).unwrapOrThrow('set_access_code failed').asSuccessOrThrow();
    log('Access code stored on-chain');
    const aceDeployment = new ACE.AceDeployment({
        apiEndpoint: LOCALNET_URL, contractAddr: adminAddr,
    });
    // Keep the low-level public-key cache path covered in a real scenario.
    const pk = (await ACE.IBE_Aptos.fetchPk({
        aceDeployment,
        keypairId,
    })).unwrapOrThrow('fetchPk failed');
    const encResult = await ACE.IBE_Aptos.encrypt({
        aceDeployment, keypairId, chainId: CHAIN_ID, moduleAddr: adminAddr,
        moduleName: 'check_acl_demo',
        label, plaintext: new TextEncoder().encode('HELLO CUSTOM FLOW'),
        pk,
    });
    assert(encResult.isOk, `encrypt failed: ${encResult.errValue}`);
    const callerKeyPair = await pke.keygen();
    log('Plaintext encrypted');
    return {
        aceDeployment, keypairId, adminAddr, label, correctCode, wrongCode,
        baseArgs: {
            ciphertext: encResult.okValue!,
            encPk: callerKeyPair.encryptionKey.toBytes(),
            encSk: callerKeyPair.decryptionKey.toBytes(),
            aceDeployment, chainId: CHAIN_ID, moduleAddr: adminAddr,
            moduleName: 'check_acl_demo',
        },
    };
}

/** Each worker registers its PKE enc key + HTTP endpoint on-chain. */
async function registerWorkersOnChain(
    workers: Account[],
    encKeypairs: { encryptionKey: pke.EncryptionKey; decryptionKey: pke.DecryptionKey }[],
    aceContract: string,
): Promise<void> {
    log('Registering PKE enc keys and HTTP endpoints...');
    for (let i = 0; i < workers.length; i++) {
        (await submitTxn({
            signer: workers[i]!,
            entryFunction: `${aceContract}::worker_config::register_pke_enc_key`,
            args: [encKeypairs[i]!.encryptionKey.toBytes()],
        })).unwrapOrThrow('register_pke_enc_key failed').asSuccessOrThrow();
        (await submitTxn({
            signer: workers[i]!,
            entryFunction: `${aceContract}::worker_config::register_endpoint`,
            args: [`http://127.0.0.1:${WORKER_BASE_PORT + i}`],
        })).unwrapOrThrow('register_endpoint failed').asSuccessOrThrow();
    }
}

/** Spawn one `network-node` process per worker. Returns the (possibly
 *  split-process) handles for the cleanup hook. */
function spawnAceWorkers(
    workers: Account[],
    encKeypairs: { encryptionKey: pke.EncryptionKey; decryptionKey: pke.DecryptionKey }[],
    aceContract: string,
): ChildProcess[] {
    const nodeProcs: ChildProcess[] = [];
    for (let i = 0; i < workers.length; i++) {
        const pkeDkHex = `0x${Buffer.from(encKeypairs[i]!.decryptionKey.toBytes()).toString('hex')}`;
        nodeProcs.push(...spawnNetworkNodeMaybeSplit({
            index: i, total: workers.length, runAs: workers[i]!, pkeDkHex,
            aceDeploymentAddr: aceContract, aceDeploymentApi: LOCALNET_URL,
            workerBasePort: WORKER_BASE_PORT,
        }));
    }
    return nodeProcs;
}

/** Admin calls `start_initial_epoch` (reshare interval 3600s - no
 *  auto-rotation during this test), then proposes one new_secret;
 *  threshold of workers approve; poll until DKG completes. Returns the
 *  DKG'd keypair_id. */
async function startInitialEpochAndRunDkg(
    admin: Account,
    workers: Account[],
    aceContract: string,
): Promise<AccountAddress> {
    log('Admin: start_initial_epoch (resharing_interval_secs=3600)...');
    (await submitTxn({
        signer: admin,
        entryFunction: `${aceContract}::network::start_initial_epoch`,
        args: [workers.map(w => w.accountAddress), THRESHOLD, 3600],
    })).unwrapOrThrow('start_initial_epoch failed').asSuccessOrThrow();
    log('Admin: propose new_secret; workers 0,1 approve...');
    await proposeAndApprove(
        workers[0]!, workers.slice(0, THRESHOLD), aceContract,
        serializeNewSecretProposal(1),
    );
    log('Waiting for DKG to complete...');
    const deadline = Date.now() + 300_000;
    let networkState: ACE.network.State | undefined;
    while (Date.now() < deadline) {
        const maybe = await getNetworkState(admin.accountAddress);
        if (maybe.isOk) {
            networkState = maybe.okValue!;
            if (networkState.epochChangeInfo === null && networkState.secrets.length >= 1) break;
        }
        await sleep(5_000);
    }
    if (!networkState || networkState.secrets.length < 1) {
        throw 'DKG did not complete within 5 minutes.';
    }
    const keypairId = networkState.secrets[0]!.keypairId;
    log(`DKG complete. keypairId=${keypairId.toStringLong()}`);
    return keypairId;
}

/** Deploy `check_acl_demo` Move contract under the admin's address and
 *  call its `initialize()` entry function. */
async function deployAndInitCheckAclDemo(
    adminAccount: Account,
    adminAddr: AccountAddress,
    adminKeyHex: string,
    aceContract: string,
): Promise<void> {
    log('Deploying check_acl_demo contract...');
    await deployContract(CHECK_ACL_DEMO_CONTRACT_DIR, adminAddr.toStringLong(), adminKeyHex);
    (await submitTxn({
        signer: adminAccount,
        entryFunction: `${aceContract}::check_acl_demo::initialize`,
        args: [],
    })).unwrapOrThrow('check_acl_demo::initialize failed').asSuccessOrThrow();
    log('check_acl_demo deployed and initialized');
}
