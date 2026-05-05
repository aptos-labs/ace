// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * CI scenario: stand up the ACE local network, then exercise the Aptos custom flow
 * using the `check_acl_demo` contract.
 *
 * Flow:
 *   1. Start Aptos localnet.
 *   2. Fund 1 admin + 3 worker accounts.
 *   3. Deploy ACE contracts.
 *   4. Register PKE enc keys + HTTP endpoints for all workers.
 *   5. Build Rust workspace.
 *   6. Spawn one network-node per worker.
 *   7. Start initial epoch + propose new_secret; wait for DKG.
 *   8. Deploy and initialize check_acl_demo contract.
 *   9. Admin stores access code for a test label.
 *  10. Encrypt a test plaintext.
 *  11. Decrypt with wrong payload → expect failure.
 *  12. Decrypt with correct payload → expect success, verify plaintext.
 */

import { Account } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { pke } from '@aptos-labs/ace-sdk';
import { type ChildProcess } from 'child_process';
import * as path from 'path';

import {
    CHAIN_ID,
    LOCALNET_URL,
    REPO_ROOT,
    WORKER_BASE_PORT,
} from './common/config';
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
} from './common/helpers';
import { deployContract } from './common/infra';
import { buildRustWorkspace, killStaleNetworkNodes, spawnNetworkNode } from './common/network-clients';

const CHECK_ACL_DEMO_CONTRACT_DIR = path.join(REPO_ROOT, 'scenarios', 'custom-flow-aptos', 'contract');
const NUM_WORKERS = 3;
const THRESHOLD = 2;

async function main() {
    const nodeProcs: ChildProcess[] = [];
    let localnetProc: ChildProcess | undefined;

    const cleanup = () => {
        for (const proc of nodeProcs) proc.kill();
        localnetProc?.kill();
    };
    process.on('SIGINT', () => { cleanup(); process.exit(1); });
    process.on('SIGTERM', () => { cleanup(); process.exit(1); });

    let exitCode = 0;
    try {
        // ── 1. Start localnet ────────────────────────────────────────────────
        log('Starting Aptos localnet...');
        localnetProc = await startLocalnet();

        // ── 2. Fund accounts ──────────────────────────────────────────────────
        const accounts: Account[] = Array.from({ length: NUM_WORKERS + 1 }, () => Account.generate());
        const encKeypairs = await Promise.all(Array.from({ length: NUM_WORKERS }, () => pke.keygen()));
        log(`Funding ${NUM_WORKERS + 1} accounts...`);
        for (const account of accounts) {
            await fundAccount(account.accountAddress);
        }
        const adminAccount = accounts[NUM_WORKERS]!;
        const workerAccounts = accounts.slice(0, NUM_WORKERS);
        const aceContract = adminAccount.accountAddress.toStringLong();
        const adminAddr = adminAccount.accountAddress;
        const adminKeyHex = ed25519PrivateKeyHex(adminAccount);

        // ── 3. Deploy ACE contracts ───────────────────────────────────────────
        log('Deploying ACE contracts...');
        await deployContracts(adminAccount, [
            'pke', 'worker_config', 'group', 'fiat-shamir-transform',
            'sigma-dlog-eq', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network',
        ]);

        // ── 4. Register PKE enc keys + HTTP endpoints ─────────────────────────
        log('Registering PKE enc keys and HTTP endpoints...');
        for (let i = 0; i < NUM_WORKERS; i++) {
            (await submitTxn({
                signer: workerAccounts[i]!,
                entryFunction: `${aceContract}::worker_config::register_pke_enc_key`,
                args: [encKeypairs[i]!.encryptionKey.toBytes()],
            })).unwrapOrThrow('register_pke_enc_key failed').asSuccessOrThrow();
            (await submitTxn({
                signer: workerAccounts[i]!,
                entryFunction: `${aceContract}::worker_config::register_endpoint`,
                args: [`http://127.0.0.1:${WORKER_BASE_PORT + i}`],
            })).unwrapOrThrow('register_endpoint failed').asSuccessOrThrow();
        }

        // ── 5. Build Rust workspace ───────────────────────────────────────────
        log('Building Rust workspace...');
        await buildRustWorkspace();

        // ── 6. Kill stale workers + spawn fresh workers ───────────────────────
        killStaleNetworkNodes();
        for (let i = 0; i < NUM_WORKERS; i++) {
            const pkeDkHex = `0x${Buffer.from(encKeypairs[i]!.decryptionKey.toBytes()).toString('hex')}`;
            nodeProcs.push(spawnNetworkNode({
                runAs: workerAccounts[i]!,
                pkeDkHex,
                aceDeploymentAddr: aceContract,
                aceDeploymentApi: LOCALNET_URL,
                port: WORKER_BASE_PORT + i,
            }));
        }

        // ── 7. Start epoch + DKG ──────────────────────────────────────────────
        log('Admin: start_initial_epoch (resharing_interval_secs=3600)...');
        (await submitTxn({
            signer: adminAccount,
            entryFunction: `${aceContract}::network::start_initial_epoch`,
            args: [workerAccounts.map(w => w.accountAddress), THRESHOLD, 3600],
        })).unwrapOrThrow('start_initial_epoch failed').asSuccessOrThrow();

        log('Admin: propose new_secret; workers 0,1 approve...');
        await proposeAndApprove(
            workerAccounts[0]!,
            workerAccounts.slice(0, THRESHOLD),
            aceContract,
            serializeNewSecretProposal(0),
        );

        log('Waiting for DKG to complete...');
        const deadline = Date.now() + 300_000;
        let networkState: ACE.network.State | undefined;
        while (Date.now() < deadline) {
            const maybe = await getNetworkState(adminAddr);
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
        await sleep(5_000); // let workers stabilise

        // ── 8. Deploy check_acl_demo contract ────────────────────────────────
        log('Deploying check_acl_demo contract...');
        await deployContract(CHECK_ACL_DEMO_CONTRACT_DIR, adminAddr.toStringLong(), adminKeyHex);
        (await submitTxn({
            signer: adminAccount,
            entryFunction: `${aceContract}::check_acl_demo::initialize`,
            args: [],
        })).unwrapOrThrow('check_acl_demo::initialize failed').asSuccessOrThrow();
        log('check_acl_demo deployed and initialized');

        // ── 9. Admin stores access code ───────────────────────────────────────
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
            apiEndpoint: LOCALNET_URL,
            contractAddr: adminAddr,
        });

        // ── 10. Encrypt plaintext with the label ──────────────────────────────
        const plaintext = new TextEncoder().encode('HELLO CUSTOM FLOW');
        const encResult = await ACE.AptosCustomFlow.encrypt({
            aceDeployment,
            keypairId,
            chainId: CHAIN_ID,
            moduleAddr: adminAddr,
            moduleName: 'check_acl_demo',
            functionName: 'check_acl',
            domain: label,
            plaintext,
        });
        assert(encResult.isOk, `encrypt failed: ${encResult.errValue}`);
        const ciphertext = encResult.okValue!;
        log('Plaintext encrypted');

        // Generate caller PKE keypair (used to receive the decryption key share)
        const callerKeyPair = await pke.keygen();
        const encPk = callerKeyPair.encryptionKey.toBytes();
        const encSk = callerKeyPair.decryptionKey.toBytes();

        // ── 11. Wrong payload must be rejected ────────────────────────────────
        log('Attempting decrypt with wrong payload (should fail)...');
        let wrongPayloadFailed = false;
        try {
            await ACE.AptosCustomFlow.decrypt({
                ciphertext,
                label,
                encPk,
                encSk,
                payload: wrongCode,
                aceDeployment,
                keypairId,
                chainId: CHAIN_ID,
                moduleAddr: adminAddr,
                moduleName: 'check_acl_demo',
                functionName: 'check_acl',
            });
        } catch (_e) {
            wrongPayloadFailed = true;
        }
        assert(wrongPayloadFailed, 'Wrong payload should have been rejected');
        log('Wrong payload correctly rejected ✓');

        // ── 12. Correct payload must succeed ──────────────────────────────────
        log('Attempting decrypt with correct payload (should succeed)...');
        const decrypted = await ACE.AptosCustomFlow.decrypt({
            ciphertext,
            label,
            encPk,
            encSk,
            payload: correctCode,
            aceDeployment,
            keypairId,
            chainId: CHAIN_ID,
            moduleAddr: adminAddr,
            moduleName: 'check_acl_demo',
            functionName: 'check_acl',
        });
        assert(
            new TextDecoder().decode(decrypted) === 'HELLO CUSTOM FLOW',
            `plaintext mismatch: ${new TextDecoder().decode(decrypted)}`,
        );
        log('Correct payload accepted; plaintext recovered ✓');

        log('\n✅ Aptos custom-flow tests passed!\n');
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        cleanup();
        process.exit(exitCode);
    }
}

main();
