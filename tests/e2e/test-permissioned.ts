// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * E2E test for the permissioned ACE network with threshold IBE.
 *
 * Scenario:
 *   Epoch 0: 3-out-of-4 committee (workers 0–3)
 *   Epoch 1: 3-out-of-5 committee (workers 1–5)
 *             Worker 0 leaves; workers 4 and 5 join.
 *
 * Run:
 *   cd tests/e2e && pnpm test:permissioned
 */

import {
    Account,
    AccountAddress,
    Ed25519PrivateKey,
    Serializer,
} from '@aptos-labs/ts-sdk';
import { ace, ace_threshold } from '@aptos-labs/ace-sdk';
import { spawn, ChildProcess } from 'child_process';
import { existsSync, rmSync } from 'fs';
import * as path from 'path';

import {
    CONTRACT_DIR,
    ACCESS_CONTROL_CONTRACT_DIR,
    LOCALNET_URL,
    FAUCET_URL,
    CHAIN_ID,
    NUM_WORKERS,
    THRESHOLD,
    WORKER_BASE_PORT,
} from './config.js';
import { log, assert, sleep, waitFor, createAptos, fundAccount, callView, submitTxn } from './helpers.js';
import { buildWorker, deployContract, spawnWorker, waitWorkerHealthy } from './infra.js';

// Epoch-1 committee: workers 1–5 (3-of-5); worker 0 leaves, workers 4–5 join.
const NEW_NUM_WORKERS = 5;
const NEW_THRESHOLD = 3;
// Total unique workers across both epochs: 0–5 (6 total).
const TOTAL_WORKERS = NUM_WORKERS + 2; // 6

async function main() {
    const workers: ChildProcess[] = [];
    let localnetProc: ChildProcess | null = null;

    // Clean up any stale share files from previous runs (all 6 workers).
    for (let i = 0; i < TOTAL_WORKERS; i++) {
        const jsonPath = path.join(process.cwd(), `worker_shares_${WORKER_BASE_PORT + i}.json`);
        if (existsSync(jsonPath)) rmSync(jsonPath);
    }

    let exitCode = 0;
    try {
        const aptos = createAptos();

        // ── Step 0: Start a fresh localnet ───────────────────────────────────
        log('0', 'Start fresh localnet');
        const localnetAlreadyUp = await (async () => {
            try {
                const r = await fetch(LOCALNET_URL, { signal: AbortSignal.timeout(1000) });
                return r.ok;
            } catch { return false; }
        })();
        if (localnetAlreadyUp) {
            throw new Error(
                `A localnet is already running at ${LOCALNET_URL}.\n` +
                `Please shut it down before running this test.`
            );
        }
        localnetProc = spawn('aptos', ['node', 'run-local-testnet', '--with-faucet', '--force-restart', '--assume-yes'], {
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        localnetProc.stdout?.on('data', (d: Buffer) => process.stdout.write(`  [localnet] ${d}`));
        localnetProc.stderr?.on('data', (d: Buffer) => process.stderr.write(`  [localnet] ${d}`));
        await waitFor('localnet healthy', async () => {
            try {
                const [rpc, faucet] = await Promise.all([
                    fetch(LOCALNET_URL, { signal: AbortSignal.timeout(1000) }),
                    fetch(`${FAUCET_URL}/`, { signal: AbortSignal.timeout(1000) }),
                ]);
                return rpc.ok && faucet.ok;
            } catch { return false; }
        }, 60_000, 1_000);
        console.log('  Localnet is up');

        // ── Step 1: Fund admin account ──────────────────────────────────────
        log('1', 'Fund admin account');
        const adminKey = new Ed25519PrivateKey('0x1111111111111111111111111111111111111111111111111111111111111111');
        const adminAccount = Account.fromPrivateKey({ privateKey: adminKey });
        await fundAccount(aptos, adminAccount);
        const adminAddr = adminAccount.accountAddress.toStringLong();
        const adminKeyHex = Buffer.from(adminAccount.privateKey.toUint8Array()).toString('hex');
        console.log(`  Admin: ${adminAddr}`);

        // ── Step 2: Fund Alice and Bob ──────────────────────────────────────
        log('2', 'Fund Alice and Bob');
        const aliceKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 100)));
        const bobKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 200)));
        const alice = Account.fromPrivateKey({ privateKey: aliceKey });
        const bob = Account.fromPrivateKey({ privateKey: bobKey });
        await Promise.all([fundAccount(aptos, alice), fundAccount(aptos, bob)]);
        console.log(`  Alice: ${alice.accountAddress.toStringLong()}`);
        console.log(`  Bob:   ${bob.accountAddress.toStringLong()}`);

        // ── Step 3: Deploy ACE network contract ──────────────────────────────
        log('3', 'Deploy ACE network contract');
        deployContract(CONTRACT_DIR, adminAddr, adminKeyHex);
        console.log(`  Deployed ace_network at ${adminAddr}`);

        // ── Step 4: Initialize ACE network contract ──────────────────────────
        log('4', 'Initialize ACE network contract');
        await submitTxn(aptos, adminAccount, adminAddr, 'ace_network', 'initialize', []);
        console.log('  Initialized');

        // ── Step 5: Fund all 6 worker accounts ──────────────────────────────
        log('5', `Fund ${TOTAL_WORKERS} worker accounts (epoch-0 uses 0–${NUM_WORKERS - 1}, epoch-1 uses 1–${TOTAL_WORKERS - 1})`);
        const workerKeys: Ed25519PrivateKey[] = [];
        const workerAccounts: Account[] = [];
        for (let i = 0; i < TOTAL_WORKERS; i++) {
            const key = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, j) => j + 10 + i)));
            const acc = Account.fromPrivateKey({ privateKey: key });
            await fundAccount(aptos, acc);
            workerKeys.push(key);
            workerAccounts.push(acc);
            console.log(`  Worker ${i}: ${acc.accountAddress.toStringLong()}`);
        }
        const workerAddrs = workerAccounts.map(a => a.accountAddress.toStringLong());

        // Epoch-0 committee: workers 0–3 (NUM_WORKERS = 4, threshold = THRESHOLD = 3)
        const epoch0Addrs = workerAddrs.slice(0, NUM_WORKERS);

        // Epoch-1 committee: workers 1–5 (NEW_NUM_WORKERS = 5, threshold = NEW_THRESHOLD = 3)
        // Worker 0 leaves; workers 4 and 5 join.
        const epoch1Addrs = workerAddrs.slice(1, TOTAL_WORKERS);

        // ── Step 5b: Set epoch 0 committee ───────────────────────────────────
        log('5b', `Admin calls start_initial_epoch (${NUM_WORKERS} workers, threshold=${THRESHOLD})`);
        await submitTxn(aptos, adminAccount, adminAddr, 'ace_network', 'start_initial_epoch', [
            epoch0Addrs, THRESHOLD,
        ]);
        const [epochNum] = await callView(aptos, adminAddr, 'ace_network', 'get_current_epoch', []);
        assert(Number(epochNum) === 0, `Expected epoch 0, got ${epochNum}`);
        console.log(`  Epoch 0 committee set (${NUM_WORKERS} workers, threshold=${THRESHOLD})`);

        // ── Step 6: Build and start all 6 worker processes ──────────────────
        log('6', `Build and start ${TOTAL_WORKERS} worker processes (ports ${WORKER_BASE_PORT}–${WORKER_BASE_PORT + TOTAL_WORKERS - 1})`);
        buildWorker();
        for (let i = 0; i < TOTAL_WORKERS; i++) {
            const proc = spawnWorker(workerKeys[i], WORKER_BASE_PORT + i, adminAddr);
            workers.push(proc);
        }

        log('6b', 'Wait for all workers to become healthy');
        for (let i = 0; i < TOTAL_WORKERS; i++) {
            await waitWorkerHealthy(WORKER_BASE_PORT + i);
        }
        // Give extra time for registration transactions to land.
        // Workers 4–5 are not in epoch-0 committee but still register their endpoints
        // on-chain so old members can look them up during DKR.
        await sleep(3000);

        // ── Step 7: Propose a new secret ─────────────────────────────────────
        const proposerIdx = Math.floor(Math.random() * NUM_WORKERS); // from old committee
        log('7', `Worker ${proposerIdx} proposes a new secret`);
        const specBytes = Array.from(new TextEncoder().encode(
            JSON.stringify({ scheme: 'bls12-381-ibe', description: 'test-secret-0' })
        ));
        await submitTxn(aptos, workerAccounts[proposerIdx], adminAddr, 'ace_network', 'propose_new_secret', [specBytes]);

        const proposalsResult = await callView(aptos, adminAddr, 'ace_network', 'get_pending_secret_proposals', []);
        const secretProposalAddrs = proposalsResult[0] as string[];
        assert(secretProposalAddrs.length === 1, `Expected 1 pending proposal, got ${secretProposalAddrs.length}`);
        const secretProposalAddr = secretProposalAddrs[0];
        console.log(`  Proposal created at ${secretProposalAddr}`);

        // ── Step 7b: THRESHOLD workers approve the proposal ───────────────────
        log('7b', `${THRESHOLD} workers approve the secret proposal (DKG starts when threshold reached)`);
        for (let i = 0; i < THRESHOLD; i++) {
            const approverIdx = (proposerIdx + 1 + i) % NUM_WORKERS;
            console.log(`  Worker ${approverIdx} approves`);
            await submitTxn(aptos, workerAccounts[approverIdx], adminAddr, 'ace_network', 'approve_secret_proposal', [secretProposalAddr]);
        }
        console.log('  Threshold reached — DKG record created');

        // ── Step 8: Wait for DKG completion ──────────────────────────────────
        log('8', 'Wait for workers to complete DKG and store shares');
        await waitFor('DKG done (secret_count >= 1)', async () => {
            const [count] = await callView(aptos, adminAddr, 'ace_network', 'get_secret_count', []);
            return Number(count) >= 1;
        }, 60_000);
        console.log('  DKG complete, secret_id=0 created');

        await sleep(5000);
        console.log('  Workers should have derived shares by now');

        // ── Step 9: Deploy access_control contract ────────────────────────────
        log('9', 'Deploy access_control contract');
        deployContract(ACCESS_CONTROL_CONTRACT_DIR, adminAddr, adminKeyHex, false);
        console.log(`  Deployed access_control at ${adminAddr}`);

        await submitTxn(aptos, adminAccount, adminAddr, 'access_control', 'initialize', []);
        console.log('  access_control initialized');

        // ── Step 10: Register blob (Alice as owner, Bob in allowlist) ─────────
        log('10', 'Alice registers a blob with Bob in the allowlist');
        const blobNameSuffix = 'test-blob-001';

        const regSerializer = new Serializer();
        regSerializer.serializeStr(blobNameSuffix);
        regSerializer.serializeU8(0); // SCHEME_ALLOWLIST
        regSerializer.serializeU32AsUleb128(1); // 1 address
        regSerializer.serialize(bob.accountAddress);
        const regBytes = regSerializer.toUint8Array();

        const outerSerializer = new Serializer();
        outerSerializer.serializeU32AsUleb128(1); // 1 registration
        outerSerializer.serializeFixedBytes(regBytes);
        const regsBytes = outerSerializer.toUint8Array();

        const registerTxn = await aptos.transaction.build.simple({
            sender: alice.accountAddress,
            data: {
                function: `${adminAddr}::access_control::register_blobs` as `${string}::${string}::${string}`,
                typeArguments: [],
                functionArguments: [Array.from(regsBytes)],
            },
        });
        const registerPending = await aptos.signAndSubmitTransaction({ signer: alice, transaction: registerTxn });
        await aptos.waitForTransaction({ transactionHash: registerPending.hash });
        console.log(`  Blob '${blobNameSuffix}' registered (owner=Alice, allowlist=[Bob])`);

        const fullBlobName = `@${alice.accountAddress.toStringLong().slice(2)}/${blobNameSuffix}`;
        const blobDomain = new TextEncoder().encode(fullBlobName);

        {
            const registerTxResult = await aptos.waitForTransaction({ transactionHash: registerPending.hash });
            console.log(`  [DIAG] register tx success=${registerTxResult.success} vm_status=${registerTxResult.vm_status}`);
            const diagAlice = await aptos.view({
                payload: {
                    function: `${adminAddr}::access_control::check_permission` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [alice.accountAddress, Array.from(blobDomain)],
                },
            });
            console.log(`  [DIAG] check_permission(alice=owner) = ${diagAlice[0]}`);
            const diagResult = await aptos.view({
                payload: {
                    function: `${adminAddr}::access_control::check_permission` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [bob.accountAddress, Array.from(blobDomain)],
                },
            });
            console.log(`  [DIAG] check_permission(bob) = ${diagResult[0]}`);
        }

        // ── Step 11: Alice encrypts plaintext ────────────────────────────────
        log('11', 'Alice encrypts plaintext using committee MPK');
        const plaintext = new TextEncoder().encode('Hello threshold IBE world!');

        const network: ace_threshold.AceNetwork = {
            contractAddress: adminAddr,
            chainId: CHAIN_ID,
            rpcConfig: { aptos: { localnet: { endpoint: LOCALNET_URL } } },
        };

        const encKeyResult = await ace_threshold.ThresholdEncryptionKey.fetch(network);
        assert(encKeyResult.isOk, `Failed to fetch encryption key: ${encKeyResult.errValue}`);
        const encKey = encKeyResult.okValue!;

        const contractId = ace.ContractID.newAptos({
            chainId: CHAIN_ID,
            moduleAddr: AccountAddress.fromString(adminAddr),
            moduleName: 'access_control',
            functionName: 'check_permission',
        });

        const encResult = ace_threshold.encryptThreshold({
            encryptionKey: encKey,
            contractId,
            domain: blobDomain,
            plaintext,
        });
        assert(encResult.isOk, `Encryption failed: ${encResult.errValue}`);
        const { fullDecryptionDomain, ciphertext } = encResult.okValue!;
        console.log(`  Encrypted (ciphertext hex length: ${ciphertext.toHex().length})`);

        // ── Step 12: Bob fetches partial keys and decrypts ───────────────────
        log('12', 'Bob requests partial keys and decrypts');

        const msgToSign = fullDecryptionDomain.toPrettyMessage();
        const proof = ace.ProofOfPermission.createAptos({
            userAddr: bob.accountAddress,
            publicKey: bob.publicKey,
            signature: bob.sign(msgToSign),
            fullMessage: msgToSign,
        });

        const decKeyResult = await ace_threshold.ThresholdDecryptionKey.fetch(
            network, contractId, blobDomain, proof
        );
        assert(decKeyResult.isOk, `Failed to fetch decryption key: ${JSON.stringify(decKeyResult.errValue)}`);

        const decResult = ace_threshold.decryptThreshold({ decryptionKey: decKeyResult.okValue!, ciphertext });
        assert(decResult.isOk, `Decryption failed: ${decResult.errValue}`);
        const decryptedText = new TextDecoder().decode(decResult.okValue!);
        assert(decryptedText === 'Hello threshold IBE world!', `Decrypted text mismatch: ${decryptedText}`);
        console.log(`  Bob decrypted: "${decryptedText}" ✓`);

        // ── Step 13: Propose epoch change (committee rotation) ────────────────
        // Worker 0 leaves; workers 4 and 5 join. New committee: workers 1–5, threshold 3-of-5.
        const ecProposerIdx = Math.floor(Math.random() * NUM_WORKERS); // from old committee
        log('13', `Worker ${ecProposerIdx} proposes epoch change: ${NUM_WORKERS}-of-${NUM_WORKERS} → ${NEW_THRESHOLD}-of-${NEW_NUM_WORKERS} (worker 0 leaves, workers 4–5 join)`);
        await submitTxn(aptos, workerAccounts[ecProposerIdx], adminAddr, 'ace_network', 'propose_epoch_change', [
            epoch1Addrs, NEW_THRESHOLD,
        ]);

        const ecProposalResult = await callView(aptos, adminAddr, 'ace_network', 'get_pending_epoch_change_proposal', []);
        assert(ecProposalResult[0] === true, 'Expected a pending epoch change proposal');
        const ecProposalAddr = ecProposalResult[1] as string;
        console.log(`  EpochChangeProposal created at ${ecProposalAddr}`);
        console.log(`  New committee: workers 1–5 (${epoch1Addrs.map((_, i) => i + 1).join(', ')})`);

        // ── Step 13b: OLD committee approves epoch change ─────────────────────
        log('13b', `${THRESHOLD} old-committee workers approve the epoch change proposal`);
        for (let i = 0; i < THRESHOLD; i++) {
            const approverIdx = (ecProposerIdx + 1 + i) % NUM_WORKERS; // within old committee (0–3)
            console.log(`  Worker ${approverIdx} approves`);
            await submitTxn(aptos, workerAccounts[approverIdx], adminAddr, 'ace_network', 'approve_epoch_change', [ecProposalAddr]);
        }
        console.log('  Threshold reached — DKR started');

        // ── Step 14: Wait for epoch change to complete ────────────────────────
        log('14', 'Wait for epoch change to complete (epoch → 1)');
        await waitFor('epoch 1', async () => {
            const [ep] = await callView(aptos, adminAddr, 'ace_network', 'get_current_epoch', []);
            return Number(ep) === 1;
        }, 60_000);
        console.log('  Epoch advanced to 1');

        // Wait for workers to re-derive shares at epoch 1.
        // Workers 4 and 5 compute their shares for the first time via Lagrange interpolation.
        await sleep(6000);

        // ── Step 15: Bob decrypts again after DKR ────────────────────────────
        // MPK is unchanged; shares are refreshed across a NEW committee (workers 1–5).
        // Worker 0 is no longer in the committee and is not contacted.
        log('15', 'Bob decrypts again after DKR (same MPK, new committee workers 1–5)');

        const decKey2Result = await ace_threshold.ThresholdDecryptionKey.fetch(
            network, contractId, blobDomain, proof
        );
        assert(decKey2Result.isOk, `Post-DKR decryption key fetch failed: ${JSON.stringify(decKey2Result.errValue)}`);
        const decResult2 = ace_threshold.decryptThreshold({
            decryptionKey: decKey2Result.okValue!,
            ciphertext,
        });
        assert(decResult2.isOk, `Post-DKR decryption failed: ${decResult2.errValue}`);
        const decrypted2 = new TextDecoder().decode(decResult2.okValue!);
        assert(decrypted2 === 'Hello threshold IBE world!', `Post-DKR text mismatch: ${decrypted2}`);
        console.log(`  Bob decrypted after DKR: "${decrypted2}" ✓`);

        // ── All steps passed ─────────────────────────────────────────────────
        console.log('\n✅ All tests passed!\n');

    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        console.log('\nCleaning up worker processes...');
        for (const proc of workers) {
            proc.kill('SIGTERM');
        }
        if (localnetProc) {
            console.log('Stopping localnet...');
            localnetProc.kill('SIGTERM');
        }
        for (let i = 0; i < TOTAL_WORKERS; i++) {
            const jsonPath = path.join(process.cwd(), `worker_shares_${WORKER_BASE_PORT + i}.json`);
            if (existsSync(jsonPath)) rmSync(jsonPath);
        }
        process.exit(exitCode);
    }
}

main();
