// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Full happy-path E2E test: covers SDK, network, DKG, epoch transitions, and encrypt/decrypt.
 *
 * Epoch layout (epoch_duration = 90 s so epoch 1 times out before any manual proposal):
 *   Epoch 0: committee {0,1,2}    threshold=2  (initial)
 *     ↓ new_secret proposal → keypair-0 DKG
 *   Epoch 1: committee {0,1,2}    threshold=2
 *     ↓ timeout (no proposal; epoch 1 expires after 90 s)
 *   Epoch 2: committee {0,1,2}    threshold=2
 *     ↓ CommitteeChange: add workers 3&4, drop worker 0
 *   Epoch 3: committee {1,2,3,4}  threshold=3
 *     ↓ new_secret proposal → keypair-1 DKG
 *   Epoch 4: committee {1,2,3,4}  threshold=3
 *     ↓ CommitteeChange: drop worker 1
 *   Epoch 5: committee {2,3,4}    threshold=3
 *
 * Flow:
 *   - Worker 0 proposes keypair-0 (epoch 0→1 DKG; workers 0,1 approve)
 *   - Epoch 1→2 auto-reshare (same committee, epoch duration expires)
 *   - Alice encrypts "PING" for keypair-0 (allowlist: Bob)
 *   - Epoch 2→3 CommitteeChange to {1,2,3,4} (workers 0,1 approve from epoch-2 committee)
 *   - Bob decrypts "PING" (keypair-0, epoch-3 committee)
 *   - Worker 1 proposes keypair-1 (epoch 3→4 DKG; workers 1,2 approve)
 *   - Epoch 4→5 CommitteeChange to {2,3,4}
 *   - Bob registers "pong-blob" (pay-to-download) and encrypts "PONG"
 *   - Alice purchases pong-blob and decrypts "PONG"
 *
 * Run:
 *   cd scenarios && pnpm full-happy-path
 */

import {
    Account,
    AccountAddress,
    Ed25519PrivateKey,
    Serializer,
} from '@aptos-labs/ts-sdk';
import { ace_ex, pke } from '@aptos-labs/ace-sdk';
import { ChildProcess } from 'child_process';

import {
    ACCESS_CONTROL_CONTRACT_DIR,
    CHAIN_ID,
    LOCALNET_URL,
    WORKER_BASE_PORT,
} from './common/config';
import {
    assertTxnSuccess,
    assert,
    sleep,
    waitFor,
    createAptos,
    fundAccount,
    submitTxn,
    deployContracts,
    startLocalnet,
    getNetworkState,
    proposeAndApprove,
    serializeNewSecretProposal,
    serializeCommitteeChangeProposal,
} from './common/helpers';
import {
    deployContract,
} from './common/infra';
import {
    buildRustWorkspace,
    killStaleNetworkNodes,
    spawnNetworkNode,
} from './common/network-clients';

const TOTAL_WORKERS = 5;
// Three overlapping committees referenced by worker indices (not epoch numbers).
const COMMITTEE_A_INDICES = [0, 1, 2];   // epochs 0, 1, 2
const COMMITTEE_A_THRESHOLD = 2;
const COMMITTEE_B_INDICES = [1, 2, 3, 4]; // epochs 3, 4
const COMMITTEE_B_THRESHOLD = 3;
const COMMITTEE_C_INDICES = [2, 3, 4];   // epoch 5
const COMMITTEE_C_THRESHOLD = 3;

// Short enough for epoch 1 to time out before the CommitteeChange proposal in step 12.
// Long enough for workers to complete the keypair-0 DKG (~30 s at n=3) before timeout.
const EPOCH_DURATION_SECS = 90;

function step(n: string | number, msg: string): void {
    console.log(`\n── Step ${n}: ${msg} ──`);
}

async function main() {
    const workers: ChildProcess[] = [];
    let localnetProc: ChildProcess | null = null;

    let exitCode = 0;
    try {
        const aptos = createAptos();

        // ── Step 0: Start a fresh localnet ──────────────────────────────────
        step(0, 'Start fresh localnet');
        localnetProc = await startLocalnet();
        console.log('  Localnet is up');

        // ── Step 1: Fund admin, Alice, Bob ───────────────────────────────────
        step(1, 'Fund admin, Alice, Bob');
        const adminKey = new Ed25519PrivateKey('0x1111111111111111111111111111111111111111111111111111111111111111');
        const adminAccount = Account.fromPrivateKey({ privateKey: adminKey });
        await fundAccount(adminAccount.accountAddress);
        const adminAddr = adminAccount.accountAddress.toStringLong();
        const adminKeyHex = Buffer.from(adminAccount.privateKey.toUint8Array()).toString('hex');
        console.log(`  Admin: ${adminAddr}`);

        const aliceKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 100)));
        const bobKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 200)));
        const alice = Account.fromPrivateKey({ privateKey: aliceKey });
        const bob = Account.fromPrivateKey({ privateKey: bobKey });
        await Promise.all([fundAccount(alice.accountAddress), fundAccount(bob.accountAddress)]);
        console.log(`  Alice: ${alice.accountAddress.toStringLong()}`);
        console.log(`  Bob:   ${bob.accountAddress.toStringLong()}`);

        // ── Step 2: Deploy ACE network contracts ─────────────────────────────
        step(2, 'Deploy ACE network contracts');
        await deployContracts(adminAccount, ['pke', 'worker_config', 'group', 'fiat-shamir-transform', 'sigma-dlog-eq', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network']);
        console.log('  Contracts deployed');

        // ── Step 3: Fund 5 worker accounts ───────────────────────────────────
        step(3, `Fund ${TOTAL_WORKERS} worker accounts`);
        const workerKeys: Ed25519PrivateKey[] = [];
        const workerAccounts: Account[] = [];
        for (let i = 0; i < TOTAL_WORKERS; i++) {
            const key = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, j) => j + 10 + i)));
            const acc = Account.fromPrivateKey({ privateKey: key });
            await fundAccount(acc.accountAddress);
            workerKeys.push(key);
            workerAccounts.push(acc);
            console.log(`  Worker ${i}: ${acc.accountAddress.toStringLong()}`);
        }

        // ── Step 4: Register all workers on-chain ────────────────────────────
        step(4, 'Register all worker PKE keys and endpoints on-chain (before start_initial_epoch)');
        const encKeypairs = Array.from({ length: TOTAL_WORKERS }, () => pke.keygen());
        for (let i = 0; i < TOTAL_WORKERS; i++) {
            const endpoint = `http://localhost:${WORKER_BASE_PORT + i}`;
            console.log(`  Registering worker ${i}: ${endpoint}`);
            assertTxnSuccess(
                await submitTxn({
                    signer: workerAccounts[i],
                    entryFunction: `${adminAddr}::worker_config::register_pke_enc_key`,
                    args: [Array.from(encKeypairs[i].encryptionKey.toBytes())],
                }),
                `register_pke_enc_key worker ${i}`,
            );
            assertTxnSuccess(
                await submitTxn({
                    signer: workerAccounts[i],
                    entryFunction: `${adminAddr}::worker_config::register_endpoint`,
                    args: [endpoint],
                }),
                `register_endpoint worker ${i}`,
            );
        }

        // ── Step 5: Admin calls start_initial_epoch (epoch 0) ────────────────
        step(5, `Admin: start_initial_epoch (committee A = workers ${COMMITTEE_A_INDICES}, threshold=${COMMITTEE_A_THRESHOLD})`);
        const committeeAAddrs = COMMITTEE_A_INDICES.map(i => workerAccounts[i].accountAddress.toStringLong());
        assertTxnSuccess(
            await submitTxn({
                signer: adminAccount,
                entryFunction: `${adminAddr}::network::start_initial_epoch`,
                args: [committeeAAddrs, COMMITTEE_A_THRESHOLD, EPOCH_DURATION_SECS],
            }),
            'network::start_initial_epoch',
        );
        console.log(`  Epoch 0 started (committee A = workers ${COMMITTEE_A_INDICES}, threshold=${COMMITTEE_A_THRESHOLD}, duration=${EPOCH_DURATION_SECS}s)`);

        // ── Step 6: Build worker binary ───────────────────────────────────────
        step(6, 'Build network-node binary');
        await buildRustWorkspace();

        // ── Step 6b: Spawn all worker processes ───────────────────────────────
        step('6b', `Spawn ${TOTAL_WORKERS} network-node processes (ports ${WORKER_BASE_PORT}–${WORKER_BASE_PORT + TOTAL_WORKERS - 1})`);
        killStaleNetworkNodes();
        for (let i = 0; i < TOTAL_WORKERS; i++) {
            const pkeDkBytes = encKeypairs[i].decryptionKey.toBytes();
            const pkeDkHex = `0x${Buffer.from(pkeDkBytes).toString('hex')}`;
            const proc = spawnNetworkNode({
                runAs: workerAccounts[i],
                pkeDkHex,
                aceDeploymentAddr: adminAddr,
                aceDeploymentApi: LOCALNET_URL,
                port: WORKER_BASE_PORT + i,
            });
            workers.push(proc);
        }

        step('6c', 'Wait for workers to initialize');
        await sleep(2000);

        // ── Step 7: Worker 0 proposes keypair-0 (new_secret, epoch 0→1) ──────
        // Proposer and approvers are all from committee A (workers 0,1,2; threshold=2).
        step(7, `Worker 0 proposes keypair-0 (scheme=0, BLS12-381 G1); workers 0,1 approve`);
        const committeeAApprovers = COMMITTEE_A_INDICES.slice(0, COMMITTEE_A_THRESHOLD).map(i => workerAccounts[i]);
        await proposeAndApprove(
            committeeAApprovers[0]!,
            committeeAApprovers,
            adminAddr,
            serializeNewSecretProposal(0),
        );
        const adminAccountAddress = AccountAddress.fromString(adminAddr);
        await waitFor('keypair-0 DKG done (epoch advances to 1)', async () => {
            const stateResult = await getNetworkState(adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.epoch === 1;
        }, 90_000);
        const state0 = (await getNetworkState(adminAccountAddress)).unwrapOrThrow('state read failed after keypair-0 DKG');
        const keypair0Id = state0.secrets[0];
        console.log(`  Keypair-0 ID: ${keypair0Id.toStringLong()}`);
        await sleep(30000); // workers derive shares for keypair-0

        // ── Step 8: Wait for epoch 1→2 auto-reshare (timeout-triggered) ──────
        // Epoch 1 has the same ${EPOCH_DURATION_SECS}s duration. Once it expires,
        // network::touch triggers a same-committee reshare with no manual proposal needed.
        step(8, `Wait for epoch 1→2 auto-reshare (epoch ${EPOCH_DURATION_SECS}s timer expires; same committee A)`);
        await waitFor('auto-reshare done (epoch advances to 2)', async () => {
            const stateResult = await getNetworkState(adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.epoch === 2;
        }, 300_000);
        console.log('  Epoch advanced to 2 (timeout-triggered reshare)');
        await sleep(10000); // workers derive shares for epoch-2 committee

        // ── Step 9: Deploy access_control contract ────────────────────────────
        step(9, 'Deploy and initialize access_control contract');
        await deployContract(ACCESS_CONTROL_CONTRACT_DIR, adminAddr, adminKeyHex);
        assertTxnSuccess(
            await submitTxn({
                signer: adminAccount,
                entryFunction: `${adminAddr}::access_control::initialize`,
                args: [],
            }),
            'access_control::initialize',
        );
        console.log('  access_control deployed and initialized');

        // ── Step 10: Alice registers "ping-blob" (allowlist: [Bob]) ──────────
        step(10, 'Alice registers "ping-blob" (allowlist: [Bob])');
        {
            const regSer = new Serializer();
            regSer.serializeStr('ping-blob');
            regSer.serializeU8(0); // SCHEME_ALLOWLIST = 0
            regSer.serializeU32AsUleb128(1); // 1 address in allowlist
            regSer.serialize(bob.accountAddress);
            const regBytes = regSer.toUint8Array();

            const outerSer = new Serializer();
            outerSer.serializeU32AsUleb128(1); // 1 registration entry
            outerSer.serializeFixedBytes(regBytes);
            const regsBytes = outerSer.toUint8Array();

            const txn = await aptos.transaction.build.simple({
                sender: alice.accountAddress,
                data: {
                    function: `${adminAddr}::access_control::register_blobs` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [Array.from(regsBytes)],
                },
            });
            const pending = await aptos.signAndSubmitTransaction({ signer: alice, transaction: txn });
            await aptos.waitForTransaction({ transactionHash: pending.hash });
            console.log('  ping-blob registered (owner=Alice, allowlist=[Bob])');
        }

        // ── Step 11: Alice encrypts "PING" with keypair-0 ────────────────────
        step(11, 'Alice encrypts "PING" with keypair-0');
        const pingDomain = new TextEncoder().encode(`@${alice.accountAddress.toStringLong().slice(2)}/ping-blob`);
        const aceDeployment = new ace_ex.AceDeployment({
            apiEndpoint: LOCALNET_URL,
            contractAddr: adminAccountAddress,
        });

        const pingEncResult = await ace_ex.aptosEncrypt({
            aceDeployment,
            keypairId: keypair0Id,
            chainId: CHAIN_ID,
            moduleAddr: adminAccountAddress,
            moduleName: 'access_control',
            functionName: 'check_permission',
            domain: pingDomain,
            plaintext: new TextEncoder().encode('PING'),
        });
        assert(pingEncResult.isOk, `encrypt PING failed: ${pingEncResult.errValue}`);
        const pingCiph = pingEncResult.okValue!;
        console.log('  Encrypted PING');

        // ── Step 12: CommitteeChange epoch 2→3 (committee B = workers 1,2,3,4) ─
        // Still in epoch 2 (committee A = {0,1,2}, threshold=2); propose and approve
        // before the epoch-2 ${EPOCH_DURATION_SECS}s timer expires.
        step(12, `Epoch 2→3 CommitteeChange to committee B = workers ${COMMITTEE_B_INDICES}, threshold=${COMMITTEE_B_THRESHOLD}`);
        await proposeAndApprove(
            committeeAApprovers[0]!,
            committeeAApprovers,
            adminAddr,
            serializeCommitteeChangeProposal(
                COMMITTEE_B_INDICES.map(i => workerAccounts[i].accountAddress),
                COMMITTEE_B_THRESHOLD,
            ),
        );
        await waitFor('epoch 3', async () => {
            const stateResult = await getNetworkState(adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.epoch === 3;
        }, 120_000);
        console.log('  Epoch advanced to 3 (committee B active)');
        await sleep(30000); // workers re-derive shares for epoch-3 committee

        // ── Step 13: Bob decrypts "PING" (keypair-0, epoch-3 committee) ───────
        step(13, 'Bob decrypts "PING" (keypair-0, epoch-3 committee)');
        {
            const pingSession = new ace_ex.AptosDecryptionSession({
                aceDeployment,
                keypairId: keypair0Id,
                chainId: CHAIN_ID,
                moduleAddr: adminAccountAddress,
                moduleName: 'access_control',
                functionName: 'check_permission',
                domain: pingDomain,
                ciphertext: pingCiph,
            });
            const pingMsgToSign = await pingSession.getRequestToSign();
            const pingDecResult = await pingSession.decryptWithProof({
                userAddr: bob.accountAddress,
                publicKey: bob.publicKey,
                signature: bob.sign(pingMsgToSign),
            });
            assert(pingDecResult.isOk, `decrypt PING failed: ${pingDecResult.errValue}`);
            assert(new TextDecoder().decode(pingDecResult.okValue!) === 'PING', 'PING plaintext mismatch');
            console.log('  Bob decrypted PING ✓');
        }

        // ── Step 14: Worker 1 proposes keypair-1 (epoch 3→4) ─────────────────
        // Proposer and approvers are from committee B (workers 1,2,3,4; threshold=3).
        step(14, 'Worker 1 proposes keypair-1 in epoch 3; workers 1,2,3 approve');
        const committeeBApprovers = COMMITTEE_B_INDICES.slice(0, COMMITTEE_B_THRESHOLD).map(i => workerAccounts[i]);
        await proposeAndApprove(
            committeeBApprovers[0]!,
            committeeBApprovers,
            adminAddr,
            serializeNewSecretProposal(0),
        );
        await waitFor('keypair-1 DKG done (epoch advances to 4)', async () => {
            const stateResult = await getNetworkState(adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.epoch === 4;
        }, 90_000);
        const state1 = (await getNetworkState(adminAccountAddress)).unwrapOrThrow('state read failed after keypair-1 DKG');
        const keypair1Id = state1.secrets[1];
        console.log(`  Keypair-1 ID: ${keypair1Id.toStringLong()}`);
        await sleep(30000); // workers derive shares for keypair-1

        // ── Step 15: CommitteeChange epoch 4→5 (committee C = workers 2,3,4) ──
        step(15, `Epoch 4→5 CommitteeChange to committee C = workers ${COMMITTEE_C_INDICES}, threshold=${COMMITTEE_C_THRESHOLD}`);
        await proposeAndApprove(
            committeeBApprovers[0]!,
            committeeBApprovers,
            adminAddr,
            serializeCommitteeChangeProposal(
                COMMITTEE_C_INDICES.map(i => workerAccounts[i].accountAddress),
                COMMITTEE_C_THRESHOLD,
            ),
        );
        await waitFor('epoch 5', async () => {
            const stateResult = await getNetworkState(adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.epoch === 5;
        }, 120_000);
        console.log('  Epoch advanced to 5 (committee C active)');
        await sleep(30000); // workers re-derive shares for epoch-5 committee

        // ── Step 16: Bob registers "pong-blob" (pay-to-download) and encrypts "PONG" ──
        step(16, 'Bob registers "pong-blob" (pay-to-download, price=1) and encrypts "PONG"');
        const pongDomain = new TextEncoder().encode(`@${bob.accountAddress.toStringLong().slice(2)}/pong-blob`);
        {
            const regSer = new Serializer();
            regSer.serializeStr('pong-blob');
            regSer.serializeU8(2); // SCHEME_PAY_TO_DOWNLOAD = 2
            regSer.serializeU64(1); // price = 1 octa
            const regBytes = regSer.toUint8Array();

            const outerSer = new Serializer();
            outerSer.serializeU32AsUleb128(1); // 1 registration entry
            outerSer.serializeFixedBytes(regBytes);
            const regsBytes = outerSer.toUint8Array();

            const txn = await aptos.transaction.build.simple({
                sender: bob.accountAddress,
                data: {
                    function: `${adminAddr}::access_control::register_blobs` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [Array.from(regsBytes)],
                },
            });
            const pending = await aptos.signAndSubmitTransaction({ signer: bob, transaction: txn });
            await aptos.waitForTransaction({ transactionHash: pending.hash });
            console.log('  pong-blob registered (owner=Bob, pay-to-download price=1)');
        }

        const pongEncResult = await ace_ex.aptosEncrypt({
            aceDeployment,
            keypairId: keypair1Id,
            chainId: CHAIN_ID,
            moduleAddr: adminAccountAddress,
            moduleName: 'access_control',
            functionName: 'check_permission',
            domain: pongDomain,
            plaintext: new TextEncoder().encode('PONG'),
        });
        assert(pongEncResult.isOk, `encrypt PONG failed: ${pongEncResult.errValue}`);
        const pongCiph = pongEncResult.okValue!;
        console.log('  Encrypted PONG');

        // ── Step 17: Alice purchases pong-blob and decrypts "PONG" ───────────
        step(17, 'Alice purchases pong-blob and decrypts "PONG"');
        assertTxnSuccess(
            await submitTxn({
                signer: alice,
                entryFunction: `${adminAddr}::access_control::init_new_buyer`,
                args: [],
            }),
            'access_control::init_new_buyer',
        );
        assertTxnSuccess(
            await submitTxn({
                signer: alice,
                entryFunction: `${adminAddr}::access_control::purchase`,
                args: [new TextDecoder().decode(pongDomain)],
            }),
            'access_control::purchase',
        );
        console.log('  Alice purchased pong-blob');

        {
            const pongSession = new ace_ex.AptosDecryptionSession({
                aceDeployment,
                keypairId: keypair1Id,
                chainId: CHAIN_ID,
                moduleAddr: adminAccountAddress,
                moduleName: 'access_control',
                functionName: 'check_permission',
                domain: pongDomain,
                ciphertext: pongCiph,
            });
            const pongMsgToSign = await pongSession.getRequestToSign();
            const pongDecResult = await pongSession.decryptWithProof({
                userAddr: alice.accountAddress,
                publicKey: alice.publicKey,
                signature: alice.sign(pongMsgToSign),
            });
            assert(pongDecResult.isOk, `decrypt PONG failed: ${pongDecResult.errValue}`);
            assert(new TextDecoder().decode(pongDecResult.okValue!) === 'PONG', 'PONG plaintext mismatch');
            console.log('  Alice decrypted PONG ✓');
        }

        console.log('\n✅ All tests passed!\n');

    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        console.log('\nCleaning up worker processes...');
        for (const proc of workers) {
            proc.kill('SIGKILL');
        }
        if (localnetProc) {
            console.log('Stopping localnet...');
            localnetProc.kill('SIGTERM');
        }
        process.exit(exitCode);
    }
}

main();
