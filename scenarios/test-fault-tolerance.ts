// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Fault-tolerance test: one committee member is offline per epoch.
 * DKG, DKR, and decryption must still succeed with the remaining online nodes.
 *
 * Epoch layout:
 *   Epoch 0: workers 0,1,2,3  threshold=3  (n=4, threshold*2=6>4 ✓)
 *   Epoch 1: workers 1,2,3,4  threshold=3
 *
 * Offline nodes (never spawned):
 *   Worker 0: exclusive to epoch 0's committee → offline in epoch 0
 *   Worker 4: exclusive to epoch 1's committee → offline in epoch 1
 *
 * With worker 0 absent:
 *   Epoch 0 DKG: workers 1,2,3 → 3 VSS sessions ≥ threshold=3 ✓
 *   DKR-src:     workers 1,2,3 → 3 completions  ≥ threshold=3 ✓
 *   DKR VSS acks: new committee [1,2,3,4] minus worker 4 → 3 acks ≥ threshold=3 ✓
 *   Epoch 1 decrypt: workers 1,2,3 → 3 shares ≥ threshold=3 ✓
 *
 * Run:
 *   cd integration-tests && pnpm test:fault-tolerance
 */

import {
    Account,
    AccountAddress,
    Ed25519PrivateKey,
    Serializer,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { pke } from '@aptos-labs/ace-sdk';
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
    spawnNetworkNode,
} from './common/network-clients';

const TOTAL_WORKERS = 5;
const EPOCH0_WORKER_INDICES = [0, 1, 2, 3];
const EPOCH0_THRESHOLD = 3; // VSS: threshold*2=6 > 4=n ✓
const EPOCH1_WORKER_INDICES = [1, 2, 3, 4];
const EPOCH1_THRESHOLD = 3;

// Workers that are never spawned:
//   Worker 0: exclusive to epoch 0 → absent in epoch 0
//   Worker 4: exclusive to epoch 1 → absent in epoch 1
const OFFLINE_WORKERS = new Set([0, 4]);

function step(n: string | number, msg: string): void {
    console.log(`\n── Step ${n}: ${msg} ──`);
}

async function main() {
    const workers: (ChildProcess | null)[] = Array(TOTAL_WORKERS).fill(null);
    let localnetProc: ChildProcess | null = null;

    let exitCode = 0;
    try {
        const aptos = createAptos();

        step(0, 'Start fresh localnet');
        localnetProc = await startLocalnet();
        console.log('  Localnet is up');

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

        step(2, 'Deploy ACE network contracts');
        await deployContracts(adminAccount, ['pke', 'worker_config', 'group', 'fiat-shamir-transform', 'sigma-dlog-eq', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network']);
        console.log('  Contracts deployed');

        step(3, `Fund ${TOTAL_WORKERS} worker accounts`);
        const workerKeys: Ed25519PrivateKey[] = [];
        const workerAccounts: Account[] = [];
        for (let i = 0; i < TOTAL_WORKERS; i++) {
            const key = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, j) => j + 10 + i)));
            const acc = Account.fromPrivateKey({ privateKey: key });
            await fundAccount(acc.accountAddress);
            workerKeys.push(key);
            workerAccounts.push(acc);
        }

        step(4, 'Register all worker PKE keys and endpoints on-chain');
        const encKeypairs = await Promise.all(Array.from({ length: TOTAL_WORKERS }, () => pke.keygen()));
        for (let i = 0; i < TOTAL_WORKERS; i++) {
            const endpoint = `http://localhost:${WORKER_BASE_PORT + i}`;
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

        console.log(`\n  Fault injection: workers ${[...OFFLINE_WORKERS].join(',')} never spawned`);

        step(5, `Admin: start_initial_epoch (workers ${EPOCH0_WORKER_INDICES}, threshold=${EPOCH0_THRESHOLD})`);
        const epoch0Addrs = EPOCH0_WORKER_INDICES.map(i => workerAccounts[i].accountAddress.toStringLong());
        assertTxnSuccess(
            await submitTxn({
                signer: adminAccount,
                entryFunction: `${adminAddr}::network::start_initial_epoch`,
                args: [epoch0Addrs, EPOCH0_THRESHOLD, 600],
            }),
            'network::start_initial_epoch',
        );

        step(6, 'Build and spawn online worker processes (workers 1,2,3 only)');
        await buildRustWorkspace();
        for (let i = 0; i < TOTAL_WORKERS; i++) {
            if (OFFLINE_WORKERS.has(i)) {
                console.log(`  Worker ${i}: OFFLINE (not spawned)`);
                continue;
            }
            const pkeDkHex = `0x${Buffer.from(encKeypairs[i].decryptionKey.toBytes()).toString('hex')}`;
            workers[i] = spawnNetworkNode({
                runAs: workerAccounts[i],
                pkeDkHex,
                aceDeploymentAddr: adminAddr,
                aceDeploymentApi: LOCALNET_URL,
                port: WORKER_BASE_PORT + i,
            });
            console.log(`  Worker ${i}: spawned`);
        }
        await sleep(2000);

        // ── Epoch 0 ─────────────────────────────────────────────────────────────
        // Worker 0 is offline; approvers are workers 1,2,3 (all online, threshold=3).
        step(7, 'Admin proposes keypair-0 (epoch 0, worker 0 offline); workers 1,2,3 approve');
        const onlineEpoch0Workers = [1, 2, 3].map(i => workerAccounts[i]);
        await proposeAndApprove(
            onlineEpoch0Workers[0]!,
            onlineEpoch0Workers,
            adminAddr,
            serializeNewSecretProposal(1),
        );
        const adminAccountAddress = AccountAddress.fromString(adminAddr);
        await waitFor('keypair-0 DKG done', async () => {
            const stateResult = await getNetworkState(adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.secrets.length >= 1;
        }, 90_000);
        const state0 = (await getNetworkState(adminAccountAddress)).unwrapOrThrow('state read failed after keypair-0 DKG');
        const keypair0Id = state0.secrets[0]!.keypairId;
        console.log(`  Keypair-0 ID: ${keypair0Id.toStringLong()}`);
        console.log('  ✓ DKG completed with worker 0 offline');
        await sleep(10000);

        step(8, 'Deploy and initialize access_control');
        await deployContract(ACCESS_CONTROL_CONTRACT_DIR, adminAddr, adminKeyHex);
        assertTxnSuccess(
            await submitTxn({
                signer: adminAccount,
                entryFunction: `${adminAddr}::access_control::initialize`,
                args: [],
            }),
            'access_control::initialize',
        );

        step(9, 'Alice registers "ping-blob" (allowlist: [Bob])');
        {
            const regSer = new Serializer();
            regSer.serializeStr('ping-blob');
            regSer.serializeU8(0); // SCHEME_ALLOWLIST = 0
            regSer.serializeU32AsUleb128(1);
            regSer.serialize(bob.accountAddress);

            const outerSer = new Serializer();
            outerSer.serializeU32AsUleb128(1);
            outerSer.serializeFixedBytes(regSer.toUint8Array());

            const txn = await aptos.transaction.build.simple({
                sender: alice.accountAddress,
                data: {
                    function: `${adminAddr}::access_control::register_blobs` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [Array.from(outerSer.toUint8Array())],
                },
            });
            const pending = await aptos.signAndSubmitTransaction({ signer: alice, transaction: txn });
            await aptos.waitForTransaction({ transactionHash: pending.hash });
            console.log('  ping-blob registered (owner=Alice, allowlist=[Bob])');
        }

        step(10, 'Alice encrypts "PING" with keypair-0');
        const pingDomain = new TextEncoder().encode(`@${alice.accountAddress.toStringLong().slice(2)}/ping-blob`);
        const aceDeployment = new ACE.AceDeployment({
            apiEndpoint: LOCALNET_URL,
            contractAddr: adminAccountAddress,
        });
        const pingEncResult = await ACE.AptosBasicFlow.encrypt({
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

        // ── Epoch change 1→2 (CommitteeChange) ─────────────────────────────────
        // After new_secret, cur_nodes=[0,1,2,3], threshold=3. Worker 0 is still offline.
        step(11, `Epoch change 1→2 (workers ${EPOCH1_WORKER_INDICES}, threshold=${EPOCH1_THRESHOLD}, worker 4 offline)`);
        await proposeAndApprove(
            onlineEpoch0Workers[0]!,
            onlineEpoch0Workers, // workers 1,2,3 (cur_nodes minus offline worker 0)
            adminAddr,
            serializeCommitteeChangeProposal(
                EPOCH1_WORKER_INDICES.map(i => workerAccounts[i].accountAddress),
                EPOCH1_THRESHOLD,
            ),
        );
        await waitFor('epoch 2', async () => {
            const stateResult = await getNetworkState(adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.epoch === 2;
        }, 120_000);
        console.log('  ✓ DKR completed — epoch advanced to 2 (worker 4 offline)');
        await sleep(10000);

        // ── Decrypt in epoch 1 (workers 1,2,3 online, worker 4 offline) ─────────
        step(12, 'Bob decrypts "PING" (keypair-0, epoch-1 committee, worker 4 offline)');
        {
            const pingSession = await ACE.AptosBasicFlow.DecryptionSession.create({
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

        console.log('\n✅ Fault-tolerance test passed! (worker 0 offline in epoch 0, worker 4 offline in epoch 1)\n');

    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        console.log('\nCleaning up worker processes...');
        for (const proc of workers) {
            if (proc) proc.kill('SIGTERM');
        }
        if (localnetProc) {
            console.log('Stopping localnet...');
            localnetProc.kill('SIGTERM');
        }
        process.exit(exitCode);
    }
}

main();
