// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Full happy-path E2E test: covers SDK, network, DKG, epoch transitions, and encrypt/decrypt.
 *
 * Epoch layout:
 *   Epoch 0: workers 0,1,2  threshold=2
 *   Epoch 1: workers 1,2,3,4  threshold=3
 *   Epoch 2: workers 2,3,4  threshold=3
 *
 * Flow:
 *   - Admin creates keypair-0 (epoch 0 DKG)
 *   - Alice encrypts "PING" for keypair-0 (allowlist: Bob)
 *   - Epoch change 0→1
 *   - Bob decrypts "PING" (keypair-0, epoch-1 committee)
 *   - Admin creates keypair-1 (epoch 1 DKG)
 *   - Epoch change 1→2
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
const EPOCH0_WORKER_INDICES = [0, 1, 2];
const EPOCH0_THRESHOLD = 2;
const EPOCH1_WORKER_INDICES = [1, 2, 3, 4];
const EPOCH1_THRESHOLD = 3;
const EPOCH2_WORKER_INDICES = [2, 3, 4];
const EPOCH2_THRESHOLD = 3;

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
        await deployContracts(adminAccount, ['pke', 'worker_config', 'group', 'fiat-shamir-transform', 'sigma-dlog-eq', 'vss', 'dkg', 'dkr', 'network']);
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
        // Must happen BEFORE start_initial_epoch: the contract validates has_pke_enc_key(node).
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
        step(5, `Admin: start_initial_epoch (workers ${EPOCH0_WORKER_INDICES}, threshold=${EPOCH0_THRESHOLD})`);
        const epoch0Addrs = EPOCH0_WORKER_INDICES.map(i => workerAccounts[i].accountAddress.toStringLong());
        assertTxnSuccess(
            await submitTxn({
                signer: adminAccount,
                entryFunction: `${adminAddr}::network::start_initial_epoch`,
                args: [epoch0Addrs, EPOCH0_THRESHOLD],
            }),
            'network::start_initial_epoch',
        );
        console.log(`  Epoch 0 committee set (workers ${EPOCH0_WORKER_INDICES}, threshold=${EPOCH0_THRESHOLD})`);

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

        // ── Step 7: Admin creates keypair-0 DKG ──────────────────────────────
        // Workers watch chain state and complete the DKG automatically (call touch() when done).
        step(7, 'Admin creates keypair-0 DKG (scheme=0, BLS12-381 G1)');
        assertTxnSuccess(
            await submitTxn({
                signer: adminAccount,
                entryFunction: `${adminAddr}::network::new_secret`,
                args: [0 /* scheme: BLS12-381 G1 */],
            }),
            'network::new_secret (keypair-0)',
        );
        const adminAccountAddress = AccountAddress.fromString(adminAddr);
        await waitFor('keypair-0 DKG done (secrets.length >= 1)', async () => {
            const stateResult = await getNetworkState(adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.secrets.length >= 1;
        }, 90_000);
        const state0 = (await getNetworkState(adminAccountAddress)).unwrapOrThrow('state read failed after keypair-0 DKG');
        const keypair0Id = state0.secrets[0];
        console.log(`  Keypair-0 ID: ${keypair0Id.toStringLong()}`);
        await sleep(30000); // workers derive shares for keypair-0

        // ── Step 8: Deploy access_control contract ────────────────────────────
        step(8, 'Deploy and initialize access_control contract');
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

        // ── Step 9: Alice registers "ping-blob" (allowlist: [Bob]) ───────────
        step(9, 'Alice registers "ping-blob" (allowlist: [Bob])');
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

        // ── Step 10: Alice encrypts "PING" with keypair-0 ────────────────────
        step(10, 'Alice encrypts "PING" with keypair-0');
        const pingDomain = new TextEncoder().encode(`@${alice.accountAddress.toStringLong().slice(2)}/ping-blob`);
        const contractId = ace_ex.ContractID.newAptos({
            chainId: CHAIN_ID,
            moduleAddr: AccountAddress.fromString(adminAddr),
            moduleName: 'access_control',
            functionName: 'check_permission',
        });

        const pingEncResult = await ace_ex.encrypt({
            keypairId: keypair0Id,
            contractId,
            domain: pingDomain,
            plaintext: new TextEncoder().encode('PING'),
            aceDeploymentAddr: adminAddr,
            aceDeploymentApi: LOCALNET_URL,
        });
        assert(pingEncResult.isOk, `encrypt PING failed: ${pingEncResult.errValue}`);
        const { fullDecryptionDomain: pingFdd, ciphertext: pingCiph } = pingEncResult.okValue!;
        console.log('  Encrypted PING');

        // ── Step 11: Epoch change 0→1 ─────────────────────────────────────────
        // Workers 1,2,3,4 form the new committee; worker 0 leaves.
        step(11, `Epoch change 0→1 (workers ${EPOCH1_WORKER_INDICES}, threshold=${EPOCH1_THRESHOLD})`);
        const epoch1Addrs = EPOCH1_WORKER_INDICES.map(i => workerAccounts[i].accountAddress.toStringLong());
        assertTxnSuccess(
            await submitTxn({
                signer: adminAccount,
                entryFunction: `${adminAddr}::network::start_epoch_change`,
                args: [epoch1Addrs, EPOCH1_THRESHOLD],
            }),
            'network::start_epoch_change (0→1)',
        );
        // Workers run DKR automatically and call touch() when done.
        await waitFor('epoch 1', async () => {
            const stateResult = await getNetworkState(adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.epoch === 1;
        }, 120_000);
        console.log('  Epoch advanced to 1');
        await sleep(30000); // workers re-derive shares for epoch-1 committee

        // ── Step 12: Bob decrypts "PING" (keypair-0, epoch-1 committee) ───────
        step(12, 'Bob decrypts "PING" (keypair-0, epoch-1 committee)');
        {
            const msgToSign = pingFdd.toPrettyMessage();
            const pingProof = ace_ex.ProofOfPermission.createAptos({
                userAddr: bob.accountAddress,
                publicKey: bob.publicKey,
                signature: bob.sign(msgToSign),
                fullMessage: msgToSign,
            });
            const pingDecResult = await ace_ex.decrypt({
                keypairId: keypair0Id,
                contractId,
                domain: pingDomain,
                proof: pingProof,
                ciphertext: pingCiph,
                aceDeploymentAddr: adminAddr,
                aceDeploymentApi: LOCALNET_URL,
            });
            assert(pingDecResult.isOk, `decrypt PING failed: ${pingDecResult.errValue}`);
            assert(new TextDecoder().decode(pingDecResult.okValue!) === 'PING', 'PING plaintext mismatch');
            console.log('  Bob decrypted PING ✓');
        }

        // ── Step 13: Admin creates keypair-1 DKG in epoch 1 ──────────────────
        step(13, 'Admin creates keypair-1 DKG in epoch 1');
        assertTxnSuccess(
            await submitTxn({
                signer: adminAccount,
                entryFunction: `${adminAddr}::network::new_secret`,
                args: [0 /* scheme: BLS12-381 G1 */],
            }),
            'network::new_secret (keypair-1)',
        );
        await waitFor('keypair-1 DKG done (secrets.length >= 2)', async () => {
            const stateResult = await getNetworkState(adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.secrets.length >= 2;
        }, 90_000);
        const state1 = (await getNetworkState(adminAccountAddress)).unwrapOrThrow('state read failed after keypair-1 DKG');
        const keypair1Id = state1.secrets[1];
        console.log(`  Keypair-1 ID: ${keypair1Id.toStringLong()}`);
        await sleep(30000); // workers derive shares for keypair-1

        // ── Step 14: Epoch change 1→2 ─────────────────────────────────────────
        // Workers 2,3,4 form the new committee; worker 1 leaves.
        step(14, `Epoch change 1→2 (workers ${EPOCH2_WORKER_INDICES}, threshold=${EPOCH2_THRESHOLD})`);
        const epoch2Addrs = EPOCH2_WORKER_INDICES.map(i => workerAccounts[i].accountAddress.toStringLong());
        assertTxnSuccess(
            await submitTxn({
                signer: adminAccount,
                entryFunction: `${adminAddr}::network::start_epoch_change`,
                args: [epoch2Addrs, EPOCH2_THRESHOLD],
            }),
            'network::start_epoch_change (1→2)',
        );
        await waitFor('epoch 2', async () => {
            const stateResult = await getNetworkState(adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.epoch === 2;
        }, 120_000);
        console.log('  Epoch advanced to 2');
        await sleep(30000); // workers re-derive shares for epoch-2 committee

        // ── Step 15: Bob registers "pong-blob" (pay-to-download) and encrypts "PONG" ──
        step(15, 'Bob registers "pong-blob" (pay-to-download, price=1) and encrypts "PONG"');
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

        const pongEncResult = await ace_ex.encrypt({
            keypairId: keypair1Id,
            contractId,
            domain: pongDomain,
            plaintext: new TextEncoder().encode('PONG'),
            aceDeploymentAddr: adminAddr,
            aceDeploymentApi: LOCALNET_URL,
        });
        assert(pongEncResult.isOk, `encrypt PONG failed: ${pongEncResult.errValue}`);
        const { fullDecryptionDomain: pongFdd, ciphertext: pongCiph } = pongEncResult.okValue!;
        console.log('  Encrypted PONG');

        // ── Step 16: Alice purchases pong-blob and decrypts "PONG" ───────────
        step(16, 'Alice purchases pong-blob and decrypts "PONG"');
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
            const pongMsg = pongFdd.toPrettyMessage();
            const pongProof = ace_ex.ProofOfPermission.createAptos({
                userAddr: alice.accountAddress,
                publicKey: alice.publicKey,
                signature: alice.sign(pongMsg),
                fullMessage: pongMsg,
            });
            const pongDecResult = await ace_ex.decrypt({
                keypairId: keypair1Id,
                contractId,
                domain: pongDomain,
                proof: pongProof,
                ciphertext: pongCiph,
                aceDeploymentAddr: adminAddr,
                aceDeploymentApi: LOCALNET_URL,
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
