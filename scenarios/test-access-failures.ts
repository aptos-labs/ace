// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Unhappy-path test: decrypt failure cases.
 *
 * Epoch layout:
 *   Epoch 0: workers 0,1,2  threshold=2  (single epoch, no transitions)
 *
 * Test cases:
 *   A. Decrypt with a nonexistent keypair ID → must fail
 *      (workers return 404: no share for that keypairId)
 *   B. Decrypt by Charlie (not on allowlist) with correct keypairId and domain → must fail
 *      (worker returns 403: check_permission(Charlie, domain) == false)
 *   C. Decrypt with wrong domain (blob doesn't exist) → must fail
 *      (worker returns 403: check_permission(Bob, wrong-domain) == false)
 *   D. Decrypt by Bob (allowlisted) with correct keypairId and domain → must succeed
 *
 * Workers enforce all three checks before returning an IBE key share:
 *   1. Ed25519 signature over fullMessage
 *   2. On-chain auth key matches the provided public key
 *   3. on-chain view function returns true for (userAddr, domain)
 *
 * Run:
 *   cd integration-tests && pnpm test:access-failures
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
} from './config';
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
} from './helpers';
import {
    deployContract,
} from './infra';
import {
    buildRustWorkspace,
    spawnNetworkNode,
} from './network-clients';

const TOTAL_WORKERS = 3;
const EPOCH0_WORKER_INDICES = [0, 1, 2];
const EPOCH0_THRESHOLD = 2;

function step(n: string | number, msg: string): void {
    console.log(`\n── Step ${n}: ${msg} ──`);
}

async function main() {
    const workers: ChildProcess[] = [];
    let localnetProc: ChildProcess | null = null;

    let exitCode = 0;
    try {
        const aptos = createAptos();

        step(0, 'Start fresh localnet');
        localnetProc = await startLocalnet();
        console.log('  Localnet is up');

        step(1, 'Fund admin, Alice, Bob, Charlie');
        const adminKey = new Ed25519PrivateKey('0x1111111111111111111111111111111111111111111111111111111111111111');
        const adminAccount = Account.fromPrivateKey({ privateKey: adminKey });
        await fundAccount(adminAccount.accountAddress);
        const adminAddr = adminAccount.accountAddress.toStringLong();
        const adminKeyHex = Buffer.from(adminAccount.privateKey.toUint8Array()).toString('hex');
        console.log(`  Admin: ${adminAddr}`);

        const aliceKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 100)));
        const bobKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 200)));
        // Charlie: NOT on any allowlist — used for the access-denied test
        const charlieKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 50)));
        const alice = Account.fromPrivateKey({ privateKey: aliceKey });
        const bob = Account.fromPrivateKey({ privateKey: bobKey });
        const charlie = Account.fromPrivateKey({ privateKey: charlieKey });
        await Promise.all([
            fundAccount(alice.accountAddress),
            fundAccount(bob.accountAddress),
            fundAccount(charlie.accountAddress),
        ]);
        console.log(`  Alice:   ${alice.accountAddress.toStringLong()}`);
        console.log(`  Bob:     ${bob.accountAddress.toStringLong()}`);
        console.log(`  Charlie: ${charlie.accountAddress.toStringLong()} (NOT on allowlist)`);

        step(2, 'Deploy ACE network contracts');
        await deployContracts(adminAccount, ['pke', 'worker_config', 'group', 'vss', 'dkg', 'dkr', 'network']);
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

        step(4, 'Register worker PKE keys and endpoints on-chain');
        const encKeypairs = Array.from({ length: TOTAL_WORKERS }, () => pke.keygen());
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

        step(6, 'Build and spawn worker processes');
        await buildRustWorkspace();
        for (let i = 0; i < TOTAL_WORKERS; i++) {
            const pkeDkHex = `0x${Buffer.from(encKeypairs[i].decryptionKey.toBytes()).toString('hex')}`;
            workers.push(spawnNetworkNode({
                runAs: workerAccounts[i],
                pkeDkHex,
                aceContract: adminAddr,
                rpcUrl: LOCALNET_URL,
                port: WORKER_BASE_PORT + i,
            }));
        }
        await sleep(2000);

        step(7, 'Admin creates keypair-0 DKG');
        assertTxnSuccess(
            await submitTxn({
                signer: adminAccount,
                entryFunction: `${adminAddr}::network::new_secret`,
                args: [0],
            }),
            'network::new_secret (keypair-0)',
        );
        const adminAccountAddress = AccountAddress.fromString(adminAddr);
        await waitFor('keypair-0 DKG done', async () => {
            const stateResult = await getNetworkState(adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.secrets.length >= 1;
        }, 90_000);
        const state0 = (await getNetworkState(adminAccountAddress)).unwrapOrThrow('state read failed after keypair-0 DKG');
        const keypair0Id = state0.secrets[0];
        console.log(`  Keypair-0 ID: ${keypair0Id.toStringLong()}`);
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

        step(9, 'Alice registers "ping-blob" (allowlist: [Bob only])');
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

        step(10, 'Alice encrypts "PING" with keypair-0, domain=@alice/ping-blob');
        const correctDomain = new TextEncoder().encode(`@${alice.accountAddress.toStringLong().slice(2)}/ping-blob`);
        const contractId = ace_ex.ContractID.newAptos({
            chainId: CHAIN_ID,
            moduleAddr: AccountAddress.fromString(adminAddr),
            moduleName: 'access_control',
            functionName: 'check_permission',
        });
        const pingEncResult = await ace_ex.encrypt({
            keypairId: keypair0Id,
            contractId,
            domain: correctDomain,
            plaintext: new TextEncoder().encode('PING'),
            aceContract: adminAddr,
            rpcUrl: LOCALNET_URL,
        });
        assert(pingEncResult.isOk, `encrypt PING failed: ${pingEncResult.errValue}`);
        const { fullDecryptionDomain: pingFdd, ciphertext: pingCiph } = pingEncResult.okValue!;
        console.log('  Encrypted PING');

        // ── Negative A: nonexistent keypair ID ──────────────────────────────────
        step('A', 'Negative: decrypt with nonexistent keypair ID → must fail (404)');
        {
            const fakeKeypairId = AccountAddress.fromString('0x' + 'ab'.repeat(32));
            const msg = pingFdd.toPrettyMessage();
            const proof = ace_ex.ProofOfPermission.createAptos({
                userAddr: bob.accountAddress,
                publicKey: bob.publicKey,
                signature: bob.sign(msg),
                fullMessage: msg,
            });
            const result = await ace_ex.decrypt({
                keypairId: fakeKeypairId,
                contractId,
                domain: correctDomain,
                proof,
                ciphertext: pingCiph,
                aceContract: adminAddr,
                rpcUrl: LOCALNET_URL,
            });
            assert(!result.isOk, `Expected decrypt to fail with nonexistent keypairId, but it succeeded`);
            console.log(`  ✓ decrypt with nonexistent keypairId correctly rejected (${result.errValue})`);
        }

        // ── Negative B: non-allowlisted user ────────────────────────────────────
        // Charlie is NOT on the allowlist for ping-blob.
        // Worker verifies check_permission(Charlie, domain) → false → 403 FORBIDDEN.
        step('B', 'Negative: decrypt by Charlie (not allowlisted) → must fail (403)');
        {
            const msg = pingFdd.toPrettyMessage();
            const proof = ace_ex.ProofOfPermission.createAptos({
                userAddr: charlie.accountAddress,
                publicKey: charlie.publicKey,
                signature: charlie.sign(msg),
                fullMessage: msg,
            });
            const result = await ace_ex.decrypt({
                keypairId: keypair0Id,
                contractId,
                domain: correctDomain,
                proof,
                ciphertext: pingCiph,
                aceContract: adminAddr,
                rpcUrl: LOCALNET_URL,
            });
            assert(!result.isOk, `Expected decrypt to fail for non-allowlisted Charlie, but it succeeded`);
            console.log(`  ✓ decrypt by non-allowlisted Charlie correctly rejected (${result.errValue})`);
        }

        // ── Negative C: wrong domain ─────────────────────────────────────────────
        // The domain @alice/other-blob doesn't exist in the registry.
        // Worker verifies check_permission(Bob, wrong-domain) → false → 403 FORBIDDEN.
        step('C', 'Negative: decrypt with wrong domain (unregistered blob) → must fail (403)');
        {
            const wrongDomain = new TextEncoder().encode(`@${alice.accountAddress.toStringLong().slice(2)}/other-blob`);
            const msg = pingFdd.toPrettyMessage();
            const proof = ace_ex.ProofOfPermission.createAptos({
                userAddr: bob.accountAddress,
                publicKey: bob.publicKey,
                signature: bob.sign(msg),
                fullMessage: msg,
            });
            const result = await ace_ex.decrypt({
                keypairId: keypair0Id,
                contractId,
                domain: wrongDomain,
                proof,
                ciphertext: pingCiph,
                aceContract: adminAddr,
                rpcUrl: LOCALNET_URL,
            });
            assert(!result.isOk, `Expected decrypt to fail with wrong domain, but it succeeded`);
            console.log(`  ✓ decrypt with wrong domain correctly rejected (${result.errValue})`);
        }

        // ── Positive control D: correct keypairId, domain, and allowlisted user ──
        step('D', 'Positive: Bob (allowlisted) decrypts with correct keypairId and domain → must succeed');
        {
            const msg = pingFdd.toPrettyMessage();
            const proof = ace_ex.ProofOfPermission.createAptos({
                userAddr: bob.accountAddress,
                publicKey: bob.publicKey,
                signature: bob.sign(msg),
                fullMessage: msg,
            });
            const result = await ace_ex.decrypt({
                keypairId: keypair0Id,
                contractId,
                domain: correctDomain,
                proof,
                ciphertext: pingCiph,
                aceContract: adminAddr,
                rpcUrl: LOCALNET_URL,
            });
            assert(result.isOk, `decrypt with correct inputs failed: ${result.errValue}`);
            assert(new TextDecoder().decode(result.okValue!) === 'PING', 'PING plaintext mismatch');
            console.log('  ✓ Bob decrypted successfully with correct inputs');
        }

        console.log('\n✅ All access-control enforcement tests passed!\n');

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
        process.exit(exitCode);
    }
}

main();
