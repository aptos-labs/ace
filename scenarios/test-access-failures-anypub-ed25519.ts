// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Unhappy-path test for the modern `AnyPublicKey<Ed25519>` (SingleKey) account.
 *
 * Sibling of `test-access-failures.ts` (which exercises bare-Ed25519,
 * `pk_scheme=0`). Bob here is a `SingleKeyAccount` wrapping the same
 * Ed25519 key material, but his on-chain auth-key derives via
 *   `SHA3-256( BCS(AnyPublicKey::Ed25519(pk)) || 0x02 )`
 * rather than the legacy
 *   `SHA3-256( pk || 0x00 )`
 * — so his account address is **different** from a bare-Ed25519 account
 * using the same private key, and the worker dispatches on `pk_scheme=1` /
 * `sig_scheme=1` (the new `Any` wire path) instead of `pk_scheme=0`.
 *
 * Test cases (mirror `test-access-failures.ts`):
 *   A. Decrypt with a nonexistent keypair ID                → fail (404).
 *   B. Decrypt by Charlie (not on allowlist)                → fail (403).
 *   C. Decrypt with wrong domain (blob doesn't exist)       → fail (403).
 *   D. Decrypt by Bob (allowlisted) with correct inputs     → succeed.
 *   E. Decrypt by Bob with a mauled inner Ed25519 signature → fail.
 *
 * Run:
 *   cd scenarios && pnpm test-access-failures-anypub-ed25519
 */

import {
    Account,
    AccountAddress,
    AnySignature,
    Ed25519PrivateKey,
    Ed25519Signature,
    Serializer,
    SingleKeyAccount,
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
} from './common/helpers';
import {
    deployContract,
} from './common/infra';
import {
    buildRustWorkspace,
    spawnNetworkNodeMaybeSplit,
} from './common/network-clients';

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

        step(1, 'Fund admin, Alice, Bob (SingleKey/AnyPublicKey<Ed25519>), Charlie');
        const adminKey = new Ed25519PrivateKey('0x1111111111111111111111111111111111111111111111111111111111111111');
        const adminAccount = Account.fromPrivateKey({ privateKey: adminKey });
        await fundAccount(adminAccount.accountAddress);
        const adminAddr = adminAccount.accountAddress.toStringLong();
        const adminKeyHex = Buffer.from(adminAccount.privateKey.toUint8Array()).toString('hex');
        console.log(`  Admin: ${adminAddr}`);

        const aliceKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 100)));
        const bobKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 200)));
        const charlieKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 50)));
        const alice = Account.fromPrivateKey({ privateKey: aliceKey });
        // Bob: SingleKeyAccount, so publicKey is AnyPublicKey<Ed25519> and the
        // accountAddress derives from the SingleKey scheme (≠ bare-Ed25519).
        const bob = new SingleKeyAccount({ privateKey: bobKey });
        const charlie = Account.fromPrivateKey({ privateKey: charlieKey });
        await Promise.all([
            fundAccount(alice.accountAddress),
            fundAccount(bob.accountAddress),
            fundAccount(charlie.accountAddress),
        ]);
        console.log(`  Alice:   ${alice.accountAddress.toStringLong()}`);
        console.log(`  Bob:     ${bob.accountAddress.toStringLong()} (SingleKey)`);
        console.log(`  Charlie: ${charlie.accountAddress.toStringLong()} (NOT on allowlist)`);

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

        step(4, 'Register worker PKE keys and endpoints on-chain');
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

        step(6, 'Build and spawn worker processes');
        await buildRustWorkspace();
        for (let i = 0; i < TOTAL_WORKERS; i++) {
            const pkeDkHex = `0x${Buffer.from(encKeypairs[i].decryptionKey.toBytes()).toString('hex')}`;
            workers.push(...spawnNetworkNodeMaybeSplit({
                index: i,
                total: TOTAL_WORKERS,
                runAs: workerAccounts[i],
                pkeDkHex,
                aceDeploymentAddr: adminAddr,
                aceDeploymentApi: LOCALNET_URL,
                workerBasePort: WORKER_BASE_PORT,
            }));
        }
        await sleep(2000);

        step(7, 'Admin proposes keypair-0; workers 0,1 approve');
        const epoch0WorkerAccounts = EPOCH0_WORKER_INDICES.map(i => workerAccounts[i]);
        {
            const approvers = epoch0WorkerAccounts.slice(0, EPOCH0_THRESHOLD);
            await proposeAndApprove(approvers[0]!, approvers, adminAddr, serializeNewSecretProposal(1));
        }
        const adminAccountAddress = AccountAddress.fromString(adminAddr);
        await waitFor('keypair-0 DKG done', async () => {
            const stateResult = await getNetworkState(adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.secrets.length >= 1;
        }, 90_000);
        const state0 = (await getNetworkState(adminAccountAddress)).unwrapOrThrow('state read failed after keypair-0 DKG');
        const keypair0Id = state0.secrets[0]!.keypairId;
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
            console.log('  ping-blob registered (owner=Alice, allowlist=[Bob-SingleKey])');
        }

        step(10, 'Alice encrypts "PING" with keypair-0, domain=@alice/ping-blob');
        const correctDomain = new TextEncoder().encode(`@${alice.accountAddress.toStringLong().slice(2)}/ping-blob`);
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
            domain: correctDomain,
            plaintext: new TextEncoder().encode('PING'),
        });
        assert(pingEncResult.isOk, `encrypt PING failed: ${pingEncResult.errValue}`);
        const pingCiph = pingEncResult.okValue!;
        console.log('  Encrypted PING');

        // ── Negative A: nonexistent keypair ID ──────────────────────────────────
        step('A', 'Negative: decrypt with nonexistent keypair ID → must fail (404)');
        {
            const fakeKeypairId = AccountAddress.fromString('0x' + 'ab'.repeat(32));
            const session = await ACE.AptosBasicFlow.DecryptionSession.create({
                aceDeployment,
                keypairId: fakeKeypairId,
                chainId: CHAIN_ID,
                moduleAddr: adminAccountAddress,
                moduleName: 'access_control',
                functionName: 'check_permission',
                domain: correctDomain,
                ciphertext: pingCiph,
            });
            const msg = await session.getRequestToSign();
            const result = await session.decryptWithProof({
                userAddr: bob.accountAddress,
                publicKey: bob.publicKey,
                signature: bob.sign(msg),
            });
            assert(!result.isOk, `Expected decrypt to fail with nonexistent keypairId, but it succeeded`);
            console.log(`  ✓ decrypt with nonexistent keypairId correctly rejected (${result.errValue})`);
        }

        // ── Negative B: non-allowlisted user ────────────────────────────────────
        step('B', 'Negative: decrypt by Charlie (not allowlisted) → must fail (403)');
        {
            const session = await ACE.AptosBasicFlow.DecryptionSession.create({
                aceDeployment,
                keypairId: keypair0Id,
                chainId: CHAIN_ID,
                moduleAddr: adminAccountAddress,
                moduleName: 'access_control',
                functionName: 'check_permission',
                domain: correctDomain,
                ciphertext: pingCiph,
            });
            const msg = await session.getRequestToSign();
            const result = await session.decryptWithProof({
                userAddr: charlie.accountAddress,
                publicKey: charlie.publicKey,
                signature: charlie.sign(msg),
            });
            assert(!result.isOk, `Expected decrypt to fail for non-allowlisted Charlie, but it succeeded`);
            console.log(`  ✓ decrypt by non-allowlisted Charlie correctly rejected (${result.errValue})`);
        }

        // ── Negative C: wrong domain ─────────────────────────────────────────────
        step('C', 'Negative: decrypt with wrong domain (unregistered blob) → must fail (403)');
        {
            const wrongDomain = new TextEncoder().encode(`@${alice.accountAddress.toStringLong().slice(2)}/other-blob`);
            const session = await ACE.AptosBasicFlow.DecryptionSession.create({
                aceDeployment,
                keypairId: keypair0Id,
                chainId: CHAIN_ID,
                moduleAddr: adminAccountAddress,
                moduleName: 'access_control',
                functionName: 'check_permission',
                domain: wrongDomain,
                ciphertext: pingCiph,
            });
            const msg = await session.getRequestToSign();
            const result = await session.decryptWithProof({
                userAddr: bob.accountAddress,
                publicKey: bob.publicKey,
                signature: bob.sign(msg),
            });
            assert(!result.isOk, `Expected decrypt to fail with wrong domain, but it succeeded`);
            console.log(`  ✓ decrypt with wrong domain correctly rejected (${result.errValue})`);
        }

        // ── Positive control D: correct keypairId, domain, allowlisted user ─────
        step('D', 'Positive: Bob (SingleKey, allowlisted) decrypts with correct inputs → must succeed');
        {
            const session = await ACE.AptosBasicFlow.DecryptionSession.create({
                aceDeployment,
                keypairId: keypair0Id,
                chainId: CHAIN_ID,
                moduleAddr: adminAccountAddress,
                moduleName: 'access_control',
                functionName: 'check_permission',
                domain: correctDomain,
                ciphertext: pingCiph,
            });
            const msg = await session.getRequestToSign();
            const result = await session.decryptWithProof({
                userAddr: bob.accountAddress,
                publicKey: bob.publicKey,
                signature: bob.sign(msg),
            });
            assert(result.isOk, `decrypt with correct inputs failed: ${result.errValue}`);
            assert(new TextDecoder().decode(result.okValue!) === 'PING', 'PING plaintext mismatch');
            console.log('  ✓ Bob (SingleKey/Ed25519) decrypted successfully');
        }

        // ── Negative E: mauled inner Ed25519 signature ──────────────────────────
        // Bob is allowlisted and uses the correct keypairId + domain. The only
        // thing wrong is the inner Ed25519 signature bytes inside the AnySignature
        // wrapper. Worker must reject before reaching the on-chain auth-key /
        // permission checks.
        step('E', 'Negative: Bob with mauled inner Ed25519 signature → must fail');
        {
            const session = await ACE.AptosBasicFlow.DecryptionSession.create({
                aceDeployment,
                keypairId: keypair0Id,
                chainId: CHAIN_ID,
                moduleAddr: adminAccountAddress,
                moduleName: 'access_control',
                functionName: 'check_permission',
                domain: correctDomain,
                ciphertext: pingCiph,
            });
            const msg = await session.getRequestToSign();
            const goodAny = bob.sign(msg) as AnySignature;
            const innerEd25519 = goodAny.signature as Ed25519Signature;
            const mauledBytes = new Uint8Array(innerEd25519.toUint8Array());
            mauledBytes[0] ^= 0x01; // flip one bit
            const mauledSig = new AnySignature(new Ed25519Signature(mauledBytes));
            const result = await session.decryptWithProof({
                userAddr: bob.accountAddress,
                publicKey: bob.publicKey,
                signature: mauledSig,
            });
            assert(!result.isOk, `Expected decrypt to fail with mauled signature, but it succeeded`);
            console.log(`  ✓ decrypt with mauled signature correctly rejected (${result.errValue})`);
        }

        console.log('\n✅ All AnyPublicKey<Ed25519> access-control enforcement tests passed!\n');

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
