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
import { deployContract } from './common/infra';
import { buildRustWorkspace, spawnNetworkNodeMaybeSplit } from './common/network-clients';

const TOTAL_WORKERS = 3;
const EPOCH0_WORKER_INDICES = [0, 1, 2];
const EPOCH0_THRESHOLD = 2;

type WorkerKeypair = { encryptionKey: pke.EncryptionKey; decryptionKey: pke.DecryptionKey };

interface Accounts {
    admin: Account;
    adminAddr: string;
    adminKeyHex: string;
    alice: Account;
    bob: SingleKeyAccount;
    charlie: Account;
}

interface AceState {
    workers: ChildProcess[];
    workerAccounts: Account[];
    encKeypairs: WorkerKeypair[];
    aceDeployment: ACE.AceDeployment;
    adminAccountAddress: AccountAddress;
}

interface TestCtx {
    aceDeployment: ACE.AceDeployment;
    adminAccountAddress: AccountAddress;
    keypair0Id: AccountAddress;
    correctDomain: Uint8Array;
    wrongDomain: Uint8Array;
    pingCiph: Uint8Array;
    bob: SingleKeyAccount;
    charlie: Account;
}

function step(n: string | number, msg: string): void {
    console.log(`\n── Step ${n}: ${msg} ──`);
}

function ed25519Key(seed: number): Ed25519PrivateKey {
    return new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + seed)));
}

async function initAccounts(): Promise<Accounts> {
    step(1, 'Fund admin, Alice, Bob (SingleKey/AnyPublicKey<Ed25519>), Charlie');
    const adminKey = new Ed25519PrivateKey('0x1111111111111111111111111111111111111111111111111111111111111111');
    const admin = Account.fromPrivateKey({ privateKey: adminKey });
    const adminAddr = admin.accountAddress.toStringLong();
    const adminKeyHex = Buffer.from(admin.privateKey.toUint8Array()).toString('hex');
    const alice = Account.fromPrivateKey({ privateKey: ed25519Key(100) });
    const bob = new SingleKeyAccount({ privateKey: ed25519Key(200) });
    const charlie = Account.fromPrivateKey({ privateKey: ed25519Key(50) });
    await Promise.all([
        fundAccount(admin.accountAddress),
        fundAccount(alice.accountAddress),
        fundAccount(bob.accountAddress),
        fundAccount(charlie.accountAddress),
    ]);
    console.log(`  Admin:   ${adminAddr}`);
    console.log(`  Alice:   ${alice.accountAddress.toStringLong()}`);
    console.log(`  Bob:     ${bob.accountAddress.toStringLong()} (SingleKey)`);
    console.log(`  Charlie: ${charlie.accountAddress.toStringLong()} (NOT on allowlist)`);
    return { admin, adminAddr, adminKeyHex, alice, bob, charlie };
}

async function deployAceContracts(admin: Account): Promise<void> {
    step(2, 'Deploy ACE network contracts');
    await deployContracts(admin, ['pke', 'worker_config', 'group', 'fiat-shamir-transform', 'sigma-dlog-eq', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network']);
    console.log('  Contracts deployed');
}

async function fundWorkerAccounts(): Promise<Account[]> {
    step(3, `Fund ${TOTAL_WORKERS} worker accounts`);
    const accounts: Account[] = [];
    for (let i = 0; i < TOTAL_WORKERS; i++) {
        const acc = Account.fromPrivateKey({ privateKey: ed25519Key(10 + i) });
        await fundAccount(acc.accountAddress);
        accounts.push(acc);
    }
    return accounts;
}

async function registerWorkerKeysAndEndpoints(workerAccounts: Account[], adminAddr: string): Promise<WorkerKeypair[]> {
    step(4, 'Register worker PKE keys and endpoints on-chain');
    const encKeypairs = await Promise.all(Array.from({ length: TOTAL_WORKERS }, () => pke.keygen()));
    for (let i = 0; i < TOTAL_WORKERS; i++) {
        const endpoint = `http://localhost:${WORKER_BASE_PORT + i}`;
        assertTxnSuccess(
            await submitTxn({ signer: workerAccounts[i], entryFunction: `${adminAddr}::worker_config::register_pke_enc_key`, args: [Array.from(encKeypairs[i].encryptionKey.toBytes())] }),
            `register_pke_enc_key worker ${i}`,
        );
        assertTxnSuccess(
            await submitTxn({ signer: workerAccounts[i], entryFunction: `${adminAddr}::worker_config::register_endpoint`, args: [endpoint] }),
            `register_endpoint worker ${i}`,
        );
    }
    return encKeypairs;
}

async function startInitialEpoch(admin: Account, adminAddr: string, workerAccounts: Account[]): Promise<void> {
    step(5, `Admin: start_initial_epoch (workers ${EPOCH0_WORKER_INDICES}, threshold=${EPOCH0_THRESHOLD})`);
    const epoch0Addrs = EPOCH0_WORKER_INDICES.map(i => workerAccounts[i].accountAddress.toStringLong());
    assertTxnSuccess(
        await submitTxn({
            signer: admin,
            entryFunction: `${adminAddr}::network::start_initial_epoch`,
            args: [epoch0Addrs, EPOCH0_THRESHOLD, 600],
        }),
        'network::start_initial_epoch',
    );
}

async function spawnWorkers(workerAccounts: Account[], encKeypairs: WorkerKeypair[], adminAddr: string): Promise<ChildProcess[]> {
    step(6, 'Build and spawn worker processes');
    await buildRustWorkspace();
    const workers: ChildProcess[] = [];
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
    return workers;
}

async function runDkg0(adminAddr: string, workerAccounts: Account[], adminAccountAddress: AccountAddress): Promise<AccountAddress> {
    step(7, 'Admin proposes keypair-0; workers 0,1 approve');
    const epoch0WorkerAccounts = EPOCH0_WORKER_INDICES.map(i => workerAccounts[i]);
    const approvers = epoch0WorkerAccounts.slice(0, EPOCH0_THRESHOLD);
    await proposeAndApprove(approvers[0]!, approvers, adminAddr, serializeNewSecretProposal(1));
    await waitFor('keypair-0 DKG done', async () => {
        const r = await getNetworkState(adminAccountAddress);
        return r.isOk && r.okValue!.secrets.length >= 1;
    }, 90_000);
    const state = (await getNetworkState(adminAccountAddress)).unwrapOrThrow('state read failed after keypair-0 DKG');
    const keypair0Id = state.secrets[0]!.keypairId;
    console.log(`  Keypair-0 ID: ${keypair0Id.toStringLong()}`);
    await sleep(10000);
    return keypair0Id;
}

async function initializeAccessControl(admin: Account, adminAddr: string, adminKeyHex: string): Promise<void> {
    step(8, 'Deploy and initialize access_control');
    await deployContract(ACCESS_CONTROL_CONTRACT_DIR, adminAddr, adminKeyHex);
    assertTxnSuccess(
        await submitTxn({ signer: admin, entryFunction: `${adminAddr}::access_control::initialize`, args: [] }),
        'access_control::initialize',
    );
}

async function registerPingBlobAllowlist(accounts: Accounts): Promise<void> {
    step(9, 'Alice registers "ping-blob" (allowlist: [Bob only])');
    const regSer = new Serializer();
    regSer.serializeStr('ping-blob');
    regSer.serializeU8(0); // SCHEME_ALLOWLIST = 0
    regSer.serializeU32AsUleb128(1);
    regSer.serialize(accounts.bob.accountAddress);

    const outerSer = new Serializer();
    outerSer.serializeU32AsUleb128(1);
    outerSer.serializeFixedBytes(regSer.toUint8Array());

    const aptos = createAptos();
    const txn = await aptos.transaction.build.simple({
        sender: accounts.alice.accountAddress,
        data: {
            function: `${accounts.adminAddr}::access_control::register_blobs` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [Array.from(outerSer.toUint8Array())],
        },
    });
    const pending = await aptos.signAndSubmitTransaction({ signer: accounts.alice, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: pending.hash });
    console.log('  ping-blob registered (owner=Alice, allowlist=[Bob-SingleKey])');
}

function domainFor(alice: Account, name: string): Uint8Array {
    return new TextEncoder().encode(`@${alice.accountAddress.toStringLong().slice(2)}/${name}`);
}

async function encryptPing(aceDeployment: ACE.AceDeployment, adminAccountAddress: AccountAddress, keypair0Id: AccountAddress, domain: Uint8Array): Promise<Uint8Array> {
    step(10, 'Alice encrypts "PING" with keypair-0, domain=@alice/ping-blob');
    const result = await ACE.AptosBasicFlow.encrypt({
        aceDeployment,
        keypairId: keypair0Id,
        chainId: CHAIN_ID,
        moduleAddr: adminAccountAddress,
        moduleName: 'access_control',
        functionName: 'check_permission',
        domain,
        plaintext: new TextEncoder().encode('PING'),
    });
    assert(result.isOk, `encrypt PING failed: ${result.errValue}`);
    console.log('  Encrypted PING');
    return result.okValue!;
}

/** Builds a fresh decryption session against `ctx.pingCiph` and posts a
 *  proof using `signer.{publicKey,sign}`. Common scaffold for steps A–D. */
async function attemptDecrypt(ctx: TestCtx, keypairId: AccountAddress, domain: Uint8Array, signer: Account): Promise<ACE.Result<Uint8Array>> {
    const session = await ACE.AptosBasicFlow.DecryptionSession.create({
        aceDeployment: ctx.aceDeployment,
        keypairId,
        chainId: CHAIN_ID,
        moduleAddr: ctx.adminAccountAddress,
        moduleName: 'access_control',
        functionName: 'check_permission',
        domain,
        ciphertext: ctx.pingCiph,
    });
    const msg = await session.getRequestToSign();
    return session.decryptWithProof({
        userAddr: signer.accountAddress,
        publicKey: signer.publicKey,
        signature: signer.sign(msg),
    });
}

async function runStepA(ctx: TestCtx): Promise<void> {
    step('A', 'Negative: decrypt with nonexistent keypair ID → must fail (404)');
    const fakeKeypairId = AccountAddress.fromString('0x' + 'ab'.repeat(32));
    const result = await attemptDecrypt(ctx, fakeKeypairId, ctx.correctDomain, ctx.bob);
    assert(!result.isOk, `Expected decrypt to fail with nonexistent keypairId, but it succeeded`);
    console.log(`  ✓ decrypt with nonexistent keypairId correctly rejected (${result.errValue})`);
}

async function runStepB(ctx: TestCtx): Promise<void> {
    step('B', 'Negative: decrypt by Charlie (not allowlisted) → must fail (403)');
    const result = await attemptDecrypt(ctx, ctx.keypair0Id, ctx.correctDomain, ctx.charlie);
    assert(!result.isOk, `Expected decrypt to fail for non-allowlisted Charlie, but it succeeded`);
    console.log(`  ✓ decrypt by non-allowlisted Charlie correctly rejected (${result.errValue})`);
}

async function runStepC(ctx: TestCtx): Promise<void> {
    step('C', 'Negative: decrypt with wrong domain (unregistered blob) → must fail (403)');
    const result = await attemptDecrypt(ctx, ctx.keypair0Id, ctx.wrongDomain, ctx.bob);
    assert(!result.isOk, `Expected decrypt to fail with wrong domain, but it succeeded`);
    console.log(`  ✓ decrypt with wrong domain correctly rejected (${result.errValue})`);
}

async function runStepD(ctx: TestCtx): Promise<void> {
    step('D', 'Positive: Bob (SingleKey, allowlisted) decrypts with correct inputs → must succeed');
    const result = await attemptDecrypt(ctx, ctx.keypair0Id, ctx.correctDomain, ctx.bob);
    assert(result.isOk, `decrypt with correct inputs failed: ${result.errValue}`);
    assert(new TextDecoder().decode(result.okValue!) === 'PING', 'PING plaintext mismatch');
    console.log('  ✓ Bob (SingleKey/Ed25519) decrypted successfully');
}

async function runStepE(ctx: TestCtx): Promise<void> {
    step('E', 'Negative: Bob with mauled inner Ed25519 signature → must fail');
    const session = await ACE.AptosBasicFlow.DecryptionSession.create({
        aceDeployment: ctx.aceDeployment,
        keypairId: ctx.keypair0Id,
        chainId: CHAIN_ID,
        moduleAddr: ctx.adminAccountAddress,
        moduleName: 'access_control',
        functionName: 'check_permission',
        domain: ctx.correctDomain,
        ciphertext: ctx.pingCiph,
    });
    const msg = await session.getRequestToSign();
    const goodAny = ctx.bob.sign(msg) as AnySignature;
    const innerEd25519 = goodAny.signature as Ed25519Signature;
    const mauledBytes = new Uint8Array(innerEd25519.toUint8Array());
    mauledBytes[0] ^= 0x01;
    const mauledSig = new AnySignature(new Ed25519Signature(mauledBytes));
    const result = await session.decryptWithProof({
        userAddr: ctx.bob.accountAddress,
        publicKey: ctx.bob.publicKey,
        signature: mauledSig,
    });
    assert(!result.isOk, `Expected decrypt to fail with mauled signature, but it succeeded`);
    console.log(`  ✓ decrypt with mauled signature correctly rejected (${result.errValue})`);
}

async function bringUpAceNetwork(accounts: Accounts): Promise<AceState> {
    await deployAceContracts(accounts.admin);
    const workerAccounts = await fundWorkerAccounts();
    const encKeypairs = await registerWorkerKeysAndEndpoints(workerAccounts, accounts.adminAddr);
    await startInitialEpoch(accounts.admin, accounts.adminAddr, workerAccounts);
    const workers = await spawnWorkers(workerAccounts, encKeypairs, accounts.adminAddr);
    const adminAccountAddress = AccountAddress.fromString(accounts.adminAddr);
    const aceDeployment = new ACE.AceDeployment({
        apiEndpoint: LOCALNET_URL,
        contractAddr: adminAccountAddress,
    });
    return { workers, workerAccounts, encKeypairs, aceDeployment, adminAccountAddress };
}

async function setupApp(aptosState: AceState, accounts: Accounts): Promise<TestCtx> {
    const keypair0Id = await runDkg0(accounts.adminAddr, aptosState.workerAccounts, aptosState.adminAccountAddress);
    await initializeAccessControl(accounts.admin, accounts.adminAddr, accounts.adminKeyHex);
    await registerPingBlobAllowlist(accounts);
    const correctDomain = domainFor(accounts.alice, 'ping-blob');
    const wrongDomain = domainFor(accounts.alice, 'other-blob');
    const pingCiph = await encryptPing(aptosState.aceDeployment, aptosState.adminAccountAddress, keypair0Id, correctDomain);
    return {
        aceDeployment: aptosState.aceDeployment,
        adminAccountAddress: aptosState.adminAccountAddress,
        keypair0Id,
        correctDomain,
        wrongDomain,
        pingCiph,
        bob: accounts.bob,
        charlie: accounts.charlie,
    };
}

function cleanup(workers: ChildProcess[], localnetProc: ChildProcess | null): void {
    console.log('\nCleaning up worker processes...');
    for (const proc of workers) proc.kill('SIGTERM');
    if (localnetProc) {
        console.log('Stopping localnet...');
        localnetProc.kill('SIGTERM');
    }
}

async function main(): Promise<void> {
    let workers: ChildProcess[] = [];
    let localnetProc: ChildProcess | null = null;
    let exitCode = 0;
    try {
        step(0, 'Start fresh localnet');
        localnetProc = await startLocalnet();
        console.log('  Localnet is up');
        const accounts = await initAccounts();
        const ace = await bringUpAceNetwork(accounts);
        workers = ace.workers;
        const ctx = await setupApp(ace, accounts);
        await runStepA(ctx);
        await runStepB(ctx);
        await runStepC(ctx);
        await runStepD(ctx);
        await runStepE(ctx);
        console.log('\n✅ All AnyPublicKey<Ed25519> access-control enforcement tests passed!\n');
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        cleanup(workers, localnetProc);
        process.exit(exitCode);
    }
}

main();
