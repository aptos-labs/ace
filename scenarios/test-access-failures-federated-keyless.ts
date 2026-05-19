// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Unhappy-path test: decrypt failure cases, with a FEDERATED-KEYLESS signer.
 *
 * Sibling of `test-access-failures-keyless.ts`. Same six steps (A–F), same
 * sample Groth16 proof + JWT — but Bob is a `FederatedKeylessAccount` whose
 * RSA JWK is published at a dapp-controlled `jwk_addr` rather than at
 * `0x1::jwks::PatchedJWKs`. Exercises:
 *   1. pk_scheme=5 / sig_scheme=4 wire parsing in the worker.
 *   2. Federated auth-key derivation
 *      (`SHA3-256(0x04 || BCS(FederatedKeylessPublicKey) || 0x02)`).
 *   3. JWK lookup against `0x1::jwks::FederatedJWKs` at `jwk_addr` after the
 *      system list misses — the bootstrap script deliberately clears
 *      `PatchedJWKs` so the test fails closed if the worker only consults the
 *      system list.
 *   4. The remaining keyless invariants (Groth16, EPK expiry, JWT/header kid
 *      binding, ephemeral signature) shared with the regular keyless path.
 *
 * Setup phasing:
 *   - Chain init (framework bootstrap) runs immediately after localnet is up.
 *   - Two DKGs run during ACE setup. Alice encrypts with keypair-0; Step A
 *     decrypts using keypair-1 (keypair-1 really exists, shares exist, proof
 *     verifies — the decrypt math just fails because the secrets are unrelated).
 *   - The dapp-side federated JWK is published only when Bob's identity is
 *     about to be used (alongside the access_control app setup).
 *
 * Coverage:
 *   A. Bob (federated keyless) + keypair-1 against keypair-0 ciphertext → fail.
 *   B. Charlie (ed25519, not allowlisted)                                → fail (403).
 *   C. Bob (federated keyless) + wrong domain                            → fail (403).
 *   D. Bob (federated keyless) + correct inputs                          → success.
 *   E. Bob (federated keyless) + mauled ephemeral signature              → fail.
 *   F. Bob (federated keyless) + mauled Groth16 proof.a                  → fail.
 *
 * Run:
 *   cd scenarios && pnpm test-access-failures-federated-keyless
 */

import {
    Account,
    AccountAddress,
    Aptos,
    Ed25519PrivateKey,
    FederatedKeylessAccount,
    Serializer,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { ChildProcess } from 'child_process';

import { ACCESS_CONTROL_CONTRACT_DIR, CHAIN_ID } from './common/config';
import {
    assert,
    assertTxnSuccess,
    createAptos,
    deployContracts,
    fundAccount,
    startLocalnet,
    sleep,
    submitTxn,
} from './common/helpers';
import { deployContract } from './common/infra';
import { runAccessFailureStepsAtoF } from './common/access-failures-steps';
import { AceNetworkState, runDkg, setupAceNetworkAndWorkers } from './common/ace-network';
import {
    buildBobFederatedKeylessAccount,
    installFederatedJwk,
    runFederatedKeylessFrameworkBootstrap,
} from './common/federated-keyless';
import { SAMPLE_AUD, SAMPLE_ISS } from './common/keyless-fixtures';

const TOTAL_WORKERS = 3;
const EPOCH0_WORKER_INDICES = [0, 1, 2];
const EPOCH0_THRESHOLD = 2;

interface Accounts {
    admin: Account;
    adminAddr: string;
    adminKeyHex: string;
    alice: Account;
    charlie: Account;
}

interface KeypairIds {
    keypair0Id: AccountAddress;
    keypair1Id: AccountAddress;
}

function step(n: string | number, msg: string): void {
    console.log(`\n── Step ${n}: ${msg} ──`);
}

/** Phase 1 — chain init. Framework-signer scope; settles before any ACE work
 *  so the worker can read the Groth16 VK + Configuration on the hot path. */
async function setupChain(): Promise<ChildProcess> {
    step(0, 'Start fresh localnet');
    const localnetProc = await startLocalnet();
    console.log('  Localnet is up');

    step(1, 'Framework keyless bootstrap (clear PatchedJWKs, install Groth16 VK + Configuration)');
    await runFederatedKeylessFrameworkBootstrap();
    return localnetProc;
}

/** Phase 2 — fund the four named identities (Bob's address comes later, once
 *  his FederatedKeylessPublicKey is built). */
async function setupAccounts(): Promise<Accounts> {
    step(2, 'Fund admin, Alice, Charlie (Bob funded later, after his identity is built)');
    const adminKey = new Ed25519PrivateKey('0x1111111111111111111111111111111111111111111111111111111111111111');
    const admin = Account.fromPrivateKey({ privateKey: adminKey });
    const adminAddr = admin.accountAddress.toStringLong();
    const adminKeyHex = Buffer.from(admin.privateKey.toUint8Array()).toString('hex');

    const aliceKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 100)));
    const charlieKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 50)));
    const alice = Account.fromPrivateKey({ privateKey: aliceKey });
    const charlie = Account.fromPrivateKey({ privateKey: charlieKey });

    await Promise.all([
        fundAccount(admin.accountAddress),
        fundAccount(alice.accountAddress),
        fundAccount(charlie.accountAddress),
    ]);
    console.log(`  Admin (also jwk_addr): ${adminAddr}`);
    console.log(`  Alice:                 ${alice.accountAddress.toStringLong()}`);
    console.log(`  Charlie:               ${charlie.accountAddress.toStringLong()} (NOT on allowlist)`);
    return { admin, adminAddr, adminKeyHex, alice, charlie };
}

/** Phase 3 — deploy ACE contracts then bring up workers + initial epoch. */
async function setupAceNetwork(admin: Account): Promise<AceNetworkState> {
    step(3, 'Deploy ACE network contracts');
    await deployContracts(admin, ['pke', 'worker_config', 'group', 'fiat-shamir-transform', 'sigma-dlog-eq', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network']);
    console.log('  Contracts deployed');

    step(4, `ACE network bring-up: ${TOTAL_WORKERS} workers, initial committee ${EPOCH0_WORKER_INDICES}, threshold=${EPOCH0_THRESHOLD}`);
    return await setupAceNetworkAndWorkers({
        adminAccount: admin,
        totalWorkers: TOTAL_WORKERS,
        epoch0WorkerIndices: EPOCH0_WORKER_INDICES,
        epoch0Threshold: EPOCH0_THRESHOLD,
        fundAccount,
    });
}

/** Phase 4 — run two DKGs so both keypair-0 and keypair-1 exist on chain.
 *  Step A's "decrypt with wrong keypair" test relies on keypair-1 being real. */
async function setupKeypairs(adminAddr: string, admin: Account, ace: AceNetworkState): Promise<KeypairIds> {
    const approvers = ace.epoch0WorkerAccounts.slice(0, EPOCH0_THRESHOLD);
    step(5, 'Admin proposes keypair-0; workers 0,1 approve');
    const keypair0Id = await runDkg({
        approvers, adminAddr, adminAccountAddress: admin.accountAddress,
        expectedSecretsCountAfter: 1, label: 'keypair-0',
    });
    console.log(`  Keypair-0 ID: ${keypair0Id.toStringLong()}`);

    step(6, 'Admin proposes keypair-1 (for Step A wrong-keypair test); workers 0,1 approve');
    const keypair1Id = await runDkg({
        approvers, adminAddr, adminAccountAddress: admin.accountAddress,
        expectedSecretsCountAfter: 2, label: 'keypair-1',
    });
    console.log(`  Keypair-1 ID: ${keypair1Id.toStringLong()}`);
    // Let workers settle after the second DKG before issuing decrypt traffic.
    await sleep(10000);
    return { keypair0Id, keypair1Id };
}

/** Phase 5 — build Bob from the sample fixtures. His address derives from his
 *  FederatedKeylessPublicKey (= `jwk_addr || KeylessPublicKey`); we fund it
 *  before the access-control register-blob txn references it. */
async function buildAndFundBob(admin: Account): Promise<FederatedKeylessAccount> {
    step(7, 'Build Bob (federated keyless) and fund his auth-key-derived address');
    const bob = buildBobFederatedKeylessAccount(admin.accountAddress);
    await fundAccount(bob.accountAddress);
    console.log(`  Bob (federated keyless): ${bob.accountAddress.toStringLong()} (iss="${SAMPLE_ISS}", aud="${SAMPLE_AUD}", jwk_addr=${bob.publicKey.jwkAddress.toStringLong()})`);
    return bob;
}

/** Submit `access_control::register_blobs` from Alice with a single
 *  allowlist-style blob whose sole authorised reader is Bob. */
async function registerPingBlobAllowlist(aptos: Aptos, alice: Account, bob: Account, adminAddr: string): Promise<void> {
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
    console.log('  ping-blob registered (owner=Alice, allowlist=[Bob-federated-keyless])');
}

/** Phase 6 — app setup. Deploy + init the dapp contract, publish the federated
 *  JWK at jwk_addr, then register the allowlist blob on Bob's behalf. */
async function setupApp(args: { aptos: Aptos; accounts: Accounts; bob: Account }): Promise<void> {
    const { aptos, accounts, bob } = args;
    step(8, 'Deploy and initialize access_control (dapp)');
    await deployContract(ACCESS_CONTROL_CONTRACT_DIR, accounts.adminAddr, accounts.adminKeyHex);
    assertTxnSuccess(
        await submitTxn({
            signer: accounts.admin,
            entryFunction: `${accounts.adminAddr}::access_control::initialize`,
            args: [],
        }),
        'access_control::initialize',
    );
    step(9, `Dapp publishes FederatedJWKs at jwk_addr=${accounts.adminAddr} (just before Bob signs)`);
    await installFederatedJwk(accounts.admin);
    console.log('  Federated JWK installed (iss=test.oidc.provider, kid=test-rsa)');
    step(10, 'Alice registers "ping-blob" (allowlist: [Bob only])');
    await registerPingBlobAllowlist(aptos, accounts.alice, bob, accounts.adminAddr);
}

/** Phase 7 — Alice encrypts "PING" with keypair-0 under the correct domain.
 *  This is the ciphertext the A–F steps attempt to decrypt under varied
 *  inputs. */
async function encryptPing(ace: AceNetworkState, keypair0Id: AccountAddress, alice: Account): Promise<{ pingCiph: Uint8Array; correctDomain: Uint8Array; wrongDomain: Uint8Array }> {
    step(11, 'Alice encrypts "PING" with keypair-0, domain=@alice/ping-blob');
    const correctDomain = new TextEncoder().encode(`@${alice.accountAddress.toStringLong().slice(2)}/ping-blob`);
    const wrongDomain = new TextEncoder().encode(`@${alice.accountAddress.toStringLong().slice(2)}/other-blob`);
    const result = await ACE.AptosBasicFlow.encrypt({
        aceDeployment: ace.aceDeployment,
        keypairId: keypair0Id,
        chainId: CHAIN_ID,
        moduleAddr: ace.adminAccountAddress,
        moduleName: 'access_control',
        functionName: 'check_permission',
        domain: correctDomain,
        plaintext: new TextEncoder().encode('PING'),
    });
    assert(result.isOk, `encrypt PING failed: ${result.errValue}`);
    console.log('  Encrypted PING');
    return { pingCiph: result.okValue!, correctDomain, wrongDomain };
}

/** Tear down workers + localnet. Always runs from `main`'s finally clause. */
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
        const aptos = createAptos();
        localnetProc = await setupChain();
        const accounts = await setupAccounts();
        const ace = await setupAceNetwork(accounts.admin);
        workers = ace.workers;
        const keypairs = await setupKeypairs(accounts.adminAddr, accounts.admin, ace);
        const bob = await buildAndFundBob(accounts.admin);
        await setupApp({ aptos, accounts, bob });
        const { pingCiph, correctDomain, wrongDomain } = await encryptPing(ace, keypairs.keypair0Id, accounts.alice);
        await runAccessFailureStepsAtoF({
            aceDeployment: ace.aceDeployment, chainId: CHAIN_ID,
            moduleAddr: ace.adminAccountAddress,
            moduleName: 'access_control', functionName: 'check_permission',
            keypair0Id: keypairs.keypair0Id, keypair1Id: keypairs.keypair1Id,
            correctDomain, wrongDomain, pingCiph,
            bob, bobLabel: 'federated keyless', charlie: accounts.charlie,
        });
        console.log('\n✅ All federated-keyless access-control enforcement tests passed!\n');
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        cleanup(workers, localnetProc);
        process.exit(exitCode);
    }
}

main();
