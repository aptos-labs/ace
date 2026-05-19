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
 * Setup phasing (matches PR #89 review feedback):
 *   - Chain init (framework bootstrap) runs immediately after localnet is up,
 *     before any ACE work.
 *   - Two DKGs run during ACE setup. Alice encrypts with keypair-0; Step A
 *     attempts to decrypt that ciphertext using keypair-1 (a sharper test
 *     than a fake/nonexistent ID — keypair-1 really exists, shares exist,
 *     proof verifies, the decrypt math just fails because the secrets are
 *     unrelated).
 *   - The dapp-side federated JWK is published only when Bob's identity is
 *     about to be used (right alongside the access_control app setup).
 *
 * `jwk_addr` here is the admin account — convenient because admin is already
 * signing other setup txns. In a real dapp it would be a dedicated issuer
 * management account.
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
    Ed25519PrivateKey,
    Serializer,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { ChildProcess } from 'child_process';

import {
    ACCESS_CONTROL_CONTRACT_DIR,
    CHAIN_ID,
} from './common/config';
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
import { runDkg, setupAceNetworkAndWorkers } from './common/ace-network';
import {
    buildBobFederatedKeylessAccount,
    installFederatedJwk,
    runFederatedKeylessFrameworkBootstrap,
} from './common/federated-keyless';
import { SAMPLE_AUD, SAMPLE_ISS } from './common/keyless-fixtures';

const TOTAL_WORKERS = 3;
const EPOCH0_WORKER_INDICES = [0, 1, 2];
const EPOCH0_THRESHOLD = 2;

function step(n: string | number, msg: string): void {
    console.log(`\n── Step ${n}: ${msg} ──`);
}

async function main(): Promise<void> {
    let workers: ChildProcess[] = [];
    let localnetProc: ChildProcess | null = null;
    let exitCode = 0;

    try {
        // ── Phase 1: Chain init ─────────────────────────────────────────────
        // Framework-signer scope; independent of ACE. Has to settle before
        // anything else (the worker reads VK / Configuration on the hot path).
        step(0, 'Start fresh localnet');
        localnetProc = await startLocalnet();
        console.log('  Localnet is up');

        step(1, 'Framework keyless bootstrap (clear PatchedJWKs, install Groth16 VK + Configuration)');
        await runFederatedKeylessFrameworkBootstrap();

        // ── Phase 2: Account funding ────────────────────────────────────────
        step(2, 'Fund admin, Alice, Charlie (Bob funded later, after his identity is built)');
        const aptos = createAptos();
        const adminKey = new Ed25519PrivateKey('0x1111111111111111111111111111111111111111111111111111111111111111');
        const adminAccount = Account.fromPrivateKey({ privateKey: adminKey });
        const adminAddr = adminAccount.accountAddress.toStringLong();
        const adminAccountAddress = adminAccount.accountAddress;
        const adminKeyHex = Buffer.from(adminAccount.privateKey.toUint8Array()).toString('hex');

        const aliceKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 100)));
        const charlieKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + 50)));
        const alice = Account.fromPrivateKey({ privateKey: aliceKey });
        const charlie = Account.fromPrivateKey({ privateKey: charlieKey });

        await Promise.all([
            fundAccount(adminAccount.accountAddress),
            fundAccount(alice.accountAddress),
            fundAccount(charlie.accountAddress),
        ]);
        console.log(`  Admin (also jwk_addr): ${adminAddr}`);
        console.log(`  Alice:                 ${alice.accountAddress.toStringLong()}`);
        console.log(`  Charlie:               ${charlie.accountAddress.toStringLong()} (NOT on allowlist)`);

        // ── Phase 3: ACE setup ──────────────────────────────────────────────
        step(3, 'Deploy ACE network contracts');
        await deployContracts(adminAccount, ['pke', 'worker_config', 'group', 'fiat-shamir-transform', 'sigma-dlog-eq', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network']);
        console.log('  Contracts deployed');

        step(4, `ACE network bring-up: ${TOTAL_WORKERS} workers, initial committee ${EPOCH0_WORKER_INDICES}, threshold=${EPOCH0_THRESHOLD}`);
        const ace = await setupAceNetworkAndWorkers({
            adminAccount,
            totalWorkers: TOTAL_WORKERS,
            epoch0WorkerIndices: EPOCH0_WORKER_INDICES,
            epoch0Threshold: EPOCH0_THRESHOLD,
            fundAccount,
        });
        workers = ace.workers;

        step(5, 'Admin proposes keypair-0; workers 0,1 approve');
        const approvers0 = ace.epoch0WorkerAccounts.slice(0, EPOCH0_THRESHOLD);
        const keypair0Id = await runDkg({
            approvers: approvers0,
            adminAddr,
            adminAccountAddress,
            expectedSecretsCountAfter: 1,
            label: 'keypair-0',
        });
        console.log(`  Keypair-0 ID: ${keypair0Id.toStringLong()}`);

        step(6, 'Admin proposes keypair-1 (for Step A wrong-keypair test); workers 0,1 approve');
        const approvers1 = ace.epoch0WorkerAccounts.slice(0, EPOCH0_THRESHOLD);
        const keypair1Id = await runDkg({
            approvers: approvers1,
            adminAddr,
            adminAccountAddress,
            expectedSecretsCountAfter: 2,
            label: 'keypair-1',
        });
        console.log(`  Keypair-1 ID: ${keypair1Id.toStringLong()}`);
        // Give workers a moment to settle after the second DKG before issuing
        // decrypt traffic (mirrors the existing keyless scenario's pause).
        await sleep(10000);

        // ── Phase 4: App setup ──────────────────────────────────────────────
        // Build Bob now that we know his jwk_addr (= admin). Bob's account is
        // determined by his FederatedKeylessPublicKey; it doesn't yet need any
        // on-chain resource installed.
        step(7, 'Build Bob (federated keyless) and fund his auth-key-derived address');
        const bob = buildBobFederatedKeylessAccount(adminAccount.accountAddress);
        await fundAccount(bob.accountAddress);
        console.log(`  Bob (federated keyless): ${bob.accountAddress.toStringLong()} (iss="${SAMPLE_ISS}", aud="${SAMPLE_AUD}", jwk_addr=${bob.publicKey.jwkAddress.toStringLong()})`);

        step(8, 'Deploy and initialize access_control (dapp)');
        await deployContract(ACCESS_CONTROL_CONTRACT_DIR, adminAddr, adminKeyHex);
        assertTxnSuccess(
            await submitTxn({
                signer: adminAccount,
                entryFunction: `${adminAddr}::access_control::initialize`,
                args: [],
            }),
            'access_control::initialize',
        );

        step(9, `Dapp publishes FederatedJWKs at jwk_addr=${adminAddr} (just before Bob signs)`);
        await installFederatedJwk(adminAccount);
        console.log('  Federated JWK installed (iss=test.oidc.provider, kid=test-rsa)');

        step(10, 'Alice registers "ping-blob" (allowlist: [Bob only])');
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
            console.log('  ping-blob registered (owner=Alice, allowlist=[Bob-federated-keyless])');
        }

        // ── Phase 5: Encrypt + run unhappy-path tests ───────────────────────
        step(11, 'Alice encrypts "PING" with keypair-0, domain=@alice/ping-blob');
        const correctDomain = new TextEncoder().encode(`@${alice.accountAddress.toStringLong().slice(2)}/ping-blob`);
        const wrongDomain = new TextEncoder().encode(`@${alice.accountAddress.toStringLong().slice(2)}/other-blob`);
        const pingEncResult = await ACE.AptosBasicFlow.encrypt({
            aceDeployment: ace.aceDeployment,
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

        await runAccessFailureStepsAtoF({
            aceDeployment: ace.aceDeployment,
            chainId: CHAIN_ID,
            moduleAddr: adminAccountAddress,
            moduleName: 'access_control',
            functionName: 'check_permission',
            keypair0Id,
            keypair1Id,
            correctDomain,
            wrongDomain,
            pingCiph,
            bob,
            bobLabel: 'federated keyless',
            charlie,
        });

        console.log('\n✅ All federated-keyless access-control enforcement tests passed!\n');
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
