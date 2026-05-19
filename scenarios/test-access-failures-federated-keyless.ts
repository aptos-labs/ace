// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Unhappy-path test: decrypt failure cases, with a FEDERATED-KEYLESS signer.
 *
 * Sibling of `test-access-failures-keyless.ts`. Same six steps (A–F) via
 * the shared keyless step bodies in `common/access-failures-steps.ts`,
 * same sample Groth16 proof + JWT — but Bob is a `FederatedKeylessAccount`
 * whose RSA JWK is published at a dapp-controlled `jwk_addr` rather than
 * at `0x1::jwks::PatchedJWKs`. Exercises:
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
 * All scaffolding (base actors, ACE network bring-up, dapp deploy +
 * blob registration + PING encrypt, cleanup) lives in `scenarios/common/`.
 * The variant-specific code that remains here is the framework keyless
 * bootstrap, the federated-JWK install, and constructing Bob as a
 * `FederatedKeylessAccount`.
 *
 * Coverage:
 *   A. Bob + keypair-1 against keypair-0 ciphertext → fail.
 *   B. Charlie (ed25519, not allowlisted)          → fail (403).
 *   C. Bob + wrong domain                          → fail (403).
 *   D. Bob + correct inputs                        → success.
 *   E. Bob + mauled ephemeral signature            → fail.
 *   F. Bob + mauled Groth16 proof.a                → fail.
 *
 * Run:
 *   cd scenarios && pnpm test-access-failures-federated-keyless
 */

import { AccountAddress, FederatedKeylessAccount } from '@aptos-labs/ts-sdk';
import { ChildProcess } from 'child_process';

import {
    deployAndInitAccessControl,
    domainForBlob,
    encryptForAccessControl,
    registerAllowlistBlob,
} from './common/access-control-app';
import { runAccessFailureStepsAtoF } from './common/access-failures-steps';
import { setupAceOnLocalnet } from './common/ace-network';
import { cleanupScenario, createAptos, fundAccount } from './common/helpers';
import {
    buildBobFederatedKeylessAccount,
    installFederatedJwk,
    runFederatedKeylessFrameworkBootstrap,
} from './common/federated-keyless';
import { SAMPLE_AUD, SAMPLE_ISS } from './common/keyless-fixtures';
import { CHAIN_ID } from './common/config';

const TOTAL_WORKERS = 3;
const EPOCH0_WORKER_INDICES = [0, 1, 2];
const EPOCH0_THRESHOLD = 2;

async function buildAndFundBob(jwkAddr: AccountAddress): Promise<FederatedKeylessAccount> {
    const bob = buildBobFederatedKeylessAccount(jwkAddr);
    await fundAccount(bob.accountAddress);
    console.log(`  Bob (federated keyless): ${bob.accountAddress.toStringLong()} (iss="${SAMPLE_ISS}", aud="${SAMPLE_AUD}", jwk_addr=${bob.publicKey.jwkAddress.toStringLong()})`);
    return bob;
}

/** Deploy + initialize access_control, then install the dapp-side federated
 *  JWK at `jwk_addr=adminAddr`, then register Alice's `ping-blob` allowlist
 *  with Bob as sole reader. JWK install is keyless-specific so the canned
 *  `setupAccessControlAppAndEncryptPing` one-shot doesn't fit — call the
 *  smaller helpers individually here. */
async function setupFederatedKeylessApp(
    admin: Parameters<typeof deployAndInitAccessControl>[0],
    adminAddr: string,
    adminKeyHex: string,
    alice: Parameters<typeof registerAllowlistBlob>[1],
    bobAddr: AccountAddress,
): Promise<void> {
    await deployAndInitAccessControl(admin, adminAddr, adminKeyHex);
    await installFederatedJwk(admin);
    console.log('  Federated JWK installed (iss=test.oidc.provider, kid=test-rsa)');
    await registerAllowlistBlob(createAptos(), alice, bobAddr, adminAddr, 'ping-blob');
}

async function main(): Promise<void> {
    let workers: ChildProcess[] = [];
    let localnetProc: ChildProcess | null = null;
    let exitCode = 0;
    try {
        const setup = await setupAceOnLocalnet({
            totalWorkers: TOTAL_WORKERS, epoch0WorkerIndices: EPOCH0_WORKER_INDICES,
            epoch0Threshold: EPOCH0_THRESHOLD, fundAccount, numKeypairs: 2,
            beforeAceSetup: runFederatedKeylessFrameworkBootstrap,
        });
        localnetProc = setup.localnetProc;
        workers = setup.ace.workers;
        const { actors, ace, keypairIds: [keypair0Id, keypair1Id] } = setup;
        const bob = await buildAndFundBob(actors.admin.accountAddress);
        await setupFederatedKeylessApp(actors.admin, actors.adminAddr, actors.adminKeyHex, actors.alice, bob.accountAddress);
        const correctDomain = domainForBlob(actors.alice, 'ping-blob');
        const wrongDomain = domainForBlob(actors.alice, 'other-blob');
        const pingCiph = await encryptForAccessControl(ace.aceDeployment, ace.adminAccountAddress, keypair0Id, correctDomain, new TextEncoder().encode('PING'));
        await runAccessFailureStepsAtoF({
            aceDeployment: ace.aceDeployment, chainId: CHAIN_ID,
            moduleAddr: ace.adminAccountAddress, moduleName: 'access_control',
            functionName: 'check_permission',
            keypair0Id, keypair1Id, correctDomain, wrongDomain, pingCiph,
            bob, bobLabel: 'federated keyless', charlie: actors.charlie,
        });
        console.log('\n✅ All federated-keyless access-control enforcement tests passed!\n');
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        cleanupScenario(workers, localnetProc);
        process.exit(exitCode);
    }
}

main();
