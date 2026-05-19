// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Unhappy-path test: decrypt failure cases, with a KEYLESS signer.
 *
 * Identical 6-step shape (A–F) to `test-access-failures-federated-keyless.ts`,
 * but Bob is a regular `KeylessAccount` whose JWK lives at
 * `0x1::jwks::PatchedJWKs` (installed by `keyless-bootstrap.move`), not at a
 * dapp-controlled `FederatedJWKs`. Auth-key derives from
 * `AnyPublicKey::Keyless(pk)` (`SHA3-256(0x03 || BCS(KeylessPublicKey) || 0x02)`).
 *
 * Coverage:
 *   A. Bob (keyless) + keypair-1 against keypair-0 ciphertext → fail.
 *   B. Charlie (ed25519, not allowlisted)                     → fail (403).
 *   C. Bob (keyless) + wrong domain                           → fail (403).
 *   D. Bob (keyless) + correct inputs                         → success.
 *   E. Bob (keyless) + mauled ephemeral signature             → fail.
 *   F. Bob (keyless) + mauled Groth16 proof.a                 → fail.
 *
 * Charlie stays Ed25519 because aptos-core ships exactly one valid sample
 * Groth16 proof (devnet-groth16-keys @ 02e5675) — minting a second keyless
 * identity would require running the prover service.
 *
 * All scaffolding (base actors, ACE network bring-up, dapp deploy + blob
 * registration + PING encrypt, cleanup) lives in `scenarios/common/`. The
 * variant-specific code remaining here is the framework keyless bootstrap
 * (which clears `PatchedJWKs` and installs the test JWK + Groth16 VK +
 * `Configuration`) and constructing Bob from the keyless fixtures.
 *
 * Run:
 *   cd scenarios && pnpm test-access-failures-keyless
 */

import { KeylessAccount } from '@aptos-labs/ts-sdk';
import { ChildProcess } from 'child_process';

import {
    deployAndInitAccessControl,
    domainForBlob,
    encryptForAccessControl,
    registerAllowlistBlob,
} from './common/access-control-app';
import {
    stepA_WrongKeypair,
    stepB_NonAllowlistedCharlie,
    stepC_WrongDomain,
    stepD_HappyPath,
    stepE_MauledEpkSig,
    stepF_MauledGroth16Proof,
} from './common/access-failures-steps';
import { setupAceOnLocalnet } from './common/ace-network';
import { CHAIN_ID } from './common/config';
import { cleanupScenario, createAptos, fundAccount } from './common/helpers';
import { buildBobKeylessAccount, runKeylessFrameworkBootstrap } from './common/keyless';
import { SAMPLE_AUD, SAMPLE_ISS } from './common/keyless-fixtures';

const TOTAL_WORKERS = 3;
const EPOCH0_WORKER_INDICES = [0, 1, 2];
const EPOCH0_THRESHOLD = 2;

async function buildAndFundBob(): Promise<KeylessAccount> {
    const bob = buildBobKeylessAccount();
    await fundAccount(bob.accountAddress);
    console.log(`  Bob (keyless): ${bob.accountAddress.toStringLong()} (iss="${SAMPLE_ISS}", aud="${SAMPLE_AUD}")`);
    return bob;
}

async function main(): Promise<void> {
    let workers: ChildProcess[] = [];
    let localnetProc: ChildProcess | null = null;
    let exitCode = 0;
    try {
        const setup = await setupAceOnLocalnet({
            totalWorkers: TOTAL_WORKERS, epoch0WorkerIndices: EPOCH0_WORKER_INDICES,
            epoch0Threshold: EPOCH0_THRESHOLD, fundAccount, numKeypairs: 2,
            beforeAceSetup: runKeylessFrameworkBootstrap,
        });
        localnetProc = setup.localnetProc;
        workers = setup.ace.workers;
        const { actors, ace, keypairIds: [keypair0Id, keypair1Id] } = setup;
        const bob = await buildAndFundBob();
        await deployAndInitAccessControl(actors.admin, actors.adminAddr, actors.adminKeyHex);
        await registerAllowlistBlob(createAptos(), actors.alice, bob.accountAddress, actors.adminAddr, 'ping-blob');
        const correctDomain = domainForBlob(actors.alice, 'ping-blob');
        const wrongDomain = domainForBlob(actors.alice, 'other-blob');
        const pingCiph = await encryptForAccessControl(ace.aceDeployment, ace.adminAccountAddress, keypair0Id, correctDomain, new TextEncoder().encode('PING'));
        const ctx = {
            aceDeployment: ace.aceDeployment, chainId: CHAIN_ID,
            moduleAddr: ace.adminAccountAddress, moduleName: 'access_control',
            functionName: 'check_permission',
            keypair0Id, keypair1Id, correctDomain, wrongDomain, pingCiph,
            bob, bobLabel: 'keyless', charlie: actors.charlie,
        };
        await stepA_WrongKeypair(ctx);
        await stepB_NonAllowlistedCharlie(ctx);
        await stepC_WrongDomain(ctx);
        await stepD_HappyPath(ctx);
        await stepE_MauledEpkSig(ctx);
        await stepF_MauledGroth16Proof(ctx);
        console.log('\n✅ All keyless access-control enforcement tests passed!\n');
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        cleanupScenario(workers, localnetProc);
        process.exit(exitCode);
    }
}

main();
