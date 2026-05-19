// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Unhappy-path test for the modern `AnyPublicKey<Keyless>` (SingleKey) wire.
 *
 * Sibling of `test-access-failures-keyless.ts`. Bob is the same
 * `KeylessAccount` built from the canonical Groth16 fixture, but the proof
 * of permission ships his pk wrapped in `AnyPublicKey` and his signature
 * wrapped in `AnySignature` — that flips the wire from bare keyless
 * (`pk_scheme=4`) to AnyPublicKey (`pk_scheme=1`, inner variant tag = 3).
 *
 * On-chain auth-key is identical between the two wires:
 *   `auth_key = SHA3-256( 0x03 || BCS(KeylessPublicKey) || 0x02 )`
 * so the same `bob.accountAddress` is the read account for both scenarios.
 * Only the proof's `pk_scheme` / `sig_scheme` tags and the outer enum
 * framing differ — everything downstream (JWK lookup, Groth16 verification,
 * EPK signature check, training-wheels) is shared with the bare-keyless
 * path via [`super::super::keyless::verify`].
 *
 * Run:
 *   cd scenarios && pnpm test-access-failures-anypub-keyless
 */

import { AnyPublicKey, AnySignature, KeylessAccount } from '@aptos-labs/ts-sdk';
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
    console.log(`  Bob (AnyPublicKey<Keyless>): ${bob.accountAddress.toStringLong()} (iss="${SAMPLE_ISS}", aud="${SAMPLE_AUD}")`);
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
            bob, bobLabel: 'AnyPublicKey<Keyless>', charlie: actors.charlie,
            // Flip the wire to pk_scheme=1 / sig_scheme=1 / inner variant tag 3
            // by wrapping Bob's bare keyless pk + sig before they reach the
            // proof of permission. Charlie's bare-Ed25519 wire (Step B) is
            // untouched — `wrap*` only fire for Bob.
            wrapBobPublicKey: (pk: any) => new AnyPublicKey(pk),
            wrapBobSignature: (sig: any) => new AnySignature(sig),
        };
        await stepA_WrongKeypair(ctx);
        await stepB_NonAllowlistedCharlie(ctx);
        await stepC_WrongDomain(ctx);
        await stepD_HappyPath(ctx);
        await stepE_MauledEpkSig(ctx);
        await stepF_MauledGroth16Proof(ctx);
        console.log('\n✅ All AnyPublicKey<Keyless> access-control enforcement tests passed!\n');
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        cleanupScenario(workers, localnetProc);
        process.exit(exitCode);
    }
}

main();
