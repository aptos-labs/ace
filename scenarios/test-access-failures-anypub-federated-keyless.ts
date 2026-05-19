// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Unhappy-path test for the modern `AnyPublicKey<FederatedKeyless>`
 * (SingleKey) wire.
 *
 * Sibling of `test-access-failures-federated-keyless.ts`. Bob is the same
 * `FederatedKeylessAccount` built from the canonical Groth16 fixture + a
 * dapp-published RSA JWK, but the proof of permission ships his pk wrapped
 * in `AnyPublicKey` and his signature wrapped in `AnySignature` — that flips
 * the wire from bare federated keyless (`pk_scheme=5`) to AnyPublicKey
 * (`pk_scheme=1`, inner variant tag = 4).
 *
 * On-chain auth-key is identical between the two wires:
 *   `auth_key = SHA3-256( 0x04 || BCS(FederatedKeylessPublicKey) || 0x02 )`
 * so the same `bob.accountAddress` is the read account for both scenarios.
 * Only the proof's `pk_scheme` / `sig_scheme` tags and the outer enum
 * framing differ — everything downstream (JWK lookup with federated
 * fallback, Groth16 verification, EPK signature check, training-wheels) is
 * shared with the bare federated-keyless path via
 * [`super::super::federated_keyless::verify`].
 *
 * Run:
 *   cd scenarios && pnpm test-access-failures-anypub-federated-keyless
 */

import {
    AccountAddress,
    AnyPublicKey,
    AnySignature,
    FederatedKeylessAccount,
} from '@aptos-labs/ts-sdk';
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
import {
    buildBobFederatedKeylessAccount,
    installFederatedJwk,
    runFederatedKeylessFrameworkBootstrap,
} from './common/federated-keyless';
import { cleanupScenario, createAptos, fundAccount } from './common/helpers';
import { SAMPLE_AUD, SAMPLE_ISS } from './common/keyless-fixtures';

const TOTAL_WORKERS = 3;
const EPOCH0_WORKER_INDICES = [0, 1, 2];
const EPOCH0_THRESHOLD = 2;

async function buildAndFundBob(jwkAddr: AccountAddress): Promise<FederatedKeylessAccount> {
    const bob = buildBobFederatedKeylessAccount(jwkAddr);
    await fundAccount(bob.accountAddress);
    console.log(`  Bob (AnyPublicKey<FederatedKeyless>): ${bob.accountAddress.toStringLong()} (iss="${SAMPLE_ISS}", aud="${SAMPLE_AUD}", jwk_addr=${bob.publicKey.jwkAddress.toStringLong()})`);
    return bob;
}

/** Deploy + initialize access_control, then install the dapp-side federated
 *  JWK at `jwk_addr=adminAddr`, then register Alice's `ping-blob` allowlist
 *  with Bob as sole reader. Same shape as the bare federated-keyless test —
 *  JWK install is keyless-specific so the canned one-shot doesn't fit. */
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
        const ctx = {
            aceDeployment: ace.aceDeployment, chainId: CHAIN_ID,
            moduleAddr: ace.adminAccountAddress, moduleName: 'access_control',
            functionName: 'check_permission',
            keypair0Id, keypair1Id, correctDomain, wrongDomain, pingCiph,
            bob, bobLabel: 'AnyPublicKey<FederatedKeyless>', charlie: actors.charlie,
            // Flip the wire to pk_scheme=1 / sig_scheme=1 / inner variant tag 4
            // by wrapping Bob's bare federated-keyless pk + sig before they
            // reach the proof of permission. Charlie's bare-Ed25519 wire
            // (Step B) is untouched — `wrap*` only fire for Bob.
            wrapBobPublicKey: (pk: any) => new AnyPublicKey(pk),
            wrapBobSignature: (sig: any) => new AnySignature(sig),
        };
        await stepA_WrongKeypair(ctx);
        await stepB_NonAllowlistedCharlie(ctx);
        await stepC_WrongDomain(ctx);
        await stepD_HappyPath(ctx);
        await stepE_MauledEpkSig(ctx);
        await stepF_MauledGroth16Proof(ctx);
        console.log('\n✅ All AnyPublicKey<FederatedKeyless> access-control enforcement tests passed!\n');
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        cleanupScenario(workers, localnetProc);
        process.exit(exitCode);
    }
}

main();
