// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Unhappy-path test for the modern `AnyPublicKey<Secp256r1Ecdsa>` +
 * `AnySignature<WebAuthn>` (SingleKey / passkeys) account type — Aptos
 * `pk_scheme=1` inner variant `2`, paired with `sig_scheme=1` inner variant `2`.
 *
 * Drives the new WebAuthn-flavoured SDK surface
 * (`session.getRequestToSignForWebAuthn` + `session.decryptWithWebAuthnAssertion`):
 *
 * ```ts
 * const challenge = await session.getRequestToSignForWebAuthn();
 * const cred = await navigator.credentials.get({ publicKey: { challenge, ... } });
 * const result = await session.decryptWithWebAuthnAssertion({
 *     userAddr,
 *     publicKey: walletSecp256r1Pk,
 *     authenticatorData: new Uint8Array(cred.response.authenticatorData),
 *     clientDataJSON:    new Uint8Array(cred.response.clientDataJSON),
 *     signature:         new Uint8Array(cred.response.signature), // DER
 * });
 * ```
 *
 * Real wallets call `navigator.credentials.get(...)`; this test holds a P-256
 * private key directly via [`WebAuthnSigner`] (in `common/webauthn-signer.ts`)
 * and synthesises the same three byte buffers a browser would return,
 * including a DER-encoded signature so the SDK's DER→raw decoding path is
 * exercised end-to-end.
 *
 * Coverage:
 *   A. Bob + keypair-1 against keypair-0 ciphertext → fail (TIBE decrypt fails).
 *   B. Charlie (ed25519, not allowlisted)          → fail (403).
 *   C. Bob + wrong domain                          → fail (403).
 *   D. Bob + correct inputs                        → success.
 *   E. Bob + mauled WebAuthn signature             → fail (ECDSA verification).
 *
 * Run:
 *   cd scenarios && pnpm test-access-failures-anypub-secp256r1
 */

import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { ChildProcess } from 'child_process';

import {
    domainForBlob,
    setupAccessControlAppAndEncryptPing,
} from './common/access-control-app';
import { setupAceOnLocalnet } from './common/ace-network';
import { CHAIN_ID } from './common/config';
import { assert, cleanupScenario, fundAccount } from './common/helpers';
import { WebAuthnAssertion, WebAuthnSigner } from './common/webauthn-signer';

const TOTAL_WORKERS = 3;
const EPOCH0_WORKER_INDICES = [0, 1, 2];
const EPOCH0_THRESHOLD = 2;
const BOB_KEY_SEED = 199;

interface Ctx {
    aceDeployment: ACE.AceDeployment;
    moduleAddr: AccountAddress;
    moduleName: string;
    functionName: string;
    keypair0Id: AccountAddress;
    keypair1Id: AccountAddress;
    correctDomain: Uint8Array;
    wrongDomain: Uint8Array;
    pingCiph: Uint8Array;
    bob: WebAuthnSigner;
    charlie: Account;
}

function step(n: string, msg: string): void {
    console.log(`\n── Step ${n}: ${msg} ──`);
}

async function makeSession(
    ctx: Ctx,
    overrides: { keypairId?: AccountAddress; domain?: Uint8Array } = {},
): Promise<ACE.AptosBasicFlow.DecryptionSession> {
    return ACE.AptosBasicFlow.DecryptionSession.create({
        aceDeployment: ctx.aceDeployment,
        keypairId: overrides.keypairId ?? ctx.keypair0Id,
        chainId: CHAIN_ID,
        moduleAddr: ctx.moduleAddr,
        moduleName: ctx.moduleName,
        functionName: ctx.functionName,
        domain: overrides.domain ?? ctx.correctDomain,
        ciphertext: ctx.pingCiph,
    });
}

/** Drive the 3-line WebAuthn dev flow: ask the SDK for the challenge, hand
 *  it to the signer (browser stand-in), submit the assertion. */
async function runWebAuthnDecrypt(
    ctx: Ctx,
    session: ACE.AptosBasicFlow.DecryptionSession,
    build: (challenge: Uint8Array) => WebAuthnAssertion,
): ReturnType<ACE.AptosBasicFlow.DecryptionSession['decryptWithWebAuthnAssertion']> {
    const challenge = await session.getRequestToSignForWebAuthn();
    const assertion = build(challenge);
    return session.decryptWithWebAuthnAssertion({
        userAddr: ctx.bob.accountAddress,
        publicKey: ctx.bob.publicKey,
        ...assertion,
    });
}

async function stepA_WrongKeypair(ctx: Ctx): Promise<void> {
    step('A', `Negative: Bob (AnyPublicKey<Secp256r1Ecdsa+WebAuthn>) decrypt with WRONG keypair (real DKG'd keypair-1, but PING was encrypted under keypair-0) → must fail`);
    const session = await makeSession(ctx, { keypairId: ctx.keypair1Id });
    const result = await runWebAuthnDecrypt(ctx, session, (c) => ctx.bob.buildAssertion(c));
    assert(!result.isOk, `Expected decrypt to fail when using keypair-1 against keypair-0 ciphertext, but it succeeded`);
    console.log(`  ✓ decrypt with wrong keypair correctly rejected (${result.errValue})`);
}

async function stepB_NonAllowlistedCharlie(ctx: Ctx): Promise<void> {
    step('B', `Negative: decrypt by Charlie (Ed25519, not allowlisted) → must fail (403)`);
    const session = await makeSession(ctx);
    const msg = await session.getRequestToSign();
    const result = await session.decryptWithProof({
        userAddr: ctx.charlie.accountAddress,
        publicKey: ctx.charlie.publicKey,
        signature: ctx.charlie.sign(msg),
    });
    assert(!result.isOk, `Expected decrypt to fail for non-allowlisted Charlie, but it succeeded`);
    console.log(`  ✓ decrypt by non-allowlisted Charlie correctly rejected (${result.errValue})`);
}

async function stepC_WrongDomain(ctx: Ctx): Promise<void> {
    step('C', `Negative: Bob (AnyPublicKey<Secp256r1Ecdsa+WebAuthn>) decrypt with wrong domain → must fail (403)`);
    const session = await makeSession(ctx, { domain: ctx.wrongDomain });
    const result = await runWebAuthnDecrypt(ctx, session, (c) => ctx.bob.buildAssertion(c));
    assert(!result.isOk, `Expected decrypt to fail with wrong domain, but it succeeded`);
    console.log(`  ✓ decrypt with wrong domain correctly rejected (${result.errValue})`);
}

async function stepD_HappyPath(ctx: Ctx): Promise<void> {
    step('D', `Positive: Bob (AnyPublicKey<Secp256r1Ecdsa+WebAuthn>, allowlisted) decrypts with correct inputs → must succeed`);
    const session = await makeSession(ctx);
    const result = await runWebAuthnDecrypt(ctx, session, (c) => ctx.bob.buildAssertion(c));
    assert(result.isOk, `decrypt with correct inputs failed: ${result.errValue}`);
    assert(new TextDecoder().decode(result.okValue!) === 'PING', 'PING plaintext mismatch');
    console.log(`  ✓ Bob (AnyPublicKey<Secp256r1Ecdsa+WebAuthn>) decrypted successfully`);
}

async function stepE_MauledSignature(ctx: Ctx): Promise<void> {
    step('E', `Negative: Bob (AnyPublicKey<Secp256r1Ecdsa+WebAuthn>) with mauled P-256 r||s → must fail`);
    const session = await makeSession(ctx);
    const result = await runWebAuthnDecrypt(ctx, session, (c) => ctx.bob.buildAssertionWithMauledSignature(c));
    assert(!result.isOk, `Expected decrypt to fail with mauled signature, but it succeeded`);
    console.log(`  ✓ decrypt with mauled WebAuthn signature correctly rejected (${result.errValue})`);
}

async function buildAndFundBob(): Promise<WebAuthnSigner> {
    const seed = new Uint8Array(32).map((_, i) => i + BOB_KEY_SEED);
    const bob = new WebAuthnSigner(seed);
    await fundAccount(bob.accountAddress);
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
        });
        localnetProc = setup.localnetProc;
        workers = setup.ace.workers;
        const { actors, ace, keypairIds: [keypair0Id, keypair1Id] } = setup;
        const bob = await buildAndFundBob();
        console.log(`  Bob (AnyPublicKey<Secp256r1Ecdsa+WebAuthn>): ${bob.accountAddress.toStringLong()}`);
        const { correctDomain, pingCiph } = await setupAccessControlAppAndEncryptPing(
            actors, bob.accountAddress, ace.aceDeployment, ace.adminAccountAddress, keypair0Id,
        );
        const ctx: Ctx = {
            aceDeployment: ace.aceDeployment, moduleAddr: ace.adminAccountAddress,
            moduleName: 'access_control', functionName: 'check_permission',
            keypair0Id, keypair1Id, correctDomain,
            wrongDomain: domainForBlob(actors.alice, 'other-blob'),
            pingCiph, bob, charlie: actors.charlie,
        };
        await stepA_WrongKeypair(ctx);
        await stepB_NonAllowlistedCharlie(ctx);
        await stepC_WrongDomain(ctx);
        await stepD_HappyPath(ctx);
        await stepE_MauledSignature(ctx);
        console.log('\n✅ All AnyPublicKey<Secp256r1Ecdsa+WebAuthn> access-control enforcement tests passed!\n');
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        cleanupScenario(workers, localnetProc);
        process.exit(exitCode);
    }
}

main();
