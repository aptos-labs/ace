// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Unhappy-path step bodies for **non-keyless** Aptos account types — bare
 * Ed25519 (pk_scheme=0), and the `AnyPublicKey`/`AnySignature` family
 * (pk_scheme=1) wrapping any non-keyless inner key. Parameterised on a
 * generic `Account` signer so the same five bodies work for every variant.
 *
 * The sibling [`access-failures-steps.ts`] is the keyless-flavoured variant
 * (six steps A–F including Groth16 proof mauling).
 *
 * Step E's signature mauling is type-specific (raw Ed25519 sig vs. an
 * `AnySignature` envelope vs. a Secp256k1 sig …), so the helper takes a
 * `SignatureMauler` callback rather than hard-coding any one variant.
 */

import { Account, AccountAddress, Signature } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

import { CHAIN_ID } from './config';
import { assert } from './helpers';

/** Shared inputs every step needs: session config + the cast of users. */
export interface NonKeylessAccessFailureContext {
    aceDeployment: ACE.AceDeployment;
    moduleAddr: AccountAddress;
    moduleName: string;
    functionName: string;
    /** The keypair Alice actually encrypted PING under. */
    keypair0Id: AccountAddress;
    correctDomain: Uint8Array;
    wrongDomain: Uint8Array;
    /** `ACE.AptosBasicFlow.encrypt(..., plaintext='PING', keypair=keypair0)`. */
    pingCiph: Uint8Array;
    /** Allowlisted reader. Any `Account` — bare Ed25519, `SingleKeyAccount`,
     *  whichever the per-variant scenario constructs. */
    bob: Account;
    /** Human-readable label for Bob, printed in step descriptions
     *  (e.g. `"SingleKey/Ed25519"`). */
    bobLabel: string;
    /** Not on the allowlist. Used by Step B only. */
    charlie: Account;
}

/** Per-variant mauling logic for Step E. Receives the bob signer and the
 *  pretty-message string returned by `session.getRequestToSign()`; must
 *  return a *bad* signature of whatever shape the variant expects (e.g. an
 *  `AnySignature` wrapping a flipped-bit `Ed25519Signature`). */
export type SignatureMauler = (signer: Account, msg: string) => Signature;

function step(n: string, msg: string): void {
    console.log(`\n── Step ${n}: ${msg} ──`);
}

async function makeSession(
    ctx: NonKeylessAccessFailureContext,
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

/** Step A — nonexistent keypair ID. Workers fail-closed at the share lookup
 *  step (404). Different from the keyless variant of Step A, which uses a
 *  valid-but-wrong keypair (requires a second DKG'd secret). */
export async function decryptWithBadKeypairID(ctx: NonKeylessAccessFailureContext): Promise<void> {
    step('A', `Negative: Bob (${ctx.bobLabel}) decrypt with nonexistent keypair ID → must fail (404)`);
    const fakeKeypairId = AccountAddress.fromString('0x' + 'ab'.repeat(32));
    const session = await makeSession(ctx, { keypairId: fakeKeypairId });
    const msg = await session.getRequestToSign();
    const result = await session.decryptWithProof({
        userAddr: ctx.bob.accountAddress,
        publicKey: ctx.bob.publicKey,
        signature: ctx.bob.sign(msg),
    });
    assert(!result.isOk, `Expected decrypt to fail with nonexistent keypairId, but it succeeded`);
    console.log(`  ✓ decrypt with nonexistent keypairId correctly rejected (${result.errValue})`);
}

/** Step B — non-allowlisted user. Charlie is not on `ping-blob`'s allowlist;
 *  the permission view returns false and workers fail-closed (403). */
export async function decryptAsNonAllowlistedUser(ctx: NonKeylessAccessFailureContext): Promise<void> {
    step('B', `Negative: decrypt by Charlie (not allowlisted) → must fail (403)`);
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

/** Step C — wrong domain. Signed request commits to a domain that doesn't
 *  match any registered blob; permission view returns false (403). */
export async function decryptWithWrongDomain(ctx: NonKeylessAccessFailureContext): Promise<void> {
    step('C', `Negative: Bob (${ctx.bobLabel}) decrypt with wrong domain → must fail (403)`);
    const session = await makeSession(ctx, { domain: ctx.wrongDomain });
    const msg = await session.getRequestToSign();
    const result = await session.decryptWithProof({
        userAddr: ctx.bob.accountAddress,
        publicKey: ctx.bob.publicKey,
        signature: ctx.bob.sign(msg),
    });
    assert(!result.isOk, `Expected decrypt to fail with wrong domain, but it succeeded`);
    console.log(`  ✓ decrypt with wrong domain correctly rejected (${result.errValue})`);
}

/** Step D — positive control. Everything correct; expect plaintext "PING". */
export async function decryptWithCorrectInputs(ctx: NonKeylessAccessFailureContext): Promise<void> {
    step('D', `Positive: Bob (${ctx.bobLabel}, allowlisted) decrypts with correct inputs → must succeed`);
    const session = await makeSession(ctx);
    const msg = await session.getRequestToSign();
    const result = await session.decryptWithProof({
        userAddr: ctx.bob.accountAddress,
        publicKey: ctx.bob.publicKey,
        signature: ctx.bob.sign(msg),
    });
    assert(result.isOk, `decrypt with correct inputs failed: ${result.errValue}`);
    assert(new TextDecoder().decode(result.okValue!) === 'PING', 'PING plaintext mismatch');
    console.log(`  ✓ Bob (${ctx.bobLabel}) decrypted successfully`);
}

/** Step E — mauled signature. The caller-supplied `mauler` builds a bad
 *  signature of whatever shape this variant expects (raw Ed25519,
 *  `AnySignature<Ed25519>`, secp256k1, …). Workers must reject before
 *  reaching the on-chain auth-key / permission checks. */
export async function decryptWithMauledSignature(
    ctx: NonKeylessAccessFailureContext,
    mauler: SignatureMauler,
): Promise<void> {
    step('E', `Negative: Bob (${ctx.bobLabel}) with mauled signature → must fail`);
    const session = await makeSession(ctx);
    const msg = await session.getRequestToSign();
    const mauledSig = mauler(ctx.bob, msg);
    const result = await session.decryptWithProof({
        userAddr: ctx.bob.accountAddress,
        publicKey: ctx.bob.publicKey,
        signature: mauledSig,
    });
    assert(!result.isOk, `Expected decrypt to fail with mauled signature, but it succeeded`);
    console.log(`  ✓ decrypt with mauled signature correctly rejected (${result.errValue})`);
}

/** Convenience runner — invokes A → E in order, threading the per-variant
 *  `mauler` into Step E. */
export async function runNonKeylessAccessFailureSteps(
    ctx: NonKeylessAccessFailureContext,
    mauler: SignatureMauler,
): Promise<void> {
    await decryptWithBadKeypairID(ctx);
    await decryptAsNonAllowlistedUser(ctx);
    await decryptWithWrongDomain(ctx);
    await decryptWithCorrectInputs(ctx);
    await decryptWithMauledSignature(ctx, mauler);
}
