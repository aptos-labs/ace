// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Test-step bodies for keyless / federated-keyless access-failure scenarios.
 *
 * Each step constructs a fresh `DecryptionSession`, has the configured signer
 * sign the request, and asserts the decryption outcome. Parametrised on a
 * `AccessFailureContext` so the scenario file just describes *which* signer
 * + which keypair pair to use; mauling logic for the keyless signature itself
 * is local to steps E + F.
 */

import {
    AbstractKeylessAccount,
    Account,
    AccountAddress,
    Ed25519Signature,
    EphemeralCertificate,
    EphemeralCertificateVariant,
    EphemeralSignature,
    FederatedKeylessPublicKey,
    Groth16Zkp,
    KeylessPublicKey,
    KeylessSignature,
    PublicKey,
    Signature,
    ZeroKnowledgeSig,
    ZkProof,
    ZkpVariant,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

import { assert } from './helpers';
import {
    SAMPLE_PROOF_A_HEX,
    SAMPLE_PROOF_B_HEX,
    SAMPLE_PROOF_C_HEX,
} from './keyless-fixtures';
import { buildAptosWalletFullMessage } from './aptos-wallet-message';

/** Shared inputs every step needs: session config + the cast of users. */
export interface AccessFailureContext {
    aceDeployment: ACE.AceDeployment;
    chainId: number;
    moduleAddr: AccountAddress;
    moduleName: string;
    /** The keypair that Alice actually encrypted with. */
    keypair0Id: AccountAddress;
    /** A second, valid-but-different keypair — Step A tries to decrypt the
     *  keypair-0 ciphertext with this one. */
    keypair1Id: AccountAddress;
    correctDomain: Uint8Array;
    wrongDomain: Uint8Array;
    /** Output of `ACE.AptosBasicFlow.encrypt(..., plaintext='PING', keypair=keypair0)`. */
    pingCiph: Uint8Array;
    /** The keyless-flavoured Bob (KeylessAccount or FederatedKeylessAccount).
     *  Used for Steps A, C, D, E, F. */
    bob: AbstractKeylessAccount;
    /** Human-readable label for Bob — printed in step descriptions, e.g.
     *  `"keyless"` or `"federated keyless"`. */
    bobLabel: string;
    /** A regular Ed25519 account that is NOT on the allowlist. Step B only. */
    charlie: Account;
    /** Optional transform applied to Bob's `publicKey` before the proof is
     *  constructed. Defaults to identity (bare-keyless wire, `pk_scheme=4`).
     *  The `AnyPublicKey<Keyless>` scenario sets this to
     *  `(pk) => new AnyPublicKey(pk)` to flip the wire to `pk_scheme=1` with
     *  inner variant tag `3`. Only applied to Bob — Charlie (Step B) is
     *  always sent on the bare-Ed25519 wire. */
    wrapBobPublicKey?: (pk: KeylessPublicKey | FederatedKeylessPublicKey) => PublicKey;
    /** Optional transform applied to Bob's signature. Same rationale as
     *  [`wrapBobPublicKey`] but for the signature side; the AnyPublicKey
     *  scenario passes `(sig) => new AnySignature(sig)`. The mauled sigs in
     *  Steps E/F are produced in the bare shape first, then wrapped, so the
     *  mauling helpers don't need to know about the outer envelope. */
    wrapBobSignature?: (sig: KeylessSignature) => Signature;
}

/** Returns the wrap callbacks with identity defaults — keeps the per-step
 *  bodies free of `?? identity` clutter. */
function bobWrappers(ctx: AccessFailureContext): {
    wrapPk: (pk: KeylessPublicKey | FederatedKeylessPublicKey) => PublicKey;
    wrapSig: (sig: KeylessSignature) => Signature;
} {
    return {
        wrapPk: ctx.wrapBobPublicKey ?? ((pk) => pk),
        wrapSig: ctx.wrapBobSignature ?? ((sig) => sig),
    };
}

function step(n: string, msg: string): void {
    console.log(`\n── Step ${n}: ${msg} ──`);
}

async function makeSession(
    ctx: AccessFailureContext,
    overrides: { keypairId?: AccountAddress; label?: Uint8Array } = {},
) {
    return ACE.AptosBasicFlow.DecryptionSession.create({
        aceDeployment: ctx.aceDeployment,
        keypairId: overrides.keypairId ?? ctx.keypair0Id,
        chainId: ctx.chainId,
        moduleAddr: ctx.moduleAddr,
        moduleName: ctx.moduleName,
        label: overrides.label ?? ctx.correctDomain,
        ciphertext: ctx.pingCiph,
    });
}

function walletFullMessage(
    ctx: AccessFailureContext,
    account: AccountAddress,
    message: string,
    nonce: string,
): string {
    return buildAptosWalletFullMessage({
        accountAddress: account,
        chainId: ctx.chainId,
        message,
        nonce,
    });
}

/** Step A — keypair mismatch.
 *
 * Alice encrypted with keypair-0. Bob crafts a (correctly signed) proof of
 * permission claiming `keypair1Id`. Each worker dutifully fetches its
 * keypair-1 share and runs the decrypt math — but the ciphertext was made for
 * keypair-0, so the recombined plaintext is garbage. The session-level decrypt
 * surfaces this as a failure.
 *
 * This is a sharper test than a syntactically-invalid keypair ID: keypair-1
 * exists, shares exist, the proof verifies — the failure is purely "wrong
 * key for this ciphertext".
 */
export async function stepA_WrongKeypair(ctx: AccessFailureContext): Promise<void> {
    step('A', `Negative: Bob (${ctx.bobLabel}) decrypt with WRONG keypair (real DKG'd keypair-1, but PING was encrypted under keypair-0) → must fail`);
    const { wrapPk, wrapSig } = bobWrappers(ctx);
    const session = await makeSession(ctx, { keypairId: ctx.keypair1Id });
    const msg = await session.getRequestToSign();
    const fullMessage = walletFullMessage(ctx, ctx.bob.accountAddress, msg, 'keyless-step-a');
    const result = await session.decryptWithProof({
        userAddr: ctx.bob.accountAddress,
        publicKey: wrapPk(ctx.bob.publicKey),
        signature: wrapSig(ctx.bob.sign(fullMessage)),
        fullMessage,
    });
    assert(!result.isOk, `Expected decrypt to fail when using keypair-1 against keypair-0 ciphertext, but it succeeded`);
    console.log(`  ✓ decrypt with wrong keypair (keypair-1 vs keypair-0 ciphertext) correctly rejected (${result.errValue})`);
}

/** Step B — non-allowlisted user. Charlie is plain Ed25519; the on-chain
 *  permission view returns false; workers fail-closed on the permission check
 *  before even attempting cryptographic work. */
export async function stepB_NonAllowlistedCharlie(ctx: AccessFailureContext): Promise<void> {
    step('B', 'Negative: decrypt by Charlie (Ed25519, not allowlisted) → must fail (403)');
    const session = await makeSession(ctx);
    const msg = await session.getRequestToSign();
    const fullMessage = walletFullMessage(ctx, ctx.charlie.accountAddress, msg, 'keyless-step-b');
    const result = await session.decryptWithProof({
        userAddr: ctx.charlie.accountAddress,
        publicKey: ctx.charlie.publicKey,
        signature: ctx.charlie.sign(fullMessage),
        fullMessage,
    });
    assert(!result.isOk, `Expected decrypt to fail for non-allowlisted Charlie, but it succeeded`);
    console.log(`  ✓ decrypt by non-allowlisted Charlie correctly rejected (${result.errValue})`);
}

/** Step C — wrong domain. The signed request commits to a domain that doesn't
 *  match Alice's ping-blob; permission view returns false. */
export async function stepC_WrongDomain(ctx: AccessFailureContext): Promise<void> {
    step('C', `Negative: Bob (${ctx.bobLabel}) decrypt with wrong domain → must fail (403)`);
    const { wrapPk, wrapSig } = bobWrappers(ctx);
    const session = await makeSession(ctx, { label: ctx.wrongDomain });
    const msg = await session.getRequestToSign();
    const fullMessage = walletFullMessage(ctx, ctx.bob.accountAddress, msg, 'keyless-step-c');
    const result = await session.decryptWithProof({
        userAddr: ctx.bob.accountAddress,
        publicKey: wrapPk(ctx.bob.publicKey),
        signature: wrapSig(ctx.bob.sign(fullMessage)),
        fullMessage,
    });
    assert(!result.isOk, `Expected decrypt to fail with wrong domain, but it succeeded`);
    console.log(`  ✓ decrypt with wrong domain correctly rejected (${result.errValue})`);
}

/** Step D — positive control. Everything correct; expect plaintext "PING". */
export async function stepD_HappyPath(ctx: AccessFailureContext): Promise<void> {
    step('D', `Positive: Bob (${ctx.bobLabel}, allowlisted) decrypts with correct inputs → must succeed`);
    const { wrapPk, wrapSig } = bobWrappers(ctx);
    const session = await makeSession(ctx);
    const msg = await session.getRequestToSign();
    const fullMessage = walletFullMessage(ctx, ctx.bob.accountAddress, msg, 'keyless-step-d');
    const result = await session.decryptWithProof({
        userAddr: ctx.bob.accountAddress,
        publicKey: wrapPk(ctx.bob.publicKey),
        signature: wrapSig(ctx.bob.sign(fullMessage)),
        fullMessage,
    });
    assert(result.isOk, `decrypt with correct inputs failed: ${result.errValue}`);
    assert(new TextDecoder().decode(result.okValue!) === 'PING', 'PING plaintext mismatch');
    console.log(`  ✓ Bob (${ctx.bobLabel}) decrypted successfully with correct inputs`);
}

/** Step E — mauled ephemeral signature. Everything in the `KeylessSignature`
 *  is valid except the inner Ed25519 bytes over the pretty message. Worker
 *  must reject in its ephemeral-sig verification step. */
export async function stepE_MauledEpkSig(ctx: AccessFailureContext): Promise<void> {
    step('E', `Negative: Bob (${ctx.bobLabel}) with mauled ephemeral Ed25519 signature → must fail`);
    const { wrapPk, wrapSig } = bobWrappers(ctx);
    const session = await makeSession(ctx);
    const msg = await session.getRequestToSign();
    const fullMessage = walletFullMessage(ctx, ctx.bob.accountAddress, msg, 'keyless-step-e');
    const goodSig = ctx.bob.sign(fullMessage);
    const innerEd = goodSig.ephemeralSignature.signature as Ed25519Signature;
    const mauledBytes = new Uint8Array(innerEd.toUint8Array());
    mauledBytes[0] ^= 0x01;
    const mauledSig = new KeylessSignature({
        jwtHeader: goodSig.jwtHeader,
        ephemeralCertificate: goodSig.ephemeralCertificate,
        expiryDateSecs: goodSig.expiryDateSecs,
        ephemeralPublicKey: goodSig.ephemeralPublicKey,
        ephemeralSignature: new EphemeralSignature(new Ed25519Signature(mauledBytes)),
    });
    const result = await session.decryptWithProof({
        userAddr: ctx.bob.accountAddress,
        publicKey: wrapPk(ctx.bob.publicKey),
        signature: wrapSig(mauledSig),
        fullMessage,
    });
    assert(!result.isOk, `Expected decrypt to fail with mauled ephemeral signature, but it succeeded`);
    console.log(`  ✓ decrypt with mauled ephemeral signature correctly rejected (${result.errValue})`);
}

/** Step F — mauled Groth16 proof. The ephemeral signature still verifies, but
 *  proof.a is corrupted so Groth16 verification must fail. Catches a worker
 *  bug where the proof field is parsed but never verified. */
export async function stepF_MauledGroth16Proof(ctx: AccessFailureContext): Promise<void> {
    step('F', `Negative: Bob (${ctx.bobLabel}) with mauled Groth16 proof.a → must fail`);
    const { wrapPk, wrapSig } = bobWrappers(ctx);
    const session = await makeSession(ctx);
    const msg = await session.getRequestToSign();
    const fullMessage = walletFullMessage(ctx, ctx.bob.accountAddress, msg, 'keyless-step-f');
    const goodSig = ctx.bob.sign(fullMessage);

    // Flip the first byte of proof.a (still 32 bytes; not necessarily a valid
    // curve point but the worker should fail closed regardless).
    const firstByte = parseInt(SAMPLE_PROOF_A_HEX.slice(0, 2), 16);
    const mauledFirstByte = (firstByte ^ 0x01).toString(16).padStart(2, '0');
    const mauledAHex = mauledFirstByte + SAMPLE_PROOF_A_HEX.slice(2);
    const mauledProof = new Groth16Zkp({
        a: mauledAHex,
        b: SAMPLE_PROOF_B_HEX,
        c: SAMPLE_PROOF_C_HEX,
    });
    const goodZk = goodSig.ephemeralCertificate.signature as ZeroKnowledgeSig;
    const mauledCert = new EphemeralCertificate(
        new ZeroKnowledgeSig({
            proof: new ZkProof(mauledProof, ZkpVariant.Groth16),
            expHorizonSecs: goodZk.expHorizonSecs,
            extraField: goodZk.extraField,
            overrideAudVal: goodZk.overrideAudVal,
            trainingWheelsSignature: goodZk.trainingWheelsSignature,
        }),
        EphemeralCertificateVariant.ZkProof,
    );
    const mauledSig = new KeylessSignature({
        jwtHeader: goodSig.jwtHeader,
        ephemeralCertificate: mauledCert,
        expiryDateSecs: goodSig.expiryDateSecs,
        ephemeralPublicKey: goodSig.ephemeralPublicKey,
        ephemeralSignature: goodSig.ephemeralSignature,
    });
    const result = await session.decryptWithProof({
        userAddr: ctx.bob.accountAddress,
        publicKey: wrapPk(ctx.bob.publicKey),
        signature: wrapSig(mauledSig),
        fullMessage,
    });
    assert(!result.isOk, `Expected decrypt to fail with mauled Groth16 proof, but it succeeded`);
    console.log(`  ✓ decrypt with mauled Groth16 proof correctly rejected (${result.errValue})`);
}
