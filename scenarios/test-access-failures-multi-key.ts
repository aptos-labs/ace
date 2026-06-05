// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Unhappy-path test for the K-of-N `MultiKey` account type
 * (`pk_scheme=3` / `sig_scheme=3`), with maximum position-variant diversity
 * including a WebAuthn (passkeys) position.
 *
 * Bob is a 3-of-4 `MultiKey` over four positions:
 *   - position 0: Ed25519 (a `SingleKeyAccount` wrapping a raw Ed25519 key)
 *   - position 1: Ed25519 backup (signed-with set excludes this position)
 *   - position 2: Keyless (`KeylessAccount` from the shared sample fixtures)
 *   - position 3: Secp256r1Ecdsa + WebAuthn (passkey, synthesised via
 *                 `common/webauthn-signer.ts::buildAssertion`)
 *
 * Signing-set picks positions {0, 2, 3}, so the on-the-wire `MultiKeySignature`
 * carries one Ed25519 sig + one Keyless sig + one WebAuthn assertion, with
 * bitmap = `0b1011_0000` (bits 0, 2, 3). On-chain auth-key derives via
 *   `SHA3-256( BCS(MultiKey) || 0x03 )`
 * and the worker dispatches on `pk_scheme=3` / `sig_scheme=3` →
 * `verify::aptos::multi_key`.
 *
 * The worker iterates the bitmap MSB-first, pairs each set position with the
 * corresponding inner `AnySignature`, runs per-position
 * `verify_signature_only`:
 *   - position 0 → `any::ed25519::verify_signature_only` (signs pretty-message)
 *   - position 2 → `aptos::keyless::verify_signature_only` (signs pretty-message,
 *                  JWK + VK + Cfg fetch + Groth16 + EPK verify)
 *   - position 3 → `any::secp256r1::verify_signature_only` (binds via
 *                  `clientDataJSON.challenge` to the BCS payload, NOT via
 *                  `proof.full_message` — that's why mixing pretty-message and
 *                  WebAuthn-preimage signers under one MultiKey works)
 * — then applies the MultiKey-level auth-key check + the dapp `on_ace_decryption_request`
 * view once over `proof.user_addr`.
 *
 * Three variant-specific pieces live in this file:
 *
 *   1. The MultiKeySignature is assembled manually rather than via
 *      `MultiKeyAccount.sign(msg)` because position 3 signs over the
 *      WebAuthn challenge (BCS-derived, 32 bytes) instead of the
 *      pretty-message string. `MultiKeyAccount.sign(msg)` is
 *      synchronous and feeds the same `msg` to every signer, which
 *      doesn't fit the WebAuthn flow.
 *
 *   2. WebAuthn position dispatch: the wallet returns DER from
 *      `navigator.credentials.get(...).response.signature` and we
 *      convert to raw `r || s` via noble's `p256.Signature.fromDER`
 *      (the same conversion `session.ts::derEcdsaToRawLowS` does for
 *      the single-key passkey path), then wrap in `WebAuthnSignature`
 *      and `AnySignature`.
 *
 *   3. [`mauleMultiKeySignatureWebAuthn`] peels the WebAuthn position's
 *      inner `WebAuthnSignature` out of the `MultiKeySignature`, flips
 *      the LSB of the raw `s` (mirrors single-key Secp256r1 step E),
 *      and re-packs with the unchanged bitmap. The worker should fail
 *      the per-position P-256 ECDSA verify on position 3 before
 *      reaching the MultiKey-level auth-key / ACL.
 *
 * Run:
 *   cd scenarios && pnpm test-access-failures-multi-key
 */

import {
    Account,
    AccountAddress,
    AnySignature,
    AuthenticationKey,
    Ed25519PrivateKey,
    KeylessAccount,
    MultiKey,
    MultiKeySignature,
    Secp256r1PrivateKey,
    Secp256r1PublicKey,
    SingleKeyAccount,
    WebAuthnSignature,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { p256 } from '@noble/curves/p256';
import { ChildProcess } from 'child_process';

import {
    domainForBlob,
    setupAccessControlAppAndEncryptPing,
} from './common/access-control-app';
import { setupAceOnLocalnet } from './common/ace-network';
import { CHAIN_ID } from './common/config';
import { assert, cleanupScenario, fundAccount } from './common/helpers';
import { buildBobKeylessAccount, runKeylessFrameworkBootstrap } from './common/keyless';
import { WebAuthnAssertion, buildAssertion } from './common/webauthn-signer';
import { buildAptosWalletFullMessage } from './common/aptos-wallet-message';

const TOTAL_WORKERS = 3;
const EPOCH0_WORKER_INDICES = [0, 1, 2];
const EPOCH0_THRESHOLD = 2;
const ED25519_SEED_PRIMARY = 200;
const ED25519_SEED_BACKUP = 210;
const WEBAUTHN_SEED = 220;

/** The signing-set bit positions inside Bob's 4-position MultiKey
 *  (Ed25519 = 0, Keyless = 2, Secp256r1+WebAuthn = 3). Position 1 is on-chain
 *  but never signs. */
const SIGNING_POSITIONS = [0, 2, 3];

/** Bob's actively-signing key material, plus the on-chain MultiKey
 *  composition. Constructed once and reused across all five steps. */
interface MultiKeyWithWebAuthnBob {
    multiKey: MultiKey;
    accountAddress: AccountAddress;
    ed25519Primary: SingleKeyAccount;
    keyless: KeylessAccount;
    webAuthnPrivateKey: Uint8Array;
    webAuthnPublicKey: Secp256r1PublicKey;
}

/** DER-decodes a P-256 ECDSA signature and normalises it to low-s; returns
 *  the raw 64-byte `r || s`. Mirrors `derEcdsaToRawLowS` inside
 *  `ts-sdk/src/aptos/basic-flow/session.ts` — the single-key WebAuthn path
 *  does this conversion inside `decryptWithWebAuthnAssertion`, but here we
 *  build the MultiKeySignature manually so we do it ourselves. */
function derEcdsaToRawLowS(der: Uint8Array): Uint8Array {
    return p256.Signature.fromDER(der).normalizeS().toCompactRawBytes();
}

/** Assemble the per-request MultiKeySignature. Each signing position pulls
 *  the bytes it actually needs:
 *    - position 0 (Ed25519): signs the wallet fullMessage string
 *    - position 2 (Keyless): signs the wallet fullMessage string; bare
 *      `KeylessSignature` wrapped in `AnySignature` for the on-wire
 *      `Vec<AnySignature>`
 *    - position 3 (WebAuthn): signs over the BCS-derived 32-byte WebAuthn
 *      challenge; assertion bytes converted to raw `r||s` and wrapped in
 *      `WebAuthnSignature` + `AnySignature`
 *  An optional `mauler` rewrites the assembled signatures vector before
 *  the bitmap-packed `MultiKeySignature` is constructed. */
function buildMultiKeySignature(
    bob: MultiKeyWithWebAuthnBob,
    fullMessage: string,
    webAuthnChallenge: Uint8Array,
    mauler?: (sigs: AnySignature[], webAuthnAssertion: WebAuthnAssertion) => AnySignature[],
): MultiKeySignature {
    const ed25519AnySig = bob.ed25519Primary.sign(fullMessage) as AnySignature;
    const keylessBare = bob.keyless.sign(fullMessage);
    const keylessAnySig = new AnySignature(keylessBare);
    const webAuthnAssertion = buildAssertion(webAuthnChallenge, bob.webAuthnPrivateKey);
    const webAuthnRs = derEcdsaToRawLowS(webAuthnAssertion.signature);
    const webAuthnAnySig = new AnySignature(new WebAuthnSignature(
        webAuthnRs, webAuthnAssertion.authenticatorData, webAuthnAssertion.clientDataJSON,
    ));
    let signatures: AnySignature[] = [ed25519AnySig, keylessAnySig, webAuthnAnySig];
    if (mauler) signatures = mauler(signatures, webAuthnAssertion);
    return new MultiKeySignature({
        signatures,
        bitmap: MultiKeySignature.createBitmap({ bits: SIGNING_POSITIONS }),
    });
}

/** Step-E mauler: peel the WebAuthn position's `WebAuthnSignature` out of
 *  the assembled signatures vector, flip the LSB of the raw `s`, re-wrap.
 *  Mirrors single-key Secp256r1 step E in `test-access-failures-anypub-secp256r1.ts`.
 *  Position 3 lands at `signatures[2]` because `SIGNING_POSITIONS` is in
 *  ascending order (`[0, 2, 3]` → vector indices `[0, 1, 2]`). The worker
 *  should fail the per-position P-256 ECDSA verify on position 3 before
 *  reaching the MultiKey-level auth-key / ACL. */
function mauleWebAuthnPosition(
    signatures: AnySignature[],
    assertion: WebAuthnAssertion,
): AnySignature[] {
    const sigRs = derEcdsaToRawLowS(assertion.signature);
    const mauledRs = new Uint8Array(sigRs);
    // Last byte is the LSB of `s`. Always lands in `1..curve_order`, so DER
    // parsing + low-s normalisation succeed; the ECDSA verify fails.
    mauledRs[mauledRs.length - 1] ^= 0x01;
    const mauledWebAuthnSig = new WebAuthnSignature(
        mauledRs, assertion.authenticatorData, assertion.clientDataJSON,
    );
    return [...signatures.slice(0, -1), new AnySignature(mauledWebAuthnSig)];
}

async function buildAndFundBob(): Promise<MultiKeyWithWebAuthnBob> {
    const ed25519Primary = new SingleKeyAccount({
        privateKey: new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + ED25519_SEED_PRIMARY))),
    });
    const ed25519Backup = new SingleKeyAccount({
        privateKey: new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + ED25519_SEED_BACKUP))),
    });
    const keyless = buildBobKeylessAccount();
    const webAuthnSeed = new Uint8Array(32).map((_, i) => i + WEBAUTHN_SEED);
    const webAuthnPublicKey = new Secp256r1PrivateKey(webAuthnSeed).publicKey();
    // publicKeys order = on-chain positions. The MultiKey ctor wraps each
    // raw PublicKey into AnyPublicKey internally.
    const publicKeys = [
        ed25519Primary.publicKey,
        ed25519Backup.publicKey,
        keyless.publicKey,
        webAuthnPublicKey,
    ];
    const multiKey = new MultiKey({ publicKeys, signaturesRequired: 3 });
    const accountAddress = AccountAddress.from(
        AuthenticationKey.fromPublicKey({ publicKey: multiKey }).toUint8Array(),
    );
    await fundAccount(accountAddress);
    return {
        multiKey, accountAddress, ed25519Primary, keyless,
        webAuthnPrivateKey: webAuthnSeed, webAuthnPublicKey,
    };
}

interface Ctx {
    aceDeployment: ACE.AceDeployment;
    moduleAddr: AccountAddress;
    moduleName: string;
    keypair0Id: AccountAddress;
    correctDomain: Uint8Array;
    wrongDomain: Uint8Array;
    pingCiph: Uint8Array;
    bob: MultiKeyWithWebAuthnBob;
    charlie: Account;
}

const BOB_LABEL = 'MultiKey<3-of-4 Ed25519 + Keyless + Secp256r1+WebAuthn>';

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
        domain: overrides.domain ?? ctx.correctDomain,
        ciphertext: ctx.pingCiph,
    });
}

async function decryptAsBob(
    ctx: Ctx,
    session: ACE.AptosBasicFlow.DecryptionSession,
    mauler?: (sigs: AnySignature[], assertion: WebAuthnAssertion) => AnySignature[],
) {
    const msg = await session.getRequestToSign();
    const fullMessage = buildAptosWalletFullMessage({
        accountAddress: ctx.bob.accountAddress,
        chainId: CHAIN_ID,
        message: msg,
        nonce: 'multi-key-bob',
    });
    const webAuthnChallenge = await session.getRequestToSignForWebAuthn();
    const signature = buildMultiKeySignature(ctx.bob, fullMessage, webAuthnChallenge, mauler);
    return session.decryptWithProof({
        userAddr: ctx.bob.accountAddress,
        publicKey: ctx.bob.multiKey,
        signature,
        fullMessage,
    });
}

async function stepA_BadKeypairID(ctx: Ctx): Promise<void> {
    step('A', `Negative: Bob (${BOB_LABEL}) decrypt with nonexistent keypair ID → must fail (404)`);
    const fakeKeypairId = AccountAddress.fromString('0x' + 'ab'.repeat(32));
    const session = await makeSession(ctx, { keypairId: fakeKeypairId });
    const result = await decryptAsBob(ctx, session);
    assert(!result.isOk, `Expected decrypt to fail with nonexistent keypairId, but it succeeded`);
    console.log(`  ✓ decrypt with nonexistent keypairId correctly rejected (${result.errValue})`);
}

async function stepB_NonAllowlistedCharlie(ctx: Ctx): Promise<void> {
    step('B', `Negative: decrypt by Charlie (Ed25519, not allowlisted) → must fail (403)`);
    const session = await makeSession(ctx);
    const msg = await session.getRequestToSign();
    const fullMessage = buildAptosWalletFullMessage({
        accountAddress: ctx.charlie.accountAddress,
        chainId: CHAIN_ID,
        message: msg,
        nonce: 'multi-key-step-b',
    });
    const result = await session.decryptWithProof({
        userAddr: ctx.charlie.accountAddress,
        publicKey: ctx.charlie.publicKey,
        signature: ctx.charlie.sign(fullMessage),
        fullMessage,
    });
    assert(!result.isOk, `Expected decrypt to fail for non-allowlisted Charlie, but it succeeded`);
    console.log(`  ✓ decrypt by non-allowlisted Charlie correctly rejected (${result.errValue})`);
}

async function stepC_WrongDomain(ctx: Ctx): Promise<void> {
    step('C', `Negative: Bob (${BOB_LABEL}) decrypt with wrong domain → must fail (403)`);
    const session = await makeSession(ctx, { domain: ctx.wrongDomain });
    const result = await decryptAsBob(ctx, session);
    assert(!result.isOk, `Expected decrypt to fail with wrong domain, but it succeeded`);
    console.log(`  ✓ decrypt with wrong domain correctly rejected (${result.errValue})`);
}

async function stepD_HappyPath(ctx: Ctx): Promise<void> {
    step('D', `Positive: Bob (${BOB_LABEL}, allowlisted) decrypts with correct inputs → must succeed`);
    const session = await makeSession(ctx);
    const result = await decryptAsBob(ctx, session);
    assert(result.isOk, `decrypt with correct inputs failed: ${result.errValue}`);
    assert(new TextDecoder().decode(result.okValue!) === 'PING', 'PING plaintext mismatch');
    console.log(`  ✓ Bob (${BOB_LABEL}) decrypted successfully`);
}

async function stepE_MauledWebAuthnSig(ctx: Ctx): Promise<void> {
    step('E', `Negative: Bob (${BOB_LABEL}) with mauled WebAuthn r||s LSB → must fail`);
    const session = await makeSession(ctx);
    const result = await decryptAsBob(ctx, session, mauleWebAuthnPosition);
    assert(!result.isOk, `Expected decrypt to fail with mauled WebAuthn signature, but it succeeded`);
    console.log(`  ✓ decrypt with mauled WebAuthn signature correctly rejected (${result.errValue})`);
}

async function main(): Promise<void> {
    let workers: ChildProcess[] = [];
    let localnetProc: ChildProcess | null = null;
    let exitCode = 0;
    try {
        const setup = await setupAceOnLocalnet({
            totalWorkers: TOTAL_WORKERS, epoch0WorkerIndices: EPOCH0_WORKER_INDICES,
            epoch0Threshold: EPOCH0_THRESHOLD, fundAccount, numKeypairs: 1,
            // Installs the test RSA JWK + Groth16 VK + a relaxed
            // Configuration.max_exp_horizon_secs so the Keyless position's
            // Groth16 proof + EPK signature can verify on this localnet.
            beforeAceSetup: runKeylessFrameworkBootstrap,
        });
        localnetProc = setup.localnetProc;
        workers = setup.ace.workers;
        const { actors, ace, keypairIds: [keypair0Id] } = setup;
        const bob = await buildAndFundBob();
        console.log(`  Bob (${BOB_LABEL}): ${bob.accountAddress.toStringLong()}`);
        const { correctDomain, pingCiph } = await setupAccessControlAppAndEncryptPing(
            actors, bob.accountAddress, ace.aceDeployment, ace.adminAccountAddress, keypair0Id,
        );
        const ctx: Ctx = {
            aceDeployment: ace.aceDeployment, moduleAddr: ace.adminAccountAddress,
            moduleName: 'access_control',
            keypair0Id, correctDomain, wrongDomain: domainForBlob(actors.alice, 'other-blob'),
            pingCiph, bob, charlie: actors.charlie,
        };
        await stepA_BadKeypairID(ctx);
        await stepB_NonAllowlistedCharlie(ctx);
        await stepC_WrongDomain(ctx);
        await stepD_HappyPath(ctx);
        await stepE_MauledWebAuthnSig(ctx);
        console.log(`\n✅ All ${BOB_LABEL} access-control enforcement tests passed!\n`);
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        cleanupScenario(workers, localnetProc);
        process.exit(exitCode);
    }
}

main();
