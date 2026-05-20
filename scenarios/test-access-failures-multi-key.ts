// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Unhappy-path test for the K-of-N `MultiKey` account type
 * (`pk_scheme=3` / `sig_scheme=3`), with diverse position variants.
 *
 * Bob here is a 2-of-3 `MultiKey` over three positions:
 *   - position 0: Ed25519 (a `SingleKeyAccount` wrapping a raw Ed25519 key)
 *   - position 1: Ed25519 backup (signed-with set excludes this position)
 *   - position 2: Keyless (`KeylessAccount` from the shared sample fixtures)
 *
 * Signing-set picks positions {0, 2}, so the on-the-wire `MultiKeySignature`
 * carries one Ed25519 sig + one Keyless sig, with bitmap = `0b1010_0000`
 * (bits 0 and 2). On-chain auth-key derives via
 *   `SHA3-256( BCS(MultiKey) || 0x03 )`
 * (≠ the SingleKey `... || 0x02` derivation), and the worker dispatches
 * on `pk_scheme=3` / `sig_scheme=3` → `verify::aptos::multi_key`.
 *
 * The worker iterates the bitmap MSB-first, pairs each set position with
 * the corresponding inner `AnySignature`, runs per-position
 * `verify_signature_only` (Ed25519 raw verify for position 0; JWK+VK+Cfg
 * fetch + Groth16 + EPK verify for position 2), then applies the
 * MultiKey-level auth-key check + the dapp `check_permission` view once
 * over `proof.user_addr`.
 *
 * Two variant-specific bits live in this file:
 *
 *   1. [`MultiKeyMixedAccount`] subclasses `MultiKeyAccount` to wrap any
 *      bare `KeylessSignature` returned by a Keyless signer in
 *      `AnySignature` — the upstream `MultiKeyAccount.sign` doesn't do
 *      this wrapping, but the on-wire `MultiKeySignature.signatures`
 *      vector is typed as `Vec<AnySignature>`, so each element must carry
 *      the AnyPublicKey variant tag.
 *
 *   2. [`mauleMultiKeySignature`] peels the Ed25519 position's inner
 *      signature out of the `MultiKeySignature`, flips a bit, and re-packs
 *      with the unchanged bitmap.
 *
 * Run:
 *   cd scenarios && pnpm test-access-failures-multi-key
 */

import {
    AnySignature,
    Ed25519PrivateKey,
    Ed25519Signature,
    HexInput,
    MultiKey,
    MultiKeyAccount,
    MultiKeySignature,
    Signature,
    SingleKeyAccount,
} from '@aptos-labs/ts-sdk';
import { ChildProcess } from 'child_process';

import {
    domainForBlob,
    setupAccessControlAppAndEncryptPing,
} from './common/access-control-app';
import { setupAceOnLocalnet } from './common/ace-network';
import { cleanupScenario, fundAccount } from './common/helpers';
import { buildBobKeylessAccount, runKeylessFrameworkBootstrap } from './common/keyless';
import {
    NonKeylessAccessFailureContext,
    decryptAsNonAllowlistedUser,
    decryptWithBadKeypairID,
    decryptWithCorrectInputs,
    decryptWithMauledSignature,
    decryptWithWrongDomain,
} from './common/non-keyless-access-failures';

const TOTAL_WORKERS = 3;
const EPOCH0_WORKER_INDICES = [0, 1, 2];
const EPOCH0_THRESHOLD = 2;
const ED25519_SEED_PRIMARY = 200;
const ED25519_SEED_BACKUP = 210;

/** Wrapper around `MultiKeyAccount` that AnySignature-wraps any bare
 *  `KeylessSignature` returned by a Keyless signer before packing it
 *  into the `MultiKeySignature`. The upstream `MultiKeyAccount.sign`
 *  pushes whatever each signer returns into `signatures[]` verbatim;
 *  `SingleKeyAccount.sign` already returns `AnySignature`, but
 *  `AbstractKeylessAccount.sign` returns a bare `KeylessSignature` (no
 *  variant tag) and on-the-wire that breaks BCS round-trip against the
 *  worker's `Vec<AnySignature>`-typed signatures field. */
class MultiKeyMixedAccount extends MultiKeyAccount {
    override sign(data: HexInput): MultiKeySignature {
        const sigs: Signature[] = this.signers.map((signer) => {
            const sig = signer.sign(data) as Signature;
            return sig instanceof AnySignature ? sig : new AnySignature(sig);
        });
        return new MultiKeySignature({
            signatures: sigs,
            bitmap: this.signaturesBitmap,
        });
    }
}

/** Step-E mauler: peel the Ed25519 position's `Ed25519Signature` out of
 *  the `MultiKeySignature`, flip a bit, re-pack with the same bitmap.
 *  Position 0 (Ed25519) is `signatures[0]` because `MultiKeyAccount`
 *  sorts signers by ascending bit position; the Ed25519 signer was
 *  registered at position 0, so it's first. The worker should fail the
 *  per-position signature check on that position before reaching the
 *  MultiKey-level auth-key / ACL. */
function mauleMultiKeySignature(signer: { sign(msg: string): Signature }, msg: string): Signature {
    const good = signer.sign(msg) as MultiKeySignature;
    const ed25519Any = good.signatures[0] as AnySignature;
    const ed25519Sig = ed25519Any.signature as Ed25519Signature;
    const mauledBytes = new Uint8Array(ed25519Sig.toUint8Array());
    mauledBytes[0] ^= 0x01;
    const mauledFirst = new AnySignature(new Ed25519Signature(mauledBytes));
    return new MultiKeySignature({
        signatures: [mauledFirst, ...good.signatures.slice(1)],
        bitmap: good.bitmap,
    });
}

async function buildAndFundBob(): Promise<MultiKeyMixedAccount> {
    const ed25519Primary = new SingleKeyAccount({
        privateKey: new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + ED25519_SEED_PRIMARY))),
    });
    const ed25519Backup = new SingleKeyAccount({
        privateKey: new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + ED25519_SEED_BACKUP))),
    });
    const keyless = buildBobKeylessAccount();
    // publicKeys order = on-chain positions. signers = the subset that
    // signs each request (positions 0 + 2; ed25519Backup at position 1
    // is on-chain but not used here).
    const publicKeys = [ed25519Primary.publicKey, ed25519Backup.publicKey, keyless.publicKey];
    const multiKey = new MultiKey({ publicKeys, signaturesRequired: 2 });
    const bob = new MultiKeyMixedAccount({ multiKey, signers: [ed25519Primary, keyless] });
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
        const { correctDomain, pingCiph } = await setupAccessControlAppAndEncryptPing(
            actors, bob.accountAddress, ace.aceDeployment, ace.adminAccountAddress, keypair0Id,
        );
        const ctx: NonKeylessAccessFailureContext = {
            aceDeployment: ace.aceDeployment, moduleAddr: ace.adminAccountAddress,
            moduleName: 'access_control', functionName: 'check_permission',
            keypair0Id, correctDomain, wrongDomain: domainForBlob(actors.alice, 'other-blob'),
            pingCiph, bob, bobLabel: 'MultiKey<2-of-3 Ed25519 + Keyless>', charlie: actors.charlie,
        };
        await decryptWithBadKeypairID(ctx);
        await decryptAsNonAllowlistedUser(ctx);
        await decryptWithWrongDomain(ctx);
        await decryptWithCorrectInputs(ctx);
        await decryptWithMauledSignature(ctx, mauleMultiKeySignature);
        console.log('\n✅ All MultiKey<2-of-3 Ed25519 + Keyless> access-control enforcement tests passed!\n');
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        cleanupScenario(workers, localnetProc);
        process.exit(exitCode);
    }
}

main();
