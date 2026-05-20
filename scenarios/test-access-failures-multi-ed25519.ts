// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Unhappy-path test for the legacy K-of-N `MultiEd25519` account type
 * (`pk_scheme=2` / `sig_scheme=2`). Predates `MultiKey` (`pk_scheme=3`)
 * and only supports raw Ed25519 positions; wire layout is flat byte
 * concatenation rather than length-prefixed `Vec<AnyPublicKey>` /
 * `Vec<AnySignature>`.
 *
 * Bob is a 2-of-3 `MultiEd25519` over three raw Ed25519 public keys at
 * positions `{0, 1, 2}`. `MultiEd25519Account` is given the two signing
 * private keys and computes the bitmap internally; on-the-wire signatures
 * are sorted by ascending bit position (positions {0, 1} sign here).
 * On-chain auth-key derives via
 *   `SHA3-256( pk_0 || pk_1 || pk_2 || threshold(0x02) || 0x01 )`
 * — `Scheme::MultiEd25519 = 0x01`, not `0x03` (which is MultiKey). The
 * worker dispatches on `pk_scheme=2` / `sig_scheme=2` →
 * `verify::aptos::multi_ed25519`, which:
 *   1. parses the flat byte payloads (`pk_1||...||pk_N||threshold` and
 *      `sig_1||...||sig_K||bitmap[4]`),
 *   2. validates the structural invariants (popcount/threshold/in-range),
 *   3. runs per-position Ed25519 verifies via
 *      `super::any::ed25519::verify_signature_only` against the
 *      pretty-message string (reused; same primitive),
 *   4. checks the MultiEd25519-level auth-key + dapp ACL once.
 *
 * `MultiEd25519Account` already implements `Account` (sync `sign(msg)`
 * over the pretty message, returns a `MultiEd25519Signature`), so it
 * drops into the shared 5-step non-keyless harness without a wrapper —
 * unlike `MultiKey + Keyless`/`MultiKey + WebAuthn` which need custom
 * assembly.
 *
 * Step-E mauler peels one `Ed25519Signature` out of the
 * `MultiEd25519Signature`, flips a bit, re-packs with the unchanged
 * bitmap. The worker should fail the per-position Ed25519 verify on that
 * position before reaching the MultiEd25519-level auth-key / ACL.
 *
 * Run:
 *   cd scenarios && pnpm test-access-failures-multi-ed25519
 */

import {
    Account,
    Ed25519PrivateKey,
    Ed25519Signature,
    MultiEd25519Account,
    MultiEd25519PublicKey,
    MultiEd25519Signature,
    Signature,
} from '@aptos-labs/ts-sdk';
import { ChildProcess } from 'child_process';

import {
    domainForBlob,
    setupAccessControlAppAndEncryptPing,
} from './common/access-control-app';
import { setupAceOnLocalnet } from './common/ace-network';
import { cleanupScenario, fundAccount } from './common/helpers';
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
const ED25519_SEED_0 = 230;
const ED25519_SEED_1 = 240;
const ED25519_SEED_2 = 250;

/** Step-E mauler: peel the first inner `Ed25519Signature` out of the
 *  `MultiEd25519Signature`, flip a bit, re-pack with the unchanged bitmap.
 *  Signatures sit in ascending bit-position order — `MultiEd25519Account`
 *  sorted them at construction, so `signatures[0]` corresponds to the
 *  lowest set bit (position 0 in this scenario). The worker should fail
 *  the per-position Ed25519 verify on that position before reaching the
 *  MultiEd25519-level auth-key / ACL. */
function mauleMultiEd25519Signature(signer: Account, msg: string): Signature {
    const good = signer.sign(msg) as MultiEd25519Signature;
    const innerEd25519 = good.signatures[0];
    const mauledBytes = new Uint8Array(innerEd25519.toUint8Array());
    mauledBytes[0] ^= 0x01;
    const mauledFirst = new Ed25519Signature(mauledBytes);
    return new MultiEd25519Signature({
        signatures: [mauledFirst, ...good.signatures.slice(1)],
        bitmap: good.bitmap,
    });
}

async function buildAndFundBob(): Promise<MultiEd25519Account> {
    const sk0 = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + ED25519_SEED_0)));
    const sk1 = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + ED25519_SEED_1)));
    const sk2 = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + ED25519_SEED_2)));
    const publicKey = new MultiEd25519PublicKey({
        publicKeys: [sk0.publicKey(), sk1.publicKey(), sk2.publicKey()],
        threshold: 2,
    });
    // signers = the 2 actually-signing private keys (positions 0 and 1).
    // sk2 at position 2 is on-chain but not used to sign this request.
    const bob = new MultiEd25519Account({ publicKey, signers: [sk0, sk1] });
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
            pingCiph, bob, bobLabel: 'MultiEd25519<2-of-3>', charlie: actors.charlie,
        };
        await decryptWithBadKeypairID(ctx);
        await decryptAsNonAllowlistedUser(ctx);
        await decryptWithWrongDomain(ctx);
        await decryptWithCorrectInputs(ctx);
        await decryptWithMauledSignature(ctx, mauleMultiEd25519Signature);
        console.log('\n✅ All MultiEd25519<2-of-3> access-control enforcement tests passed!\n');
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        cleanupScenario(workers, localnetProc);
        process.exit(exitCode);
    }
}

main();
