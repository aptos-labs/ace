// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Unhappy-path test: decrypt failure cases with a legacy bare-Ed25519 Bob
 * (`pk_scheme=0`, auth-key = `SHA3-256(pk || 0x00)`).
 *
 * Sibling of `test-access-failures-anypub-ed25519.ts` (SingleKey wrapping
 * the same Ed25519 key). All scaffolding (base-actor funding, ACE network
 * bring-up, DKG, access-control app setup + PING encryption, the 5
 * unhappy-path step bodies, scenario cleanup) lives in `scenarios/common/`.
 * The only variant-specific bits here are: Bob is a plain `Account` (so
 * `bob.publicKey` is `Ed25519PublicKey` and the worker dispatches on
 * `pk_scheme=0`), and the Step-E mauler operates on a raw
 * `Ed25519Signature` (no `AnySignature` envelope).
 *
 * Test cases:
 *   A. Decrypt with a nonexistent keypair ID                → fail (404).
 *   B. Decrypt by Charlie (not on allowlist)                → fail (403).
 *   C. Decrypt with wrong domain (blob doesn't exist)       → fail (403).
 *   D. Decrypt by Bob (allowlisted) with correct inputs     → succeed.
 *   E. Decrypt by Bob with a mauled Ed25519 signature       → fail.
 *
 * Run:
 *   cd scenarios && pnpm test-access-failures
 */

import {
    Account,
    Ed25519PrivateKey,
    Ed25519Signature,
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
const BOB_KEY_SEED = 200;

/** Step-E mauler for this variant: flip a bit in the raw 64-byte Ed25519
 *  signature. No envelope (legacy `pk_scheme=0` doesn't wrap the sig). */
function mauleBareEd25519Signature(signer: Account, msg: string): Signature {
    const good = signer.sign(msg) as Ed25519Signature;
    const mauledBytes = new Uint8Array(good.toUint8Array());
    mauledBytes[0] ^= 0x01;
    return new Ed25519Signature(mauledBytes);
}

async function buildAndFundBob(): Promise<Account> {
    const bobKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + BOB_KEY_SEED)));
    const bob = Account.fromPrivateKey({ privateKey: bobKey });
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
            moduleName: 'access_control', functionName: 'on_ace_decryption_request',
            keypair0Id, correctDomain, wrongDomain: domainForBlob(actors.alice, 'other-blob'),
            pingCiph, bob, bobLabel: 'Ed25519', charlie: actors.charlie,
        };
        await decryptWithBadKeypairID(ctx);
        await decryptAsNonAllowlistedUser(ctx);
        await decryptWithWrongDomain(ctx);
        await decryptWithCorrectInputs(ctx);
        await decryptWithMauledSignature(ctx, mauleBareEd25519Signature);
        console.log('\n✅ All access-control enforcement tests passed!\n');
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        cleanupScenario(workers, localnetProc);
        process.exit(exitCode);
    }
}

main();
