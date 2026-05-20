// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Unhappy-path test for the K-of-N `MultiKey` account type
 * (`pk_scheme=3` / `sig_scheme=3`).
 *
 * Bob here is a 2-of-3 `MultiKeyAccount` over three Ed25519 signers (all
 * wrapped as `SingleKeyAccount`s, so each appears as an `AnyPublicKey<Ed25519>`
 * inside the MultiKey). On-chain auth-key derives via
 *   `SHA3-256( BCS(MultiKey) || 0x03 )`
 * (≠ the SingleKey `... || 0x02` derivation), and the worker dispatches
 * on `pk_scheme=3` / `sig_scheme=3` → `verify::aptos::multi_key`.
 *
 * The worker iterates the bitmap MSB-first, pairs each set position with
 * the corresponding inner `AnySignature`, runs per-position
 * `verify_signature_only` (no per-position auth-key / ACL), then applies
 * the MultiKey-level auth-key check + the dapp `check_permission` view
 * once over `proof.user_addr`.
 *
 * All scaffolding (base-actor funding, ACE bring-up, DKG, access-control
 * app setup + PING encryption, the 5 unhappy-path step bodies, scenario
 * cleanup) lives in `scenarios/common/`. The only variant-specific code
 * here is constructing Bob as a 2-of-3 `MultiKeyAccount` and the Step-E
 * mauler [`mauleMultiKeySignature`].
 *
 * Run:
 *   cd scenarios && pnpm test-access-failures-multi-key
 */

import {
    Account,
    Ed25519PrivateKey,
    Ed25519Signature,
    AnySignature,
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
// Three deterministic seeds; their resulting Ed25519 keys form Bob's
// 3-position MultiKey. The set of signers chosen for any given sign() call
// is a subset of size = signaturesRequired (2 here).
const BOB_SIGNER_SEEDS = [200, 210, 220];
const BOB_SIGNATURES_REQUIRED = 2;

/** Step-E mauler for this variant: ask Bob to sign normally, then flip a
 *  bit inside the first inner Ed25519 signature in the MultiKeySignature,
 *  and re-pack with the same bitmap. The worker should fail the per-position
 *  signature check on the mauled position before reaching auth-key / ACL. */
function mauleMultiKeySignature(signer: Account, msg: string): Signature {
    const good = signer.sign(msg) as MultiKeySignature;
    const firstAny = good.signatures[0] as AnySignature;
    const firstEd25519 = firstAny.signature as Ed25519Signature;
    const mauledBytes = new Uint8Array(firstEd25519.toUint8Array());
    mauledBytes[0] ^= 0x01;
    const mauledFirst = new AnySignature(new Ed25519Signature(mauledBytes));
    return new MultiKeySignature({
        signatures: [mauledFirst, ...good.signatures.slice(1)],
        bitmap: good.bitmap,
    });
}

async function buildAndFundBob(): Promise<MultiKeyAccount> {
    const signers = BOB_SIGNER_SEEDS.map((seed) => {
        const key = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + seed)));
        return new SingleKeyAccount({ privateKey: key });
    });
    // 2-of-3: signers[0] + signers[1] sign each request; the on-chain
    // public-key set holds all three positions, so the bitmap selects {0, 1}.
    const publicKeys = signers.map((s) => s.publicKey);
    const multiKey = new MultiKey({ publicKeys, signaturesRequired: BOB_SIGNATURES_REQUIRED });
    const bob = new MultiKeyAccount({ multiKey, signers: signers.slice(0, BOB_SIGNATURES_REQUIRED) });
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
            pingCiph, bob, bobLabel: 'MultiKey<2-of-3 Ed25519>', charlie: actors.charlie,
        };
        await decryptWithBadKeypairID(ctx);
        await decryptAsNonAllowlistedUser(ctx);
        await decryptWithWrongDomain(ctx);
        await decryptWithCorrectInputs(ctx);
        await decryptWithMauledSignature(ctx, mauleMultiKeySignature);
        console.log('\n✅ All MultiKey<2-of-3 Ed25519> access-control enforcement tests passed!\n');
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        cleanupScenario(workers, localnetProc);
        process.exit(exitCode);
    }
}

main();
