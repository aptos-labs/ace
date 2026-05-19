// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Unhappy-path test for the modern `AnyPublicKey<Ed25519>` (SingleKey) account.
 *
 * Sibling of `test-access-failures.ts` (bare-Ed25519, `pk_scheme=0`). Bob
 * here is a `SingleKeyAccount` wrapping the same Ed25519 key material; his
 * on-chain auth-key derives via
 *   `SHA3-256( BCS(AnyPublicKey::Ed25519(pk)) || 0x02 )`
 * (≠ legacy `SHA3-256(pk || 0x00)`), so the worker dispatches on
 * `pk_scheme=1` / `sig_scheme=1` (the new `Any` wire path).
 *
 * All scaffolding (base-actor funding, ACE network bring-up, DKG,
 * access-control app setup + PING encryption, the 5 unhappy-path step
 * bodies, scenario cleanup) lives in `scenarios/common/`. The only
 * variant-specific code here is constructing Bob as a `SingleKeyAccount`
 * and the Step-E mauler [`mauleAnySignatureEd25519`].
 *
 * Run:
 *   cd scenarios && pnpm test-access-failures-anypub-ed25519
 */

import {
    Account,
    AnySignature,
    Ed25519PrivateKey,
    Ed25519Signature,
    Signature,
    SingleKeyAccount,
} from '@aptos-labs/ts-sdk';
import { ChildProcess } from 'child_process';

import {
    domainForBlob,
    setupAccessControlAppAndEncryptPing,
    setupBaseAceActors,
} from './common/access-control-app';
import { deployAndBringUpAceNetwork, runDkg } from './common/ace-network';
import { cleanupScenario, fundAccount, sleep, startLocalnet } from './common/helpers';
import {
    NonKeylessAccessFailureContext,
    runNonKeylessAccessFailureSteps,
} from './common/non-keyless-access-failures';

const TOTAL_WORKERS = 3;
const EPOCH0_WORKER_INDICES = [0, 1, 2];
const EPOCH0_THRESHOLD = 2;
const BOB_KEY_SEED = 200;

/** Step-E mauler for this variant: peel the inner `Ed25519Signature` out of
 *  the `AnySignature` envelope, flip a bit, re-wrap. */
function mauleAnySignatureEd25519(signer: Account, msg: string): Signature {
    const goodAny = signer.sign(msg) as AnySignature;
    const innerEd25519 = goodAny.signature as Ed25519Signature;
    const mauledBytes = new Uint8Array(innerEd25519.toUint8Array());
    mauledBytes[0] ^= 0x01;
    return new AnySignature(new Ed25519Signature(mauledBytes));
}

async function buildAndFundBob(): Promise<SingleKeyAccount> {
    const bobKey = new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + BOB_KEY_SEED)));
    const bob = new SingleKeyAccount({ privateKey: bobKey });
    await fundAccount(bob.accountAddress);
    return bob;
}

async function main(): Promise<void> {
    let workers: ChildProcess[] = [];
    let localnetProc: ChildProcess | null = null;
    let exitCode = 0;
    try {
        localnetProc = await startLocalnet();
        const actors = await setupBaseAceActors();
        const bob = await buildAndFundBob();
        const ace = await deployAndBringUpAceNetwork({
            adminAccount: actors.admin, totalWorkers: TOTAL_WORKERS,
            epoch0WorkerIndices: EPOCH0_WORKER_INDICES, epoch0Threshold: EPOCH0_THRESHOLD,
            fundAccount,
        });
        workers = ace.workers;
        const keypair0Id = await runDkg({
            approvers: ace.epoch0WorkerAccounts.slice(0, EPOCH0_THRESHOLD),
            adminAddr: actors.adminAddr, adminAccountAddress: ace.adminAccountAddress,
            expectedSecretsCountAfter: 1,
        });
        await sleep(10000);
        const { correctDomain, pingCiph } = await setupAccessControlAppAndEncryptPing(
            actors, bob.accountAddress, ace.aceDeployment, ace.adminAccountAddress, keypair0Id,
        );
        const ctx: NonKeylessAccessFailureContext = {
            aceDeployment: ace.aceDeployment, moduleAddr: ace.adminAccountAddress,
            moduleName: 'access_control', functionName: 'check_permission',
            keypair0Id, correctDomain, wrongDomain: domainForBlob(actors.alice, 'other-blob'),
            pingCiph, bob, bobLabel: 'SingleKey/Ed25519', charlie: actors.charlie,
        };
        await runNonKeylessAccessFailureSteps(ctx, mauleAnySignatureEd25519);
        console.log('\n✅ All AnyPublicKey<Ed25519> access-control enforcement tests passed!\n');
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        cleanupScenario(workers, localnetProc);
        process.exit(exitCode);
    }
}

main();
