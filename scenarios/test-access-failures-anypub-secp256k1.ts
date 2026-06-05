// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Unhappy-path test for the modern `AnyPublicKey<Secp256k1Ecdsa>` (SingleKey)
 * account.
 *
 * Sibling of `test-access-failures-anypub-ed25519.ts`. Bob here is a
 * `SingleKeyAccount` wrapping a `Secp256k1PrivateKey`; his on-chain auth-key
 * derives via
 *   `SHA3-256( BCS(AnyPublicKey::Secp256k1Ecdsa(pk)) || 0x02 )`
 * (variant tag `0x01`, 65-byte uncompressed SEC1 pubkey inside). The worker
 * dispatches on `pk_scheme=1` / `sig_scheme=1` and inner variant `1` — the
 * new secp256k1 verifier added alongside this scenario.
 *
 * All scaffolding (base-actor funding, ACE network bring-up, DKG,
 * access-control app setup + PING encryption, the 5 unhappy-path step
 * bodies, scenario cleanup) lives in `scenarios/common/`. The only
 * variant-specific code here is constructing Bob with a Secp256k1 inner key
 * and the Step-E mauler [`mauleAnySignatureSecp256k1`].
 *
 * Run:
 *   cd scenarios && pnpm test-access-failures-anypub-secp256k1
 */

import {
    Account,
    AnySignature,
    Secp256k1PrivateKey,
    Secp256k1Signature,
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
const BOB_KEY_SEED = 200;

/** Step-E mauler for this variant: peel the inner `Secp256k1Signature` out of
 *  the `AnySignature` envelope, flip a bit, re-wrap. Flipping a byte inside
 *  `r||s` makes the ECDSA verification fail before the worker ever hits the
 *  on-chain auth-key / permission checks. */
function mauleAnySignatureSecp256k1(signer: Account, msg: string): Signature {
    const goodAny = signer.sign(msg) as AnySignature;
    const innerSecp = goodAny.signature as Secp256k1Signature;
    const mauledBytes = new Uint8Array(innerSecp.toUint8Array());
    mauledBytes[0] ^= 0x01;
    return new AnySignature(new Secp256k1Signature(mauledBytes));
}

async function buildAndFundBob(): Promise<SingleKeyAccount> {
    const bobKey = new Secp256k1PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + BOB_KEY_SEED)));
    const bob = new SingleKeyAccount({ privateKey: bobKey });
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
            moduleName: 'access_control',
            keypair0Id, correctDomain, wrongDomain: domainForBlob(actors.alice, 'other-blob'),
            pingCiph, bob, bobLabel: 'SingleKey/Secp256k1', charlie: actors.charlie,
        };
        await decryptWithBadKeypairID(ctx);
        await decryptAsNonAllowlistedUser(ctx);
        await decryptWithWrongDomain(ctx);
        await decryptWithCorrectInputs(ctx);
        await decryptWithMauledSignature(ctx, mauleAnySignatureSecp256k1);
        console.log('\n✅ All AnyPublicKey<Secp256k1Ecdsa> access-control enforcement tests passed!\n');
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        cleanupScenario(workers, localnetProc);
        process.exit(exitCode);
    }
}

main();
