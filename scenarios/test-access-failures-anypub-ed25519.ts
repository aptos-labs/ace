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
 * The five step bodies (A nonexistent-keypair, B not-allowlisted, C
 * wrong-domain, D positive-control, E mauled-signature) live in
 * `common/non-keyless-access-failures.ts`. The only variant-specific bit
 * is [`mauleAnySignatureEd25519`] for Step E.
 *
 * Run:
 *   cd scenarios && pnpm test-access-failures-anypub-ed25519
 */

import {
    Account,
    AccountAddress,
    AnySignature,
    Ed25519PrivateKey,
    Ed25519Signature,
    Signature,
    SingleKeyAccount,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { ChildProcess } from 'child_process';

import {
    deployAndInitAccessControl,
    domainForBlob,
    encryptForAccessControl,
    registerAllowlistBlob,
} from './common/access-control-app';
import { deployAndBringUpAceNetwork, runDkg } from './common/ace-network';
import { createAptos, fundAccount, sleep, startLocalnet } from './common/helpers';
import {
    NonKeylessAccessFailureContext,
    runNonKeylessAccessFailureSteps,
} from './common/non-keyless-access-failures';

const TOTAL_WORKERS = 3;
const EPOCH0_WORKER_INDICES = [0, 1, 2];
const EPOCH0_THRESHOLD = 2;
const ADMIN_KEY = '0x1111111111111111111111111111111111111111111111111111111111111111';
const ALICE_KEY_SEED = 100;
const BOB_KEY_SEED = 200;
const CHARLIE_KEY_SEED = 50;

function ed25519Key(seed: number): Ed25519PrivateKey {
    return new Ed25519PrivateKey(Buffer.from(new Uint8Array(32).map((_, i) => i + seed)));
}

/** Step-E mauler for this variant: peel the inner `Ed25519Signature` out of
 *  the `AnySignature` envelope, flip a bit, re-wrap. */
function mauleAnySignatureEd25519(signer: Account, msg: string): Signature {
    const goodAny = signer.sign(msg) as AnySignature;
    const innerEd25519 = goodAny.signature as Ed25519Signature;
    const mauledBytes = new Uint8Array(innerEd25519.toUint8Array());
    mauledBytes[0] ^= 0x01;
    return new AnySignature(new Ed25519Signature(mauledBytes));
}

function cleanup(workers: ChildProcess[], localnetProc: ChildProcess | null): void {
    console.log('\nCleaning up worker processes...');
    for (const proc of workers) proc.kill('SIGTERM');
    if (localnetProc) {
        console.log('Stopping localnet...');
        localnetProc.kill('SIGTERM');
    }
}

interface Actors {
    admin: Account; adminAddr: string; adminKeyHex: string;
    alice: Account; bob: SingleKeyAccount; charlie: Account;
}

/** Builds and funds the 4 fixed identities: admin (hard-coded key), Alice,
 *  Bob (SingleKey/AnyPublicKey<Ed25519>), Charlie. */
async function setupActors(): Promise<Actors> {
    const admin = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(ADMIN_KEY) });
    const adminAddr = admin.accountAddress.toStringLong();
    const adminKeyHex = Buffer.from(admin.privateKey.toUint8Array()).toString('hex');
    const alice = Account.fromPrivateKey({ privateKey: ed25519Key(ALICE_KEY_SEED) });
    const bob = new SingleKeyAccount({ privateKey: ed25519Key(BOB_KEY_SEED) });
    const charlie = Account.fromPrivateKey({ privateKey: ed25519Key(CHARLIE_KEY_SEED) });
    await Promise.all([admin, alice, bob, charlie].map(a => fundAccount(a.accountAddress)));
    return { admin, adminAddr, adminKeyHex, alice, bob, charlie };
}

/** Deploys access_control, registers Alice's `ping-blob` (allowlist=[Bob]),
 *  encrypts plaintext "PING" under (`keypair0Id`, `@alice/ping-blob`). */
async function setupAppAndEncryptPing(
    actors: Actors,
    aceDeployment: ACE.AceDeployment,
    adminAccountAddress: AccountAddress,
    keypair0Id: AccountAddress,
): Promise<{ correctDomain: Uint8Array; pingCiph: Uint8Array }> {
    await deployAndInitAccessControl(actors.admin, actors.adminAddr, actors.adminKeyHex);
    await registerAllowlistBlob(createAptos(), actors.alice, actors.bob.accountAddress, actors.adminAddr, 'ping-blob');
    const correctDomain = domainForBlob(actors.alice, 'ping-blob');
    const pingCiph = await encryptForAccessControl(aceDeployment, adminAccountAddress, keypair0Id, correctDomain, new TextEncoder().encode('PING'));
    return { correctDomain, pingCiph };
}

async function main(): Promise<void> {
    let workers: ChildProcess[] = [];
    let localnetProc: ChildProcess | null = null;
    let exitCode = 0;
    try {
        localnetProc = await startLocalnet();
        const actors = await setupActors();
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
        const { correctDomain, pingCiph } = await setupAppAndEncryptPing(actors, ace.aceDeployment, ace.adminAccountAddress, keypair0Id);
        const ctx: NonKeylessAccessFailureContext = {
            aceDeployment: ace.aceDeployment, moduleAddr: ace.adminAccountAddress,
            moduleName: 'access_control', functionName: 'check_permission',
            keypair0Id, correctDomain, wrongDomain: domainForBlob(actors.alice, 'other-blob'),
            pingCiph, bob: actors.bob, bobLabel: 'SingleKey/Ed25519', charlie: actors.charlie,
        };
        await runNonKeylessAccessFailureSteps(ctx, mauleAnySignatureEd25519);
        console.log('\n✅ All AnyPublicKey<Ed25519> access-control enforcement tests passed!\n');
    } catch (err) {
        console.error('\n❌ Test failed:', err);
        exitCode = 1;
    } finally {
        cleanup(workers, localnetProc);
        process.exit(exitCode);
    }
}

main();
