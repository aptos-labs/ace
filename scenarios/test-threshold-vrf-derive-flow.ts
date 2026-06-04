// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Threshold-VRF derive flow scenario for Shelby S3 bearer-token minting.
 *
 * This follows the same shape as the other scenarios: start localnet, deploy
 * ACE contracts, register/spawn workers, run DKG, then drive the SDK API that
 * should eventually hit the Rust user request handler. The handler is not
 * implemented yet, so the scenario currently pins the flow and expects the SDK
 * to stop at the explicit NotImplemented boundary.
 *
 * Desired SDK shape:
 *
 *   const req = await ACE.tVRF.requestToSign({
 *       aceDeployment,
 *       keypairId,
 *       label,
 *       accountAddress,
 *   });
 *   const derivedBytes = await ACE.tVRF({
 *       ...req,
 *       pubKey: account.publicKey,
 *       signature: account.sign(req.message),
 *   });
 */

import * as ACE from '@aptos-labs/ace-sdk';

import { fundAccount, cleanupScenario, assert, log } from './common/helpers';
import { setupAceOnLocalnet, SetupAceOnLocalnetResult } from './common/ace-network';

const TOTAL_WORKERS = 3;
const COMMITTEE = [0, 1, 2];
const THRESHOLD = 2;

function step(n: string | number, msg: string): void {
    console.log(`\n── Step ${n}: ${msg} ──`);
}

function shelbyS3Label(ownerAddr: string, blobId: string, tokenNonce: string): Uint8Array {
    return new TextEncoder().encode([
        'shelby-s3/access-token/v1',
        `owner=${ownerAddr}`,
        `blob_id=${blobId}`,
        `token_nonce=${tokenNonce}`,
    ].join('\n'));
}

async function main() {
    let scenario: SetupAceOnLocalnetResult | undefined;
    let exitCode = 0;

    try {
        step(0, 'Bring up ACE localnet and DKG one tVRF key');
        scenario = await setupAceOnLocalnet({
            totalWorkers: TOTAL_WORKERS,
            epoch0WorkerIndices: COMMITTEE,
            epoch0Threshold: THRESHOLD,
            fundAccount,
            numKeypairs: 1,
            postDkgSettleMs: 0,
        });
        const { actors, ace, keypairIds } = scenario;
        const owner = actors.alice;
        const keypairId = keypairIds[0]!;

        step(1, 'Build Shelby S3 tVRF label');
        const blobId = 'shelby-s3://alice-bucket/contracts/acquisition-plan.txt';
        const tokenNonce = 'token-0001';
        const label = shelbyS3Label(owner.accountAddress.toStringLong(), blobId, tokenNonce);
        console.log(`  owner:    ${owner.accountAddress.toStringLong()}`);
        console.log(`  keypair:  ${keypairId.toStringLong()}`);
        console.log(`  blob id:  ${blobId}`);

        step(2, 'Ask TS SDK for the canonical tVRF request to sign');
        const req = await ACE.tVRF.requestToSign({
            aceDeployment: ace.aceDeployment,
            keypairId,
            label,
            accountAddress: owner.accountAddress,
        });
        assert(req.message.includes('ACE Threshold VRF Derive Request'), 'requestToSign returns tVRF transcript');
        assert(req.message.includes(keypairId.toStringLong()), 'transcript binds keypair id');
        assert(req.message.includes(owner.accountAddress.toStringLong()), 'transcript binds owner account');
        assert(req.message.includes('responseEncKey:'), 'transcript binds response encryption key');
        console.log(req.message);

        step(3, 'Call future tVRF derive API');
        try {
            await ACE.tVRF({
                ...req,
                pubKey: owner.publicKey,
                signature: owner.sign(req.message),
            });
            throw new Error('ACE.tVRF unexpectedly succeeded before Rust handler exists');
        } catch (err) {
            const msg = String(err);
            assert(
                msg.includes('threshold VRF worker handler is not implemented yet'),
                `expected tVRF NotImplemented boundary, got: ${msg}`,
            );
            log('tVRF SDK API shape is pinned; Rust user request handler remains TODO.');
        }
    } catch (err) {
        console.error('\nTest failed:', err);
        exitCode = 1;
    } finally {
        if (scenario) cleanupScenario(scenario.ace.workers, scenario.localnetProc);
        process.exit(exitCode);
    }
}

main();
