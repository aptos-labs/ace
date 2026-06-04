// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Threshold-VRF derive flow scenario.
 *
 * This follows the same shape as the other scenarios: start localnet, deploy
 * ACE contracts, register/spawn workers, run DKG, then drive the SDK API that
 * hits the Rust user request handler. Workers return encrypted tVRF shares;
 * the scenario currently pins the next explicit TODO boundary at TS-side share
 * reconstruction.
 *
 * Desired SDK shape:
 *
 *   const session = await ACE.tVRF.DerivationSession.create({
 *       aceDeployment,
 *       keypairId,
 *       label,
 *       accountAddress,
 *   });
 *   const msg = await session.getRequestToSign();
 *   const derivedBytes = await session.deriveWithSignature({
 *       pubKey: account.publicKey,
 *       signature: account.sign(msg),
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
        });
        const { actors, ace, keypairIds } = scenario;
        const owner = actors.alice;
        const keypairId = keypairIds[0]!;

        step(1, 'Build tVRF label');
        const label = new TextEncoder().encode('label-1');
        console.log(`  owner:    ${owner.accountAddress.toStringLong()}`);
        console.log(`  keypair:  ${keypairId.toStringLong()}`);
        console.log('  label:    label-1');

        step(2, 'Ask TS SDK for the canonical tVRF request to sign');
        const session = await ACE.tVRF.DerivationSession.create({
            aceDeployment: ace.aceDeployment,
            keypairId,
            label,
            accountAddress: owner.accountAddress,
        });
        const msg = await session.getRequestToSign();
        assert(msg.includes('ACE Threshold VRF Derive Request'), 'getRequestToSign returns tVRF transcript');
        assert(msg.includes(keypairId.toStringLong()), 'transcript binds keypair id');
        assert(msg.includes(owner.accountAddress.toStringLong()), 'transcript binds owner account');
        assert(msg.includes('chainId:'), 'transcript binds chain id');
        assert(msg.includes('responseEncKey:'), 'transcript binds response encryption key');
        console.log(msg);

        step(3, 'Call future tVRF derive API');
        try {
            await session.deriveWithSignature({
                pubKey: owner.publicKey,
                signature: owner.sign(msg),
            });
            throw new Error('tVRF derive unexpectedly succeeded before reconstruction exists');
        } catch (err) {
            const msg = String(err);
            assert(
                msg.includes('threshold VRF reconstruction is not implemented yet'),
                `expected tVRF reconstruction boundary, got: ${msg}`,
            );
            log('tVRF workers returned shares; TS reconstruction remains TODO.');
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
