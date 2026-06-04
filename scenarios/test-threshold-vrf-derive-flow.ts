// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Threshold-VRF derive flow scenario.
 *
 * This follows the same shape as the other scenarios: start localnet, deploy
 * ACE contracts, register/spawn workers, run DKG, then drive the SDK API that
 * hits the Rust user request handler. Workers return encrypted tVRF shares;
 * the SDK verifies them against on-chain G2 share commitments, reconstructs
 * the threshold VRF value, and returns domain-separated random bytes.
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

import {
    fundAccount,
    cleanupScenario,
    assert,
    getNetworkState,
    log,
    proposeAndApprove,
    serializeCommitteeChangeProposal,
    sleep,
    waitFor,
} from './common/helpers';
import { setupAceOnLocalnet, SetupAceOnLocalnetResult } from './common/ace-network';

const TOTAL_WORKERS = 3;
const COMMITTEE = [0, 1, 2];
const THRESHOLD = 2;

function step(n: string | number, msg: string): void {
    console.log(`\n── Step ${n}: ${msg} ──`);
}

function transcriptField(msg: string, field: string): string {
    const prefix = `${field}: `;
    const line = msg.split('\n').find(l => l.startsWith(prefix));
    if (!line) throw new Error(`missing transcript field: ${field}`);
    return line.slice(prefix.length);
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
        const firstResponseEncKey = transcriptField(msg, 'responseEncKey');
        console.log(msg);

        step(3, 'Derive tVRF random bytes');
        const derived = await session.deriveWithSignature({
            pubKey: owner.publicKey,
            signature: owner.sign(msg),
        });
        assert(derived.length === 32, `tVRF output should be 32 bytes, got ${derived.length}`);
        console.log(`  randomBytes: 0x${Buffer.from(derived).toString('hex')}`);

        step(4, 'Advance one epoch while retaining the same tVRF keypair');
        const stateBeforeEpochChange = (await getNetworkState(ace.adminAccountAddress))
            .unwrapOrThrow('state read failed before epoch change');
        const targetEpoch = stateBeforeEpochChange.epoch + 1;
        const approvers = COMMITTEE.slice(0, THRESHOLD).map(i => ace.workerAccounts[i]!);
        await proposeAndApprove(
            approvers[0]!,
            approvers,
            actors.adminAddr,
            serializeCommitteeChangeProposal(
                COMMITTEE.map(i => ace.workerAccounts[i]!.accountAddress),
                THRESHOLD,
            ),
        );
        await waitFor(`epoch ${targetEpoch}`, async () => {
            const stateResult = await getNetworkState(ace.adminAccountAddress);
            if (!stateResult.isOk) return false;
            return stateResult.okValue!.epoch === targetEpoch;
        }, 120_000);
        console.log(`  Epoch advanced to ${targetEpoch}`);
        await sleep(30000);

        step(5, 'Repeat derivation in the next epoch with a fresh response key and the same label');
        const repeatSession = await ACE.tVRF.DerivationSession.create({
            aceDeployment: ace.aceDeployment,
            keypairId,
            label,
            accountAddress: owner.accountAddress,
        });
        const repeatMsg = await repeatSession.getRequestToSign();
        assert(
            transcriptField(repeatMsg, 'responseEncKey') !== firstResponseEncKey,
            'repeat session uses a fresh response encryption key',
        );
        assert(repeatMsg.includes(`epoch: ${targetEpoch}`), 'repeat transcript binds the next epoch');
        const repeat = await repeatSession.deriveWithSignature({
            pubKey: owner.publicKey,
            signature: owner.sign(repeatMsg),
        });
        assert(Buffer.from(repeat).equals(Buffer.from(derived)), 'same tVRF input should derive the same random bytes');
        log('tVRF shares verified, reconstructed, and deterministically hashed to random bytes.');
    } catch (err) {
        console.error('\nTest failed:', err);
        exitCode = 1;
    } finally {
        if (scenario) cleanupScenario(scenario.ace.workers, scenario.localnetProc);
        process.exit(exitCode);
    }
}

main();
