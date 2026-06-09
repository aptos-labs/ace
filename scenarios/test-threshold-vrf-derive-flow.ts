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
 *   const session = await ACE.VRF_Aptos.DerivationSession.create({
 *       aceDeployment,
 *       keypairId,
 *       contractId,
 *       label,
 *       accountAddress,
 *   });
 *   const msg = await session.getRequestToSign();
 *   const fullMessage = wallet.signMessage({ application: true, message: msg, ... }).fullMessage;
 *   const derivedBytes = await session.deriveWithSignature({
 *       pubKey: account.publicKey,
 *       signature: account.sign(fullMessage),
 *       fullMessage,
 *   });
 */

import * as ACE from '@aptos-labs/ace-sdk';
import * as path from 'path';

import {
    fundAccount,
    cleanupScenario,
    assert,
    ed25519PrivateKeyHex,
    getNetworkState,
    log,
    prepareContractsPublishScratch,
    publishMovePackage,
    proposeAndApprove,
    rmContractsPublishScratch,
    serializeCommitteeChangeProposal,
    sleep,
    waitFor,
} from './common/helpers';
import { setupAceOnLocalnet, SetupAceOnLocalnetResult } from './common/ace-network';
import { CHAIN_ID, REPO_ROOT } from './common/config';
import { ACE_SCENARIO_APP_ORIGIN, buildAptosWalletFullMessage } from './common/aptos-wallet-message';

const TOTAL_WORKERS = 3;
const COMMITTEE = [0, 1, 2];
const THRESHOLD = 2;

function step(n: string | number, msg: string): void {
    console.log(`\n── Step ${n}: ${msg} ──`);
}

async function deployOriginContract(admin: SetupAceOnLocalnetResult['actors']['admin']): Promise<void> {
    const contractRoot = path.join(REPO_ROOT, 'scenarios', 'threshold-vrf-origin', 'contract');
    const scratch = prepareContractsPublishScratch(contractRoot, admin.accountAddress.toStringLong());
    try {
        await publishMovePackage(scratch.contractsDir, ed25519PrivateKeyHex(admin));
    } finally {
        rmContractsPublishScratch(scratch);
    }
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
            dkgPrimitive: ACE.network.PRIMITIVE_BLS12381_THRESHOLD_VRF,
        });
        const { actors, ace, keypairIds } = scenario;
        const owner = actors.alice;
        const keypairId = keypairIds[0]!;

        step('0b', 'Publish tVRF origin-check contract');
        await deployOriginContract(actors.admin);
        const contractId = ACE.ContractID.newAptos({
            chainId: CHAIN_ID,
            moduleAddr: actors.admin.accountAddress,
            moduleName: 'threshold_vrf_origin_demo',
        });
        console.log(`  contract: ${actors.admin.accountAddress.toStringLong()}::threshold_vrf_origin_demo::on_ace_vrf_request`);
        console.log(`  origin:   ${ACE_SCENARIO_APP_ORIGIN}`);

        step(1, 'Build tVRF label');
        const label = new TextEncoder().encode('label-1');
        console.log(`  owner:    ${owner.accountAddress.toStringLong()}`);
        console.log(`  keypair:  ${keypairId.toStringLong()}`);
        console.log('  label:    label-1');

        step(2, 'Ask TS SDK for the canonical tVRF request to sign');
        const session = await ACE.VRF_Aptos.DerivationSession.create({
            aceDeployment: ace.aceDeployment,
            keypairId,
            contractId,
            label,
            accountAddress: owner.accountAddress,
        });
        const msg = await session.getRequestToSign();
        // `getRequestToSign` now returns `"0x" + hex(BCS(ThresholdVrfRequestPayload))`.
        // Verify the wire-shape contract directly: it's hex, starts with 0x, and
        // the inner bytes BCS-decode back into a payload whose fields match what
        // we asked for.
        assert(msg.startsWith('0x') && /^0x[0-9a-f]+$/.test(msg), 'getRequestToSign returns hex');
        const firstPayload = ACE.VRF_Aptos.ThresholdVrfRequestPayload.fromBytes(
            Buffer.from(msg.slice(2), 'hex'),
        );
        assert(firstPayload.keypairId.toStringLong() === keypairId.toStringLong(), 'payload binds keypair id');
        assert(firstPayload.accountAddress.toStringLong() === owner.accountAddress.toStringLong(), 'payload binds owner account');
        assert(Buffer.from(firstPayload.label).equals(Buffer.from(label)), 'payload binds label');
        assert(firstPayload.contractId.toBytes().length > 0, 'payload binds contract id');
        const firstResponseEncKey = firstPayload.responseEncKey.toHex();
        console.log(msg);
        const fullMessage = buildAptosWalletFullMessage({
            accountAddress: owner.accountAddress.toStringLong(),
            chainId: CHAIN_ID,
            message: msg,
            nonce: 'threshold-vrf-derive-1',
        });

        step(3, 'Derive tVRF random bytes');
        const derived = await session.deriveWithSignature({
            pubKey: owner.publicKey,
            signature: owner.sign(fullMessage),
            fullMessage,
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
        const repeatSession = await ACE.VRF_Aptos.DerivationSession.create({
            aceDeployment: ace.aceDeployment,
            keypairId,
            contractId,
            label,
            accountAddress: owner.accountAddress,
        });
        const repeatMsg = await repeatSession.getRequestToSign();
        const repeatPayload = ACE.VRF_Aptos.ThresholdVrfRequestPayload.fromBytes(
            Buffer.from(repeatMsg.slice(2), 'hex'),
        );
        assert(
            repeatPayload.responseEncKey.toHex() !== firstResponseEncKey,
            'repeat session uses a fresh response encryption key',
        );
        assert(repeatPayload.epoch === targetEpoch, 'repeat payload binds the next epoch');
        const repeatFullMessage = buildAptosWalletFullMessage({
            accountAddress: owner.accountAddress.toStringLong(),
            chainId: CHAIN_ID,
            message: repeatMsg,
            nonce: 'threshold-vrf-derive-2',
        });
        const repeat = await repeatSession.deriveWithSignature({
            pubKey: owner.publicKey,
            signature: owner.sign(repeatFullMessage),
            fullMessage: repeatFullMessage,
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
