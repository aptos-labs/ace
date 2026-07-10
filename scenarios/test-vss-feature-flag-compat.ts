// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Compatibility scenario for VSS feature configs.
 *
 * Flow:
 *   1. Deploy ACE with `Issue154FixFlag` deliberately uninitialized/disabled.
 *   2. Run one DKG epoch change and assert its VSS session snapshots are disabled and reconstruct correctly.
 *   3. Admin enables `Issue154FixFlag`.
 *   4. Run the next epoch change and assert its newly-created VSS session snapshots are enabled and reconstruct correctly.
 */

import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import * as ace from '@aptos-labs/ace-sdk';

import {
    deployContracts,
    enableVssIssue154FixFlag,
    fundAccount,
    getDKGSession,
    getDKRSession,
    getNetworkState,
    getVssSession,
    getVssIssue154FixFlag,
    log,
    proposeAndApprove,
    serializeCommitteeChangeProposal,
    serializeNewSecretProposal,
    sleep,
    startLocalnet,
    submitTxn,
} from './common/helpers';
import { buildRustWorkspace, spawnNetworkNode } from './common/network-clients';

const ACE_CONTRACTS = [
    'pke',
    'worker_config',
    'group',
    'secret-usage',
    'fiat-shamir-transform',
    'sigma-dlog-linear',
    'pedersen-polynomial-commitment',
    'vss',
    'dkg',
    'dkr',
    'epoch-change',
    'voting',
    'network',
];

type PkeKeypair = Awaited<ReturnType<typeof ace.pke.keygen>>;

async function waitForEpoch(
    aceContractAddr: AccountAddress,
    targetEpoch: number,
    timeoutMs: number,
): Promise<ace.network.State> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        const state = (await getNetworkState(aceContractAddr))
            .unwrapOrThrow(`getNetworkState while waiting for epoch ${targetEpoch}`);
        if (state.epoch >= targetEpoch) return state;
        await sleep(5_000);
    }
    throw new Error(`Timed out waiting for epoch ${targetEpoch}`);
}

async function expectIssue154Flag(
    aceContractAddr: AccountAddress,
    configAddr: AccountAddress,
    expected: boolean,
    label: string,
): Promise<void> {
    const enabled = (await getVssIssue154FixFlag(aceContractAddr, configAddr))
        .unwrapOrThrow(`feature config view failed for ${label}`);
    if (enabled !== expected) {
        throw new Error(`${label}: expected Issue154FixFlag=${expected}, got ${enabled}`);
    }
}

async function expectVssSessionIssue154Flags(
    aceContractAddr: AccountAddress,
    vssSessions: AccountAddress[],
    expected: boolean,
    label: string,
): Promise<void> {
    if (vssSessions.length === 0) {
        throw new Error(`${label}: expected at least one VSS session`);
    }
    for (let i = 0; i < vssSessions.length; i++) {
        await expectIssue154Flag(
            aceContractAddr,
            vssSessions[i]!,
            expected,
            `${label} vss_sessions[${i}]`,
        );
    }
}

async function verifyDkgCorrectness(args: {
    aceContractAddr: AccountAddress;
    dkgSession: ace.dkg.Session;
    encKeypairs: PkeKeypair[];
    numWorkers: number;
}): Promise<void> {
    const { aceContractAddr, dkgSession, encKeypairs, numWorkers } = args;
    if (!dkgSession.resultPk) throw new Error('DKG resultPk absent');
    if (dkgSession.basePoint.scheme !== ace.vss.SCHEME_BLS12381G2) {
        throw new Error(`expected DKG base_point scheme=${ace.vss.SCHEME_BLS12381G2}, got ${dkgSession.basePoint.scheme}`);
    }

    const contributingIndices = dkgSession.doneFlags
        .map((done, i) => (done ? i : -1))
        .filter(i => i >= 0);
    if (contributingIndices.length < dkgSession.threshold) {
        throw new Error(`not enough DKG contributors: got ${contributingIndices.length}, need ${dkgSession.threshold}`);
    }

    const subShares: ace.vss.SecretShare[][] = [];
    for (const i of contributingIndices) {
        const vssSession = (await getVssSession(aceContractAddr, dkgSession.vssSessions[i]!))
            .unwrapOrThrow(`Failed to fetch DKG VSS session ${i}.`);
        const sharesForVss: ace.vss.SecretShare[] = [];
        for (let j = 0; j < numWorkers; j++) {
            const msgBytes = (await ace.pke.decrypt({
                decryptionKey: encKeypairs[j]!.decryptionKey,
                ciphertext: vssSession.dealerContribution0!.privateShareMessages[j]!,
            })).unwrapOrThrow(`Failed to decrypt DKG sub-share (vss=${i}, worker=${j}).`);
            const msg = ace.vss.PrivateShareMessage.fromBytes(msgBytes)
                .unwrapOrThrow(`Failed to parse DKG PrivateShareMessage (vss=${i}, worker=${j}).`);
            sharesForVss.push(msg.share);
        }
        subShares.push(sharesForVss);
    }

    const combinedShares: ace.vss.SecretShare[] = Array.from({ length: numWorkers }, (_, j) =>
        subShares.slice(1).reduce((acc, sharesForVss) => acc.add(sharesForVss[j]!), subShares[0]![j]!),
    );
    const reconstructedSecret = ace.vss.reconstruct({
        indexedShares: combinedShares
            .slice(0, dkgSession.threshold)
            .map((share, j) => ({ index: j + 1, share })),
    }).unwrapOrThrow('Failed to reconstruct DKG combined secret.');
    if (reconstructedSecret.scheme !== ace.vss.SCHEME_BLS12381G2) {
        throw new Error(`expected reconstructed DKG scheme=${ace.vss.SCHEME_BLS12381G2}, got ${reconstructedSecret.scheme}`);
    }

    const computedPk = dkgSession.basePoint.scale(reconstructedSecret);
    if (!computedPk.equals(dkgSession.resultPk)) {
        throw new Error('Reconstructed DKG secret does not match resultPk.');
    }
}

async function verifyDkrCorrectness(args: {
    aceContractAddr: AccountAddress;
    dkrSession: ace.dkr.Session;
    encKeypairs: PkeKeypair[];
    numWorkers: number;
    threshold: number;
    baselinePk: ace.vss.PublicPoint;
}): Promise<void> {
    const { aceContractAddr, dkrSession, encKeypairs, numWorkers, threshold, baselinePk } = args;
    if (dkrSession.publicBaseElement.scheme !== ace.vss.SCHEME_BLS12381G2) {
        throw new Error(`expected DKR publicBaseElement scheme=${ace.vss.SCHEME_BLS12381G2}, got ${dkrSession.publicBaseElement.scheme}`);
    }

    const contributingIndices = dkrSession.vssContributionFlags
        .map((flag, j) => (flag ? j : -1))
        .filter(j => j >= 0);
    if (contributingIndices.length < threshold) {
        throw new Error(`not enough DKR contributors: got ${contributingIndices.length}, need ${threshold}`);
    }

    const subShares: ace.vss.SecretShare[][] = [];
    for (const j of contributingIndices) {
        const vssSession = (await getVssSession(aceContractAddr, dkrSession.vssSessions[j]!))
            .unwrapOrThrow(`Failed to fetch DKR VSS session ${j}.`);
        const sharesForVss: ace.vss.SecretShare[] = [];
        for (let m = 0; m < numWorkers; m++) {
            const msgBytes = (await ace.pke.decrypt({
                decryptionKey: encKeypairs[m]!.decryptionKey,
                ciphertext: vssSession.dealerContribution0!.privateShareMessages[m]!,
            })).unwrapOrThrow(`Failed to decrypt DKR sub-share (vss=${j}, new_member=${m}).`);
            const msg = ace.vss.PrivateShareMessage.fromBytes(msgBytes)
                .unwrapOrThrow(`Failed to parse DKR PrivateShareMessage (vss=${j}, new_member=${m}).`);
            sharesForVss.push(msg.share);
        }
        subShares.push(sharesForVss);
    }

    const dkrCombinedShares: ace.vss.SecretShare[] = Array.from({ length: numWorkers }, (_, m) => {
        const combinedScalar = ace.vss.reconstruct({
            indexedShares: contributingIndices.map((j, vi) => ({
                index: j + 1,
                share: subShares[vi]![m]!,
            })),
        }).unwrapOrThrow(`Failed to Lagrange-combine DKR sub-shares for member ${m}.`);
        const ps = combinedScalar.asBls12381G2();
        const innerShare = new ace.group.bls12381G2.SecretShare(ps.scalar);
        return new ace.vss.SecretShare(ace.vss.SCHEME_BLS12381G2, innerShare);
    });

    const reconstructedSecret = ace.vss.reconstruct({
        indexedShares: dkrCombinedShares
            .slice(0, threshold)
            .map((share, m) => ({ index: m + 1, share })),
    }).unwrapOrThrow('Failed to reconstruct DKR combined secret.');
    if (reconstructedSecret.scheme !== ace.vss.SCHEME_BLS12381G2) {
        throw new Error(`expected reconstructed DKR scheme=${ace.vss.SCHEME_BLS12381G2}, got ${reconstructedSecret.scheme}`);
    }

    const computedPk = dkrSession.publicBaseElement.scale(reconstructedSecret);
    if (!computedPk.equals(dkrSession.secretlyScaledElement)) {
        throw new Error('Reconstructed DKR secret does not match secretlyScaledElement.');
    }
    if (!computedPk.equals(baselinePk)) {
        throw new Error(
            `Reconstructed DKR public key does not match baseline.\n  baseline: ${baselinePk.toHex()}\n  got:      ${computedPk.toHex()}`,
        );
    }
}

async function main() {
    const localnetProc = await startLocalnet();
    const nodeProcs: ReturnType<typeof spawnNetworkNode>[] = [];

    try {
        const numWorkers = 3;
        const threshold = 2;
        const accounts: Account[] = Array.from({ length: numWorkers + 1 }, () => Account.generate());
        const encKeypairs = await Promise.all(
            Array.from({ length: numWorkers }, () => ace.pke.keygen()),
        );
        for (const account of accounts) {
            await fundAccount(account.accountAddress);
        }

        const adminAccount = accounts[numWorkers]!;
        const workerAccounts = accounts.slice(0, numWorkers);
        const aceContract = adminAccount.accountAddress.toStringLong();
        const aceContractAddr = adminAccount.accountAddress;

        log('Deploy contracts with VSS Issue154FixFlag deliberately disabled.');
        await deployContracts(adminAccount, ACE_CONTRACTS, {
            enableVssIssue154FixFlag: false,
        });
        await expectIssue154Flag(
            aceContractAddr,
            aceContractAddr,
            false,
            'deployment-global config before enable',
        );

        log('Register PKE enc keys.');
        for (let i = 0; i < numWorkers; i++) {
            (await submitTxn({
                signer: workerAccounts[i]!,
                entryFunction: `${aceContract}::worker_config::register_pke_enc_key`,
                args: [encKeypairs[i]!.encryptionKey.toBytes()],
            })).unwrapOrThrow('register_pke_enc_key failed').asSuccessOrThrow();
        }

        log('Build network-node and start workers.');
        await buildRustWorkspace();
        for (let i = 0; i < numWorkers; i++) {
            nodeProcs.push(spawnNetworkNode({
                runAs: workerAccounts[i]!,
                pkeDkHex: `0x${Buffer.from(encKeypairs[i]!.decryptionKey.toBytes()).toString('hex')}`,
                aceDeploymentAddr: aceContract,
            }));
        }

        log('Start initial epoch.');
        (await submitTxn({
            signer: adminAccount,
            entryFunction: `${aceContract}::network::start_initial_epoch`,
            args: [workerAccounts.map(w => w.accountAddress), threshold, 600],
        })).unwrapOrThrow('start_initial_epoch failed').asSuccessOrThrow();

        log('Run first epoch change while feature flag is disabled.');
        const approvers = workerAccounts.slice(0, threshold);
        await proposeAndApprove(
            approvers[0]!,
            approvers,
            aceContract,
            serializeNewSecretProposal(1, 'compat-before-enable'),
        );
        const state1 = await waitForEpoch(aceContractAddr, 1, 120_000);
        const dkgSessionAddr = state1.secrets[0]?.currentSession;
        if (!dkgSessionAddr) throw new Error('missing DKG session after epoch 1');
        const dkgSession = (await getDKGSession(aceContractAddr, dkgSessionAddr))
            .unwrapOrThrow('get DKG session after epoch 1');
        if (!dkgSession.resultPk) throw new Error('DKG resultPk absent after epoch 1');
        await verifyDkgCorrectness({
            aceContractAddr,
            dkgSession,
            encKeypairs,
            numWorkers,
        });
        await expectVssSessionIssue154Flags(
            aceContractAddr,
            dkgSession.vssSessions,
            false,
            'pre-enable DKG',
        );

        log('Admin enables Issue154FixFlag.');
        await enableVssIssue154FixFlag(adminAccount, aceContract);
        await expectIssue154Flag(
            aceContractAddr,
            aceContractAddr,
            true,
            'deployment-global config after enable',
        );

        log('Run next epoch change after feature flag is enabled.');
        await proposeAndApprove(
            approvers[0]!,
            approvers,
            aceContract,
            serializeCommitteeChangeProposal(workerAccounts.map(w => w.accountAddress), threshold),
        );
        const state2 = await waitForEpoch(aceContractAddr, 2, 120_000);
        const dkrSessionAddr = state2.secrets[0]?.currentSession;
        if (!dkrSessionAddr) throw new Error('missing DKR session after epoch 2');
        const dkrSession = (await getDKRSession(aceContractAddr, dkrSessionAddr))
            .unwrapOrThrow('get DKR session after epoch 2');
        await verifyDkrCorrectness({
            aceContractAddr,
            dkrSession,
            encKeypairs,
            numWorkers,
            threshold,
            baselinePk: dkgSession.resultPk,
        });
        await expectVssSessionIssue154Flags(
            aceContractAddr,
            dkrSession.vssSessions,
            true,
            'post-enable DKR',
        );

        log('VSS feature flag compatibility scenario passed.');
    } finally {
        for (const proc of nodeProcs) proc.kill();
        localnetProc.kill();
    }
}

main();
