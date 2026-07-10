// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Compatibility scenario for VSS feature configs.
 *
 * Flow:
 *   1. Deploy ACE with `Issue154FixFlag` deliberately uninitialized/disabled.
 *   2. Run one DKG epoch change and assert its VSS session snapshots are disabled.
 *   3. Admin enables `Issue154FixFlag`.
 *   4. Run the next epoch change and assert its newly-created VSS session snapshots are enabled.
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
        if (dkrSession.secretlyScaledElement.toHex() !== dkgSession.resultPk.toHex()) {
            throw new Error(
                `reshared PK mismatch\n  before: ${dkgSession.resultPk.toHex()}\n  after:  ${dkrSession.secretlyScaledElement.toHex()}`,
            );
        }
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
