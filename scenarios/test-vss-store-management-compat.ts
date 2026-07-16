// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import type { ChildProcess } from 'child_process';
import { rmSync } from 'fs';

import {
    ACE_CONTRACTS,
    type AceNetworkState,
    runDkg,
    setupAceNetworkAndWorkers,
} from './common/ace-network';
import { LOCALNET_URL } from './common/config';
import {
    cleanupScenario,
    deployContracts,
    enableReachabilityBasedVssStoreManagementFlag,
    fundAccount,
    setupBaseAceActors,
    sleep,
    startLocalnet,
    waitFor,
} from './common/helpers';
import { spawnNetworkNodeMaybeSplit } from './common/network-clients';
import {
    assertVSSStoreRowsAbsent,
    assertVSSStoresHaveEpochColumns,
    assertVSSStoresHaveNoEpochColumns,
    insertUnreachableLegacyVSSStoreRows,
} from './common/vss/store-checks';

function spawnAceNetworkWorkers(network: AceNetworkState, adminAddr: string): ChildProcess[] {
    const workers: ChildProcess[] = [];
    for (let i = 0; i < network.workerAccounts.length; i++) {
        const pkeDkHex = `0x${Buffer.from(network.encKeypairs[i]!.decryptionKey.toBytes()).toString('hex')}`;
        workers.push(...spawnNetworkNodeMaybeSplit({
            index: i,
            total: network.workerAccounts.length,
            runAs: network.workerAccounts[i]!,
            pkeDkHex,
            sigSkHex: network.sigKeypairs[i]!.signingKey.toHex(),
            vssStoreUrl: network.storeUrls[i]!,
            nodeMsgListen: network.nodeMsgEndpoints.nodeMsgListens[i]!,
            aceDeploymentAddr: adminAddr,
            aceDeploymentApi: LOCALNET_URL,
            workerBasePort: network.nodeMsgEndpoints.basePort,
        }));
    }
    return workers;
}

async function stopWorkers(workers: ChildProcess[]): Promise<void> {
    for (const worker of workers) worker.kill('SIGTERM');
    await sleep(2_000);
}

async function main(): Promise<void> {
    let localnetProc: ChildProcess | null = null;
    let network: AceNetworkState | null = null;
    let liveWorkers: ChildProcess[] = [];

    try {
        localnetProc = await startLocalnet();
        const actors = await setupBaseAceActors();
        await deployContracts(
            actors.admin,
            [...ACE_CONTRACTS],
            LOCALNET_URL,
            { enableReachabilityBasedVssStoreManagement: false },
        );

        network = await setupAceNetworkAndWorkers({
            adminAccount: actors.admin,
            totalWorkers: 3,
            epoch0WorkerIndices: [0, 1, 2],
            epoch0Threshold: 2,
            fundAccount,
            reshareIntervalSecs: 600,
        });
        liveWorkers = network.workers;

        const approvers = network.epoch0WorkerAccounts.slice(0, 2);
        await runDkg({
            approvers,
            adminAddr: actors.adminAddr,
            adminAccountAddress: network.adminAccountAddress,
            expectedSecretsCountAfter: 1,
            label: 'legacy VSS store management',
        });

        assertVSSStoresHaveEpochColumns({ storeUrls: network.storeUrls });
        const unreachableSession = `0x${'0'.repeat(56)}facefeed`;
        insertUnreachableLegacyVSSStoreRows({
            storeUrls: network.storeUrls,
            sessionAddr: unreachableSession,
        });

        await stopWorkers(liveWorkers);
        liveWorkers = [];

        await enableReachabilityBasedVssStoreManagementFlag(actors.admin, LOCALNET_URL);
        liveWorkers = spawnAceNetworkWorkers(network, actors.adminAddr);
        network.workers = liveWorkers;

        await waitFor(
            'VSS store schema migrated and unreachable rows pruned after restart',
            async () => {
                try {
                    assertVSSStoresHaveNoEpochColumns({ storeUrls: network!.storeUrls });
                    assertVSSStoreRowsAbsent({
                        storeUrls: network!.storeUrls,
                        sessionAddr: unreachableSession,
                    });
                    return true;
                } catch {
                    return false;
                }
            },
            60_000,
            1_000,
        );

        await runDkg({
            approvers,
            adminAddr: actors.adminAddr,
            adminAccountAddress: network.adminAccountAddress,
            expectedSecretsCountAfter: 2,
            label: 'reachability-based VSS store management',
        });
        assertVSSStoresHaveNoEpochColumns({ storeUrls: network.storeUrls });

        console.log('VSS store management compatibility scenario passed.');
    } finally {
        cleanupScenario(liveWorkers, localnetProc);
        if (network) {
            rmSync(network.vssStoreTmpRoot, { recursive: true, force: true });
        }
    }
}

main().catch((e) => {
    console.error(e);
    process.exit(1);
});
