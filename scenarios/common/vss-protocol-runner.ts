// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import type { ChildProcess } from 'child_process';
import { mkdtempSync, rmSync } from 'fs';
import * as os from 'os';
import * as path from 'path';

import { log, startLocalnet } from './helpers';
import { buildRustWorkspace } from './vss-clients';
import {
    assertVSSSessionShape,
    makePcsContext,
    makePreviousCommitmentFixture,
    type VSSProtocolScenarioOptions,
} from './vss-protocol-fixtures';
import {
    createFundedVSSActors,
    deployVSSContracts,
    makeNodeMsgEndpoints,
    registerVSSWorkers,
    spawnVSSClients,
    startVSSSession,
    startVSSStores,
    type VSSStoreSetup,
    waitForCompletedVssSession,
} from './vss-protocol-setup';
import {
    assertVSSHolderShareRows,
    assertVSSPublicKeys,
    assertVSSSecretReconstruction,
    assertVSSStoresHaveNoEpochColumns,
} from './vss/store-checks';

export type { VSSProtocolScenarioOptions } from './vss-protocol-fixtures';

export async function runVSSProtocolScenario(opts: VSSProtocolScenarioOptions): Promise<void> {
    const localnetProc = await startLocalnet();
    const tmpRoot = mkdtempSync(path.join(os.tmpdir(), opts.tmpPrefix));
    let stores: VSSStoreSetup | undefined;
    let clientProcs: ChildProcess[] = [];

    try {
        const numWorkers = 4;
        const threshold = 3;
        const actors = await createFundedVSSActors(numWorkers);
        const aceContract = actors.adminAccount.accountAddress.toStringLong();
        const nodeMsgEndpoints = makeNodeMsgEndpoints(numWorkers);

        log('Deploy contracts.');
        await deployVSSContracts(actors.adminAccount);

        log('Register worker PKE keys, messaging signature keys, and node-msg endpoints.');
        await registerVSSWorkers({ actors, aceContract, nodeMsgEndpoints });

        const customPcsContext = opts.useCustomPcsContext ? makePcsContext(opts.scheme) : undefined;
        const previousFixture = opts.usePreviousCommitment
            ? makePreviousCommitmentFixture(opts.scheme)
            : undefined;

        log(`Start VSS session (${opts.label}).`);
        const sessionAddr = await startVSSSession({
            adminAccount: actors.adminAccount,
            dealerAccount: actors.dealerAccount,
            holderAccounts: actors.holderAccounts,
            aceContract,
            threshold,
            scheme: opts.scheme,
            pcsContextBytes: customPcsContext?.toBytes() ?? new Uint8Array(0),
            previousCommitmentBytes: previousFixture?.commitment.toBytes() ?? new Uint8Array(0),
        });

        log('Start VSS dealer and recipient clients.');
        await buildRustWorkspace();
        log('Start temporary Postgres processes for external VSS stores.');
        stores = startVSSStores(tmpRoot);
        clientProcs = spawnVSSClients({
            actors,
            aceContract,
            sessionAddr,
            storeUrls: stores.storeUrls,
            nodeMsgEndpoints,
            previousFixture,
        });

        log('Wait for VSS session to complete.');
        const session = await waitForCompletedVssSession(
            actors.adminAccount.accountAddress,
            sessionAddr,
        );
        assertVSSSessionShape({
            session,
            scenario: opts,
            customPcsContext,
            previousFixture,
        });

        log('Assert holder DB share rows.');
        assertVSSHolderShareRows({
            storeUrls: stores.storeUrls,
            sessionAddr,
            expectedRows: numWorkers,
        });
        assertVSSStoresHaveNoEpochColumns({ storeUrls: stores.storeUrls });

        log('Assert on-chain VSS result/share public keys against DB openings.');
        assertVSSPublicKeys({
            storeUrls: stores.storeUrls,
            sessionAddr,
            session,
            scheme: opts.scheme,
        });

        log('Reconstruct secret from holder DB shares.');
        await assertVSSSecretReconstruction({
            storeUrls: stores.storeUrls,
            sessionAddr,
            threshold,
            scheme: opts.scheme,
            expectedDealerSecret: previousFixture?.secret,
            label: opts.label,
        });
    } finally {
        for (const proc of clientProcs) proc.kill();
        for (const store of stores?.externalStores ?? []) store.stop();
        rmSync(tmpRoot, { recursive: true, force: true });
        localnetProc.kill();
    }
}
