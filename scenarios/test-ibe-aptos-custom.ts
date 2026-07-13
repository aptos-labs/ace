// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import * as ACE from '@aptos-labs/ace-sdk';
import { pke } from '@aptos-labs/ace-sdk';
import { rmSync } from 'fs';
import * as path from 'path';

import { setupAceOnLocalnet, type SetupAceOnLocalnetResult } from './common/ace-network';
import { CHAIN_ID, REPO_ROOT } from './common/config';
import { assert, cleanupScenario, fundAccount, log, submitTxn } from './common/helpers';
import { deployContract } from './common/infra';

const CONTRACT_DIR = path.join(REPO_ROOT, 'scenarios', 'custom-flow-aptos', 'contract');

async function main(): Promise<void> {
    let setup: SetupAceOnLocalnetResult | undefined;
    try {
        setup = await setupAceOnLocalnet({
            totalWorkers: 3,
            epoch0WorkerIndices: [0, 1, 2],
            epoch0Threshold: 2,
            fundAccount,
            numKeypairs: 1,
            dkgPrimitive: ACE.network.PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEAD,
            postDkgSettleMs: 5_000,
        });
        const { actors, ace, keypairIds } = setup;
        await deployContract(CONTRACT_DIR, actors.adminAddr, actors.adminKeyHex);
        (await submitTxn({
            signer: actors.admin,
            entryFunction: `${actors.adminAddr}::check_acl_demo::initialize`,
            args: [],
        })).unwrapOrThrow('initialize custom ACL').asSuccessOrThrow();

        const label = new TextEncoder().encode('custom-content');
        const accessCode = new TextEncoder().encode('open-sesame');
        (await submitTxn({
            signer: actors.admin,
            entryFunction: `${actors.adminAddr}::check_acl_demo::set_access_code`,
            args: [Array.from(label), Array.from(accessCode)],
        })).unwrapOrThrow('set custom ACL code').asSuccessOrThrow();

        const ciphertext = (await ACE.IBE_Aptos.encrypt({
            aceDeployment: ace.aceDeployment,
            keypairId: keypairIds[0]!,
            chainId: CHAIN_ID,
            moduleAddr: ace.adminAccountAddress,
            moduleName: 'check_acl_demo',
            label,
            plaintext: new TextEncoder().encode('HELLO CUSTOM FLOW'),
        })).unwrapOrThrow('custom IBE encrypt');
        const callerKeys = await pke.keygen();
        const baseArgs = {
            ciphertext,
            label,
            encPk: callerKeys.encryptionKey.toBytes(),
            encSk: callerKeys.decryptionKey.toBytes(),
            aceDeployment: ace.aceDeployment,
            keypairId: keypairIds[0]!,
            chainId: CHAIN_ID,
            moduleAddr: ace.adminAccountAddress,
            moduleName: 'check_acl_demo',
        };

        const rejected = await ACE.IBE_Aptos.decryptCustomFlow({
            ...baseArgs,
            payload: new TextEncoder().encode('wrong-code'),
        });
        assert(!rejected.isOk, 'custom IBE must reject an invalid proof payload');

        const plaintext = (await ACE.IBE_Aptos.decryptCustomFlow({
            ...baseArgs,
            payload: accessCode,
        })).unwrapOrThrow('custom IBE decrypt');
        assert(
            new TextDecoder().decode(plaintext) === 'HELLO CUSTOM FLOW',
            'custom IBE plaintext mismatch',
        );
        log('ibe-aptos-custom passed');
    } finally {
        if (setup) {
            cleanupScenario(setup.ace.workers, setup.localnetProc);
            rmSync(setup.ace.vssStoreTmpRoot, { recursive: true, force: true });
        }
    }
}

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});
