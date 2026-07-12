// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Account } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { rmSync } from 'fs';

import {
    deployAndInitAccessControl,
    domainForBlob,
    registerAllowlistBlob,
} from './common/access-control-app';
import { setupAceOnLocalnet, type SetupAceOnLocalnetResult } from './common/ace-network';
import { buildAptosWalletFullMessage } from './common/aptos-wallet-message';
import { CHAIN_ID } from './common/config';
import { assert, cleanupScenario, createAptos, fundAccount, log } from './common/helpers';

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

        const bob = Account.generate();
        await fundAccount(bob.accountAddress);
        const { actors, ace, keypairIds } = setup;
        await deployAndInitAccessControl(actors.admin, actors.adminAddr, actors.adminKeyHex);
        await registerAllowlistBlob(
            createAptos(),
            actors.alice,
            bob.accountAddress,
            actors.adminAddr,
            'ping-blob',
        );
        const correctDomain = domainForBlob(actors.alice, 'ping-blob');
        const pingCiph = (await ACE.IBE_Aptos.encrypt({
            aceDeployment: ace.aceDeployment,
            keypairId: keypairIds[0]!,
            chainId: CHAIN_ID,
            moduleAddr: ace.adminAccountAddress,
            moduleName: 'access_control',
            label: correctDomain,
            plaintext: new TextEncoder().encode('PING'),
        })).unwrapOrThrow('basic IBE encrypt');

        const session = await ACE.IBE_Aptos.BasicDecryptionSession.create({
            aceDeployment: ace.aceDeployment,
            keypairId: keypairIds[0]!,
            chainId: CHAIN_ID,
            moduleAddr: ace.adminAccountAddress,
            moduleName: 'access_control',
            label: correctDomain,
            ciphertext: pingCiph,
        });
        const message = await session.getRequestToSign();
        const fullMessage = buildAptosWalletFullMessage({
            accountAddress: bob.accountAddress,
            chainId: CHAIN_ID,
            message,
            nonce: 'ibe-aptos-basic',
        });
        const plaintext = await session.decryptWithProof({
            userAddr: bob.accountAddress,
            publicKey: bob.publicKey,
            signature: bob.sign(fullMessage),
            fullMessage,
        });

        assert(plaintext.isOk, `basic IBE decrypt failed: ${plaintext.errValue}`);
        assert(new TextDecoder().decode(plaintext.okValue!) === 'PING', 'basic IBE plaintext mismatch');
        log('ibe-Aptos-basic passed');
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
