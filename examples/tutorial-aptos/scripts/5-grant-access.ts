// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 5 — Alice adds Bob to the allowlist for the blob.
 */

import {
    Account, AccountAddress, Aptos, AptosConfig, Ed25519PrivateKey, Network,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

import {
    ALICE_FILE, AccountFile, BLOB_NAME, BOB_FILE, CONFIG_FILE, ConfigFile,
    log, readJson,
} from './common.js';

async function main() {
    const aliceFile = readJson<AccountFile>(ALICE_FILE);
    const bobFile = readJson<AccountFile>(BOB_FILE);
    const cfg = readJson<ConfigFile>(CONFIG_FILE);
    const alice = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(aliceFile.privateKeyHex) });

    const { aceDeployment } = ACE.knownDeployments.preview20260501;
    const aptos = new Aptos(new AptosConfig({ network: Network.CUSTOM, fullnode: aceDeployment.apiEndpoint }));

    const domain = Array.from(new TextEncoder().encode(BLOB_NAME));
    const bobAddr = AccountAddress.fromString(bobFile.address);

    log(`Alice granting access to ${bobFile.address}...`);
    const txn = await aptos.transaction.build.simple({
        sender: alice.accountAddress,
        data: {
            function: `${cfg.appContractAddr}::simple_acl::grant_access` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [domain, bobAddr],
        },
    });
    const submitted = await aptos.signAndSubmitTransaction({ signer: alice, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: submitted.hash });
    log(`✓ Bob is now in the allowlist (tx: ${submitted.hash})`);
    log('');
    log('Next: pnpm 6-decrypt-success');
}

main().catch(err => { console.error(err); process.exit(1); });
