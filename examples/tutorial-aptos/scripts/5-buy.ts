// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 5 — Bob buys song-1.
 *
 * Bob signs a `marketplace::buy` transaction. The contract transfers the item's
 * price in APT from Bob to Alice and pushes Bob onto song-1's buyer list. From
 * this moment, `check_permission(bob, "song-1.mp3")` returns true; song-2 is
 * unaffected.
 */

import {
    Account, Aptos, AptosConfig, Ed25519PrivateKey, Network,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

import {
    BOB_FILE, CATALOG_FILE, CONFIG_FILE, CatalogFile, ConfigFile, AccountFile, ITEMS,
    log, readJson,
} from './common.js';

async function main() {
    const bobFile = readJson<AccountFile>(BOB_FILE);
    const cfg = readJson<ConfigFile>(CONFIG_FILE);
    const catalog = readJson<CatalogFile>(CATALOG_FILE);
    const bob = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(bobFile.privateKeyHex) });

    const { aceDeployment } = ACE.knownDeployments.preview20260501;
    const aptos = new Aptos(new AptosConfig({ network: Network.CUSTOM, fullnode: aceDeployment.apiEndpoint }));

    const target = catalog.items.find(i => i.name === ITEMS[0].name)!;
    const domain = Array.from(new TextEncoder().encode(target.name));

    log(`Bob buying "${target.name}" for ${target.priceOctas / 100_000_000} APT...`);
    const txn = await aptos.transaction.build.simple({
        sender: bob.accountAddress,
        data: {
            function: `${cfg.appContractAddr}::marketplace::buy` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [domain],
        },
    });
    const submitted = await aptos.signAndSubmitTransaction({ signer: bob, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: submitted.hash });
    log(`✓ Purchase complete (tx: ${submitted.hash})`);
    log(`  Bob is now on the buyer list for "${target.name}" — but not for any other item.`);
    log('');
    log('Next: pnpm 6-decrypt');
}

main().catch(err => { console.error(err); process.exit(1); });
