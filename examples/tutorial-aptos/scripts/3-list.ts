// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 3 — Alice encrypts each item and lists it on the marketplace.
 *
 * Each ciphertext is bound to (keypairId, contractId(...::marketplace),
 * domain=itemName). ACE workers will only release a key share when a caller's
 * decryption attempt makes `on_ace_decryption_request(itemName, user, origin)` return true —
 * which happens exactly when that user has paid for that specific item.
 */

import {
    Account, AccountAddress, Aptos, AptosConfig, Ed25519PrivateKey, Network,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

import {
    ALICE_FILE, AccountFile, CATALOG_FILE, CONFIG_FILE, CatalogEntry, ConfigFile, ITEMS,
    ensureDataDir, log, readJson, writeJson,
    TUTORIAL_ACE_DEPLOYMENT, TUTORIAL_CHAIN_ID, TUTORIAL_KEYPAIR_ID,
} from './common.js';

async function main() {
    ensureDataDir();

    const aliceFile = readJson<AccountFile>(ALICE_FILE);
    const cfg = readJson<ConfigFile>(CONFIG_FILE);
    const alice = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(aliceFile.privateKeyHex) });
    const appContractAddr = AccountAddress.fromString(cfg.appContractAddr);

    const aceDeployment = TUTORIAL_ACE_DEPLOYMENT;
    const chainId       = TUTORIAL_CHAIN_ID;
    const keypairId     = TUTORIAL_KEYPAIR_ID;
    const aptos = new Aptos(new AptosConfig({ network: Network.CUSTOM, fullnode: aceDeployment.apiEndpoint }));
    const textEncoder = new TextEncoder();

    const entries: CatalogEntry[] = [];
    for (const item of ITEMS) {
        const domain = textEncoder.encode(item.name);

        log(`Encrypting "${item.name}"...`);
        const ciphertext = (await ACE.IBE_Aptos.encrypt({
            aceDeployment,
            keypairId,
            chainId,
            moduleAddr: appContractAddr,
            moduleName: 'marketplace',
            label: domain,
            plaintext: textEncoder.encode(item.plaintext),
        })).unwrapOrThrow('encrypt failed');
        log(`  Encrypted (${ciphertext.length} bytes).`);

        log(`Listing "${item.name}" at ${item.priceOctas / 100_000_000} APT...`);
        const txn = await aptos.transaction.build.simple({
            sender: alice.accountAddress,
            data: {
                function: `${cfg.appContractAddr}::marketplace::list_item` as `${string}::${string}::${string}`,
                typeArguments: [],
                functionArguments: [Array.from(domain), item.priceOctas.toString()],
            },
        });
        const submitted = await aptos.signAndSubmitTransaction({ signer: alice, transaction: txn });
        await aptos.waitForTransaction({ transactionHash: submitted.hash });
        log(`  Listed (tx: ${submitted.hash})`);

        entries.push({
            name: item.name,
            priceOctas: item.priceOctas,
            ciphertextHex: Buffer.from(ciphertext).toString('hex'),
        });
    }

    writeJson(CATALOG_FILE, { items: entries });
    log(`Saved catalog to ${CATALOG_FILE}`);
    log('');
    log('Next: pnpm 4-decrypt-fail');
}

main().catch(err => { console.error(err); process.exit(1); });
