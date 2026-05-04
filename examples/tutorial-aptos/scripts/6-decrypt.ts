// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 6 — Bob decrypts song-1; song-2 stays sealed.
 *
 * This is the punchline of the tutorial. Bob runs the same decryption flow
 * twice, against two ciphertexts produced by the same Alice with the same
 * keypair. Buying song-1 grants Bob exactly song-1: the on-chain
 * `check_permission` is bound to the item name (the encryption "domain"),
 * and Bob did not pay for song-2.
 */

import {
    Account, AccountAddress, Ed25519PrivateKey,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

import {
    BOB_FILE, CATALOG_FILE, CONFIG_FILE, CatalogEntry, CatalogFile, ConfigFile, AccountFile, ITEMS,
    log, readJson,
} from './common.js';

async function main() {
    const cfg = readJson<ConfigFile>(CONFIG_FILE);
    const catalog = readJson<CatalogFile>(CATALOG_FILE);
    const bobFile = readJson<AccountFile>(BOB_FILE);
    const bob = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(bobFile.privateKeyHex) });
    const appContractAddr = AccountAddress.fromString(cfg.appContractAddr);

    const { chainId, aceDeployment, keypairId } = ACE.knownDeployments.preview20260504;

    async function tryDecrypt(entry: CatalogEntry): Promise<{ ok: boolean; plaintext?: string }> {
        const session = ACE.AptosBasicFlow.DecryptionSession.create({
            aceDeployment,
            keypairId,
            chainId,
            moduleAddr: appContractAddr,
            moduleName: 'marketplace',
            functionName: 'check_permission',
            domain: new TextEncoder().encode(entry.name),
            ciphertext: Buffer.from(entry.ciphertextHex, 'hex'),
        });
        const msgToSign = await session.getRequestToSign();
        const result = await session.decryptWithProof({
            userAddr: bob.accountAddress,
            publicKey: bob.publicKey,
            signature: bob.sign(msgToSign),
        });
        if (!result.isOk) return { ok: false };
        return { ok: true, plaintext: new TextDecoder().decode(result.okValue!) };
    }

    const bought = catalog.items.find(i => i.name === ITEMS[0].name)!;
    const notBought = catalog.items.find(i => i.name === ITEMS[1].name)!;

    log(`Attempting to decrypt "${bought.name}" (Bob bought this)...`);
    const r1 = await tryDecrypt(bought);
    if (!r1.ok) {
        console.error(`ERROR: Bob should have decrypted "${bought.name}".`);
        process.exit(1);
    }
    log(`✓ Decryption succeeded.`);
    log(`  Plaintext: "${r1.plaintext}"`);
    if (r1.plaintext !== ITEMS[0].plaintext) {
        console.error(`ERROR: plaintext mismatch (expected "${ITEMS[0].plaintext}")`);
        process.exit(1);
    }

    log('');
    log(`Attempting to decrypt "${notBought.name}" (Bob did NOT buy this)...`);
    const r2 = await tryDecrypt(notBought);
    if (r2.ok) {
        console.error(`UNEXPECTED: Bob decrypted "${notBought.name}" without paying.`);
        process.exit(1);
    }
    log(`✓ Decryption denied (expected).`);
    log(`  marketplace::check_permission(bob, "${notBought.name}") returned false.`);
    log('  Domain-binding holds: paying for one item does not unlock another.');
}

main().catch(err => { console.error(err); process.exit(1); });
