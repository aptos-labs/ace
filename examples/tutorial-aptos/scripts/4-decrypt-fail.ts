// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 4 — Bob shows up, gets a small allowance from Alice, and is denied.
 *
 * Bob is generated locally. The Aptos testnet faucet is rate-limited (5 calls
 * per day), so rather than asking the dev to fund a second account, Alice
 * sends Bob ~0.2 APT directly — enough to cover one item's price plus gas in
 * step 5. Bob then attempts to decrypt song-1 without having bought it; ACE
 * workers each simulate `marketplace::check_permission(bob, "song-1.mp3")`,
 * which returns false, so no key share is released.
 */

import {
    Account, AccountAddress, Aptos, AptosConfig, Ed25519PrivateKey, Network,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

import {
    ALICE_FILE, AccountFile, BOB_FILE, CATALOG_FILE, CONFIG_FILE, CatalogFile, ConfigFile, ITEMS,
    ensureDataDir, log, readJson, writeJson,
} from './common.js';

const BOB_ALLOWANCE_OCTAS = 20_000_000; // 0.2 APT — covers song-1 price + gas

async function main() {
    ensureDataDir();

    const aliceFile = readJson<AccountFile>(ALICE_FILE);
    const cfg = readJson<ConfigFile>(CONFIG_FILE);
    const catalog = readJson<CatalogFile>(CATALOG_FILE);
    const alice = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(aliceFile.privateKeyHex) });
    const appContractAddr = AccountAddress.fromString(cfg.appContractAddr);

    const bob = Account.generate();
    const bobPrivateKeyHex = '0x' + Buffer.from(bob.privateKey.toUint8Array()).toString('hex');
    const bobAddress = bob.accountAddress.toStringLong();
    log(`Generated Bob keypair: ${bobAddress}`);

    const { chainId, aceDeployment, keypairId } = ACE.knownDeployments.preview20260501;
    const aptos = new Aptos(new AptosConfig({ network: Network.CUSTOM, fullnode: aceDeployment.apiEndpoint }));

    log(`Alice transferring ${BOB_ALLOWANCE_OCTAS / 100_000_000} APT to Bob...`);
    const fundTxn = await aptos.transaction.build.simple({
        sender: alice.accountAddress,
        data: {
            function: '0x1::aptos_account::transfer',
            typeArguments: [],
            functionArguments: [bob.accountAddress, BOB_ALLOWANCE_OCTAS.toString()],
        },
    });
    const fundSubmitted = await aptos.signAndSubmitTransaction({ signer: alice, transaction: fundTxn });
    await aptos.waitForTransaction({ transactionHash: fundSubmitted.hash });
    log(`✓ Bob funded (tx: ${fundSubmitted.hash})`);

    writeJson(BOB_FILE, { address: bobAddress, privateKeyHex: bobPrivateKeyHex });

    const target = catalog.items.find(i => i.name === ITEMS[0].name)!;
    const ciphertext = Buffer.from(target.ciphertextHex, 'hex');
    const domain = new TextEncoder().encode(target.name);

    log(`Bob attempting to decrypt "${target.name}" (without buying)...`);
    const session = ACE.AptosBasicFlow.DecryptionSession.create({
        aceDeployment,
        keypairId,
        chainId,
        moduleAddr: appContractAddr,
        moduleName: 'marketplace',
        functionName: 'check_permission',
        domain,
        ciphertext,
    });
    const msgToSign = await session.getRequestToSign();
    const result = await session.decryptWithProof({
        userAddr: bob.accountAddress,
        publicKey: bob.publicKey,
        signature: bob.sign(msgToSign),
    });

    if (result.isOk) {
        console.error('UNEXPECTED: Bob decrypted without paying.');
        process.exit(1);
    }
    log('✓ Decryption denied (expected).');
    log(`  Workers refused to release key shares because`);
    log(`  marketplace::check_permission(bob, "${target.name}") returned false.`);
    log('');
    log('Next: pnpm 5-buy');
}

main().catch(err => { console.error(err); process.exit(1); });
