// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 6 — Bob retries decryption and succeeds.
 *
 * Same code as step 4, but now `check_permission(bob, domain)` returns true,
 * so workers release key shares and Bob's threshold-IBE decrypt succeeds.
 */

import {
    Account, AccountAddress, Ed25519PrivateKey,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

import {
    BLOB_FILE, BLOB_NAME, BOB_FILE, BlobFile, CONFIG_FILE, ConfigFile, PLAINTEXT,
    AccountFile, log, readJson,
} from './common.js';

async function main() {
    const cfg = readJson<ConfigFile>(CONFIG_FILE);
    const blob = readJson<BlobFile>(BLOB_FILE);
    const bobFile = readJson<AccountFile>(BOB_FILE);
    const bob = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(bobFile.privateKeyHex) });
    const appContractAddr = AccountAddress.fromString(cfg.appContractAddr);

    const { chainId, aceDeployment, keypairId } = ACE.knownDeployments.preview20260501;
    const ciphertext = Buffer.from(blob.ciphertextHex, 'hex');
    const domain = new TextEncoder().encode(BLOB_NAME);

    log('Bob attempting to decrypt...');
    const session = ACE.AptosBasicFlow.DecryptionSession.create({
        aceDeployment,
        keypairId,
        chainId,
        moduleAddr: appContractAddr,
        moduleName: 'simple_acl',
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

    if (!result.isOk) {
        console.error('ERROR: Bob should have been able to decrypt.');
        console.error(result);
        process.exit(1);
    }
    const decrypted = new TextDecoder().decode(result.okValue!);
    log(`✓ Decryption succeeded.`);
    log(`  Plaintext: "${decrypted}"`);
    if (decrypted !== PLAINTEXT) {
        console.error(`ERROR: plaintext mismatch (expected "${PLAINTEXT}")`);
        process.exit(1);
    }
    log('');
    log('Next: pnpm 7-revoke');
}

main().catch(err => { console.error(err); process.exit(1); });
