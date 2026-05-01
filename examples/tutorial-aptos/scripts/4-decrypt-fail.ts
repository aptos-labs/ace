// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 4 — A new user, Bob, tries to decrypt and is correctly rejected.
 *
 * Bob has zero APT and no on-chain identity. He only signs a proof-of-permission
 * (an off-chain Ed25519 signature), then sends a request to ACE workers. Each
 * worker simulates `simple_acl::check_permission(bob, domain)`, which returns
 * false because Bob isn't in the allowlist, so no key share is released.
 */

import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

import {
    BLOB_FILE, BLOB_NAME, BOB_FILE, BlobFile, CONFIG_FILE, ConfigFile,
    ensureDataDir, log, readJson, writeJson,
} from './common.js';

async function main() {
    ensureDataDir();

    const cfg = readJson<ConfigFile>(CONFIG_FILE);
    const blob = readJson<BlobFile>(BLOB_FILE);
    const appContractAddr = AccountAddress.fromString(cfg.appContractAddr);

    const bob = Account.generate();
    const bobPrivateKeyHex = '0x' + Buffer.from(bob.privateKey.toUint8Array()).toString('hex');
    const bobAddress = bob.accountAddress.toStringLong();
    log(`Generated Bob keypair: ${bobAddress}  (no funding required — Bob never sends a tx)`);

    writeJson(BOB_FILE, { address: bobAddress, privateKeyHex: bobPrivateKeyHex });

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

    if (result.isOk) {
        console.error('UNEXPECTED: Bob succeeded — was the allowlist already non-empty?');
        process.exit(1);
    }
    log('✓ Decryption denied (expected).');
    log('  Workers refused to release enough key shares because');
    log('  simple_acl::check_permission(bob, "tutorial-blob") returned false.');
    log('');
    log('Next: pnpm 5-grant-access');
}

main().catch(err => { console.error(err); process.exit(1); });
