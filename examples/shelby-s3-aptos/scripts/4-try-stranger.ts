// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 4 - A random stranger tries to decrypt and is denied.
 */

import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

import {
    CONFIG_FILE, ConfigFile, SHELBY_ACE_DEPLOYMENT, SHELBY_CHAIN_ID, SHELBY_KEYPAIR_ID,
    UPLOAD_FILE, UploadFile, log, readJson,
} from './common.js';

async function main() {
    const cfg = readJson<ConfigFile>(CONFIG_FILE);
    const upload = readJson<UploadFile>(UPLOAD_FILE);
    const appContractAddr = AccountAddress.fromString(cfg.appContractAddr);

    const stranger = Account.generate();
    log(`Generated stranger address: ${stranger.accountAddress.toStringLong()}`);
    log('This account is not funded and not in the file allowlist.');

    const session = await ACE.AptosBasicFlow.DecryptionSession.create({
        aceDeployment: SHELBY_ACE_DEPLOYMENT,
        keypairId: SHELBY_KEYPAIR_ID,
        chainId: SHELBY_CHAIN_ID,
        moduleAddr: appContractAddr,
        moduleName: 'shelby_s3',
        functionName: 'check_permission',
        domain: new TextEncoder().encode(upload.fileId),
        ciphertext: Buffer.from(upload.ciphertextHex, 'hex'),
    });
    const msgToSign = await session.getRequestToSign();
    const result = await session.decryptWithProof({
        userAddr: stranger.accountAddress,
        publicKey: stranger.publicKey,
        signature: stranger.sign(msgToSign),
    });

    if (result.isOk) {
        console.error('UNEXPECTED: stranger decrypted without the token.');
        process.exit(1);
    }

    log('Decryption denied (expected).');
    log('shelby_s3::check_permission(stranger, file_id) returned false.');
    log('');
    log('Next: pnpm 5-decrypt-with-token');
}

main().catch(err => { console.error(err); process.exit(1); });
