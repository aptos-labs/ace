// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 5 - A reader pastes the private access token and decrypts.
 */

import { Account, AccountAddress, Ed25519PrivateKey } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

import {
    ACCESS_TOKEN_FILE, AccessTokenFile, CONFIG_FILE, ConfigFile, DEMO_FILE,
    SHELBY_ACE_DEPLOYMENT, SHELBY_CHAIN_ID, SHELBY_KEYPAIR_ID,
    UPLOAD_FILE, UploadFile, log, readJson,
} from './common.js';

async function main() {
    const cfg = readJson<ConfigFile>(CONFIG_FILE);
    const upload = readJson<UploadFile>(UPLOAD_FILE);
    const token = readJson<AccessTokenFile>(ACCESS_TOKEN_FILE);
    const appContractAddr = AccountAddress.fromString(cfg.appContractAddr);
    const tokenAccount = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(token.privateKeyHex) });

    if (tokenAccount.accountAddress.toStringLong() !== upload.tokenAddress) {
        console.error('ERROR: token private key does not derive the registered token address.');
        process.exit(1);
    }

    log(`Reader signing with bearer token address: ${token.address}`);
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
        userAddr: tokenAccount.accountAddress,
        publicKey: tokenAccount.publicKey,
        signature: tokenAccount.sign(msgToSign),
    });

    if (!result.isOk) {
        console.error('ERROR: token holder should have decrypted the file.');
        process.exit(1);
    }

    const plaintext = new TextDecoder().decode(result.okValue!);
    if (plaintext !== DEMO_FILE.plaintext) {
        console.error('ERROR: plaintext mismatch.');
        process.exit(1);
    }

    log('Decryption succeeded.');
    log('Plaintext:');
    console.log(plaintext);
}

main().catch(err => { console.error(err); process.exit(1); });
