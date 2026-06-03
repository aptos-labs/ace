// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 3 - Encrypt a file, mint a bearer access token, and register both.
 *
 * "Uploading to Shelby S3" is represented by writing the ciphertext to
 * data/upload.json. The important ACE part is that the same file id is used as
 * the encryption domain and as the Move registry key.
 */

import {
    Account, AccountAddress, Aptos, AptosConfig, Ed25519PrivateKey, Network,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

import {
    ACCESS_TOKEN_FILE, AccessTokenFile, AccountFile, CONFIG_FILE, ConfigFile, DEMO_FILE,
    OWNER_FILE, SHELBY_ACE_DEPLOYMENT, SHELBY_CHAIN_ID, SHELBY_KEYPAIR_ID, UPLOAD_FILE,
    ensureDataDir, log, privateKeyHex, readJson, writeJson,
} from './common.js';

async function main() {
    ensureDataDir();

    const ownerFile = readJson<AccountFile>(OWNER_FILE);
    const cfg = readJson<ConfigFile>(CONFIG_FILE);
    const owner = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(ownerFile.privateKeyHex) });
    const appContractAddr = AccountAddress.fromString(cfg.appContractAddr);

    const tokenAccount = Account.generate();
    const tokenAddress = tokenAccount.accountAddress.toStringLong();
    const tokenPrivateKeyHex = privateKeyHex(tokenAccount);

    const domain = new TextEncoder().encode(DEMO_FILE.fileId);
    log(`Encrypting "${DEMO_FILE.fileId}" before Shelby upload...`);
    const ciphertext = (await ACE.AptosBasicFlow.encrypt({
        aceDeployment: SHELBY_ACE_DEPLOYMENT,
        keypairId: SHELBY_KEYPAIR_ID,
        chainId: SHELBY_CHAIN_ID,
        moduleAddr: appContractAddr,
        moduleName: 'shelby_s3',
        functionName: 'check_permission',
        domain,
        plaintext: new TextEncoder().encode(DEMO_FILE.plaintext),
    })).unwrapOrThrow('encrypt failed');
    log(`Encrypted file (${ciphertext.length} bytes).`);

    const aptos = new Aptos(new AptosConfig({
        network: Network.CUSTOM,
        fullnode: SHELBY_ACE_DEPLOYMENT.apiEndpoint,
    }));

    log(`Registering file with token address in allowlist: ${tokenAddress}`);
    const txn = await aptos.transaction.build.simple({
        sender: owner.accountAddress,
        data: {
            function: `${cfg.appContractAddr}::shelby_s3::register_file` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [Array.from(domain), tokenAccount.accountAddress],
        },
    });
    const submitted = await aptos.signAndSubmitTransaction({ signer: owner, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: submitted.hash });
    log(`File registered (tx: ${submitted.hash}).`);

    writeJson(UPLOAD_FILE, {
        fileId: DEMO_FILE.fileId,
        ownerAddress: owner.accountAddress.toStringLong(),
        tokenAddress,
        ciphertextHex: Buffer.from(ciphertext).toString('hex'),
    });

    const token: AccessTokenFile = {
        kind: 'ed25519-private-key',
        scope: DEMO_FILE.fileId,
        address: tokenAddress,
        privateKeyHex: tokenPrivateKeyHex,
    };
    writeJson(ACCESS_TOKEN_FILE, token);

    log(`Saved Shelby upload metadata to ${UPLOAD_FILE}`);
    log(`Saved bearer token to ${ACCESS_TOKEN_FILE}`);
    log('');
    log('Private share token:');
    log(`  ${tokenPrivateKeyHex}`);
    log('');
    log('Next: pnpm 4-try-stranger');
}

main().catch(err => { console.error(err); process.exit(1); });
