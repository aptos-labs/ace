// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 3 — Alice encrypts a secret and registers the blob with an empty allowlist.
 *
 * Encryption is bound to (keypairId, contractId(...::simple_acl::check_permission),
 * domain=blobName). ACE workers will only release a key share to a caller whose
 * decryption attempt makes `check_permission` return true.
 */

import {
    Account, AccountAddress, Aptos, AptosConfig, Ed25519PrivateKey, Network,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

import {
    ALICE_FILE, AccountFile, BLOB_FILE, BLOB_NAME, CONFIG_FILE, ConfigFile, PLAINTEXT,
    ensureDataDir, log, readJson, writeJson,
} from './common.js';

async function main() {
    ensureDataDir();

    const aliceFile = readJson<AccountFile>(ALICE_FILE);
    const cfg = readJson<ConfigFile>(CONFIG_FILE);
    const alice = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(aliceFile.privateKeyHex) });
    const appContractAddr = AccountAddress.fromString(cfg.appContractAddr);

    const { chainId, aceDeployment, keypairId } = ACE.knownDeployments.preview20260501;
    const aptos = new Aptos(new AptosConfig({ network: Network.CUSTOM, fullnode: aceDeployment.apiEndpoint }));
    const textEncoder = new TextEncoder();
    const domain = textEncoder.encode(BLOB_NAME);

    log(`Encrypting plaintext under blob "${BLOB_NAME}"...`);
    const ciphertext = (await ACE.AptosBasicFlow.encrypt({
        aceDeployment,
        keypairId,
        chainId,
        moduleAddr: appContractAddr,
        moduleName: 'simple_acl',
        functionName: 'check_permission',
        domain,
        plaintext: textEncoder.encode(PLAINTEXT),
    })).unwrapOrThrow('encrypt failed');
    log(`Encrypted (${ciphertext.length} bytes).`);

    log('Calling simple_acl::register_blob...');
    const txn = await aptos.transaction.build.simple({
        sender: alice.accountAddress,
        data: {
            function: `${cfg.appContractAddr}::simple_acl::register_blob` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [Array.from(domain)],
        },
    });
    const submitted = await aptos.signAndSubmitTransaction({ signer: alice, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: submitted.hash });
    log('Blob registered (allowlist is empty — only Alice can decrypt).');

    writeJson(BLOB_FILE, {
        name: BLOB_NAME,
        ciphertextHex: Buffer.from(ciphertext).toString('hex'),
    });
    log(`Saved blob to ${BLOB_FILE}`);
    log('');
    log('Next: pnpm 4-decrypt-fail');
}

main().catch(err => { console.error(err); process.exit(1); });
