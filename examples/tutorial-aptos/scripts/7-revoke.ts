// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 7 — Alice revokes Bob's access; Bob's next decrypt attempt fails again.
 *
 * Demonstrates that ACE re-evaluates the on-chain ACL on every decryption
 * attempt — past success doesn't grant future access.
 */

import {
    Account, AccountAddress, Aptos, AptosConfig, Ed25519PrivateKey, Network,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

import {
    ALICE_FILE, AccountFile, BLOB_FILE, BLOB_NAME, BOB_FILE, BlobFile, CONFIG_FILE, ConfigFile,
    log, readJson,
} from './common.js';

async function main() {
    const aliceFile = readJson<AccountFile>(ALICE_FILE);
    const bobFile = readJson<AccountFile>(BOB_FILE);
    const cfg = readJson<ConfigFile>(CONFIG_FILE);
    const blob = readJson<BlobFile>(BLOB_FILE);
    const alice = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(aliceFile.privateKeyHex) });
    const bob = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(bobFile.privateKeyHex) });
    const appContractAddr = AccountAddress.fromString(cfg.appContractAddr);

    const { chainId, aceDeployment, keypairId } = ACE.knownDeployments.preview20260501;
    const aptos = new Aptos(new AptosConfig({ network: Network.CUSTOM, fullnode: aceDeployment.apiEndpoint }));

    const domainBytes = new TextEncoder().encode(BLOB_NAME);

    log(`Alice revoking Bob's access...`);
    const txn = await aptos.transaction.build.simple({
        sender: alice.accountAddress,
        data: {
            function: `${cfg.appContractAddr}::simple_acl::revoke_access` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [Array.from(domainBytes), bob.accountAddress],
        },
    });
    const submitted = await aptos.signAndSubmitTransaction({ signer: alice, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: submitted.hash });
    log(`✓ Bob removed from allowlist (tx: ${submitted.hash})`);

    log('Bob attempting to decrypt again (should fail)...');
    const ciphertext = Buffer.from(blob.ciphertextHex, 'hex');
    const session = ACE.AptosBasicFlow.DecryptionSession.create({
        aceDeployment,
        keypairId,
        chainId,
        moduleAddr: appContractAddr,
        moduleName: 'simple_acl',
        functionName: 'check_permission',
        domain: domainBytes,
        ciphertext,
    });
    const msgToSign = await session.getRequestToSign();
    const result = await session.decryptWithProof({
        userAddr: bob.accountAddress,
        publicKey: bob.publicKey,
        signature: bob.sign(msgToSign),
    });

    if (result.isOk) {
        console.error('UNEXPECTED: Bob still decrypted after revocation.');
        process.exit(1);
    }
    log('✓ Decryption denied (expected). Revocation works.');
}

main().catch(err => { console.error(err); process.exit(1); });
