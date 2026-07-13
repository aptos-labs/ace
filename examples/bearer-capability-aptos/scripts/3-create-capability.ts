// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 3 — Alice produces the "bearer capability" for `song-1.mp3`.
 *
 * Three things happen here:
 *   - Encrypt the plaintext under ACE custom flow with `domain = blob_id`.
 *   - Generate a fresh BLS keypair `(accessPrivateKey, accessPublicKey)` directly
 *     from a secure RNG. `accessPrivateKey` is the bearer capability Alice hands
 *     to Bob.
 *   - Register `accessPublicKey` on-chain. Bob (= whoever) decrypts in step 4 by
 *     signing requests under `accessPrivateKey`.
 *
 * Output: `data/capability.json` — `{ blobSuffix, blobIdHex, ciphertextHex,
 * accessPrivateKeyHex }`. That single file is the bearer capability.
 */

import {
    Account, AccountAddress, Ed25519PrivateKey,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { bytesToHex } from '@noble/hashes/utils';

import {
    ALICE_FILE, AccountFile, CONFIG_FILE, ConfigFile, CAPABILITY_FILE, CapabilityFile,
    accessPrivateKeyToHex, aceDeploymentFromConfig, aptosFromConfig,
    ensureDataDir, generateAccessKeypair, log, readAceConfig, readJson, writeJson,
} from './common.js';

const BLOB_SUFFIX = 'song-1.mp3';
const PLAINTEXT = 'Lyrics for song 1: hello sunshine!';

async function main() {
    ensureDataDir();
    const cfg = readAceConfig();
    const conf = readJson<ConfigFile>(CONFIG_FILE);
    const aliceFile = readJson<AccountFile>(ALICE_FILE);
    const alice = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(aliceFile.privateKeyHex) });

    const aceDeployment = aceDeploymentFromConfig(cfg);
    const ibeKeypairId = AccountAddress.fromString(cfg.ibeKeypairId);
    const moduleAddr = AccountAddress.fromString(conf.appContractAddr);
    const moduleName = 'capability_access';

    const aptos = aptosFromConfig(cfg);
    const chainId = await aptos.getChainId();

    // Canonical blob_id, matching what the contract builds with
    // `create_full_blob_name(signer, suffix)`.
    const blobId = `@${alice.accountAddress.toStringLong().slice(2)}/${BLOB_SUFFIX}`;
    const labelBytes = new TextEncoder().encode(blobId);
    log(`Alice = ${alice.accountAddress.toStringLong()}`);
    log(`blob_id = "${blobId}"`);

    log('Encrypting plaintext via ACE custom flow...');
    const ciphertext = (await ACE.IBE_Aptos.encrypt({
        aceDeployment,
        keypairId: ibeKeypairId,
        chainId,
        moduleAddr,
        moduleName,
        label: labelBytes,
        plaintext: new TextEncoder().encode(PLAINTEXT),
    })).unwrapOrThrow('encrypt failed');
    log(`Ciphertext (${ciphertext.length} B) ready`);

    log('Generating (accessPrivateKey, accessPublicKey) directly...');
    const { accessPrivateKey, accessPublicKey } = generateAccessKeypair();
    log(`  accessPublicKey = 0x${bytesToHex(accessPublicKey)}`);

    log('Registering accessPublicKey on-chain...');
    const registerTxn = await aptos.transaction.build.simple({
        sender: alice.accountAddress,
        data: {
            function: `${conf.appContractAddr}::capability_access::register` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [BLOB_SUFFIX, accessPublicKey],
        },
    });
    const submitted = await aptos.signAndSubmitTransaction({ signer: alice, transaction: registerTxn });
    await aptos.waitForTransaction({ transactionHash: submitted.hash });
    log('Registered.');

    writeJson(CAPABILITY_FILE, {
        blobSuffix: BLOB_SUFFIX,
        blobIdHex: bytesToHex(labelBytes),
        ciphertextHex: bytesToHex(ciphertext),
        accessPrivateKeyHex: accessPrivateKeyToHex(accessPrivateKey),
    } satisfies CapabilityFile);
    log(`Wrote bearer capability to ${CAPABILITY_FILE}`);
    log('');
    log('Next: hand `data/capability.json` to whoever should read the blob.');
    log('      That recipient runs: pnpm 4-decrypt');
}

main().catch(err => { console.error(err); process.exit(1); });
