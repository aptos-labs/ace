// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 3 — Alice produces the "pre-signed URL" for `song-1.mp3`.
 *
 * Three things happen here:
 *   - Encrypt the plaintext under ACE custom flow with `domain = blob_id`.
 *   - Derive a deterministic BLS keypair `(accessPrivateKey, accessPublicKey)` from
 *     `(vrfKeypairId, contract_id, alice_addr, blob_suffix)` via threshold
 *     VRF. `accessPrivateKey` is the bearer token Alice hands to Bob; Alice can
 *     reproduce it later by re-running this derive if needed.
 *   - Register `accessPublicKey` on-chain. Bob (= whoever) decrypts in step 4 by
 *     signing requests under `accessPrivateKey`.
 *
 * Output: `data/grant.json` — `{ blobSuffix, blobIdHex, ciphertextHex,
 * accessPrivateKeyHex }`. That single file is the pre-signed URL.
 */

import {
    Account, AccountAddress, Ed25519PrivateKey,
} from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { bytesToHex } from '@noble/hashes/utils';

import {
    ALICE_FILE, APP_ORIGIN, AccountFile, CONFIG_FILE, ConfigFile, GRANT_FILE, GrantFile,
    accessPrivateKeyToHex, aceDeploymentFromConfig, aptosFromConfig,
    ensureDataDir, log, readAceConfig, readJson,
    vrfOutputToAccessKeypair, writeJson,
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
    const vrfKeypairId = AccountAddress.fromString(cfg.vrfKeypairId);
    const moduleAddr = AccountAddress.fromString(conf.appContractAddr);
    const moduleName = 'presigned_access';

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

    async function signAsAlice(message: string) {
        const fullMessage = ACE.VRF_Aptos.buildAptosWalletFullMessage({
            accountAddress: alice.accountAddress,
            application: APP_ORIGIN,
            chainId,
            message,
            nonce: `presigned-derive-${BLOB_SUFFIX}`,
        });
        return {
            pubKey: alice.publicKey,
            signature: alice.sign(fullMessage),
            fullMessage,
        };
    }

    log('Deriving (accessPrivateKey, accessPublicKey) via threshold VRF...');
    const vrfBytes = await ACE.VRF_Aptos.derive({
        aceDeployment,
        keypairId: vrfKeypairId,
        chainId, moduleAddr, moduleName,
        label: new TextEncoder().encode(BLOB_SUFFIX),
        accountAddress: alice.accountAddress,
        sign: signAsAlice,
    });
    const { accessPrivateKey, accessPublicKey } = vrfOutputToAccessKeypair(vrfBytes);
    log(`  accessPublicKey = 0x${bytesToHex(accessPublicKey)}`);

    log('Registering accessPublicKey on-chain...');
    const registerTxn = await aptos.transaction.build.simple({
        sender: alice.accountAddress,
        data: {
            function: `${conf.appContractAddr}::presigned_access::register` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [BLOB_SUFFIX, accessPublicKey],
        },
    });
    const submitted = await aptos.signAndSubmitTransaction({ signer: alice, transaction: registerTxn });
    await aptos.waitForTransaction({ transactionHash: submitted.hash });
    log('Registered.');

    writeJson(GRANT_FILE, {
        blobSuffix: BLOB_SUFFIX,
        blobIdHex: bytesToHex(labelBytes),
        ciphertextHex: bytesToHex(ciphertext),
        accessPrivateKeyHex: accessPrivateKeyToHex(accessPrivateKey),
    } satisfies GrantFile);
    log(`Wrote pre-signed grant to ${GRANT_FILE}`);
    log('');
    log('Next: hand `data/grant.json` to whoever should read the blob.');
    log('      That recipient runs: pnpm 4-decrypt');
}

main().catch(err => { console.error(err); process.exit(1); });
