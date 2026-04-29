// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Script 4 — Encrypt a Secret
 *
 * Encrypts a plaintext under the KYC ACL policy using ACE.
 * Anyone can encrypt; only a holder with a valid KYC credential can decrypt.
 *
 * The encryption uses the `kyc_verifier::check_acl` function as the ACE contract
 * identity, so the ACE network will only release the decryption key share to a
 * caller who presents a valid ZK proof.
 *
 * Output: data/session.json  (ciphertext + ephemeral PKE keypair)
 */

import { AccountAddress } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import * as path from 'path';
import { DATA_DIR, ensureDataDir, readJson, writeJson } from './common.js';

interface Config {
    adminAddress: string;
    aceApiEndpoint: string;
    aceContractAddr: string;
    keypairId: string;
    chainId: number;
    moduleName: string;
    functionName: string;
}

const LABEL = new TextEncoder().encode('kyc-demo');
// The plaintext represents a secret only KYC-verified users should read,
// e.g. a compliance report, a trading parameter, or gated content.
const PLAINTEXT = new TextEncoder().encode('KYC-GATED SECRET: you have been verified!');

async function main() {
    ensureDataDir();

    const configPath = path.join(DATA_DIR, 'config.json');
    const cfg = readJson<Config>(configPath);

    const aceDeployment = new ACE.AceDeployment({
        apiEndpoint: cfg.aceApiEndpoint,
        contractAddr: AccountAddress.fromString(cfg.aceContractAddr),
    });
    const keypairId = AccountAddress.fromString(cfg.keypairId);
    const moduleAddr = AccountAddress.fromString(cfg.adminAddress);

    console.log('Encrypting plaintext...');
    console.log(`  Label (IBE domain): "${new TextDecoder().decode(LABEL)}"`);

    const result = await ACE.AptosCustomFlow.encrypt({
        aceDeployment,
        keypairId,
        chainId: cfg.chainId,
        moduleAddr,
        moduleName: cfg.moduleName,
        functionName: cfg.functionName,
        domain: LABEL,
        plaintext: PLAINTEXT,
    });
    const ciphertext = result.unwrapOrThrow('AptosCustomFlow.encrypt failed');
    console.log('Plaintext encrypted.');

    // Generate ephemeral PKE keypair for the decryption request.
    const callerKeypair = ACE.pke.keygen();
    const encPk = callerKeypair.encryptionKey.toBytes();
    const encSk = callerKeypair.decryptionKey.toBytes();

    const session = {
        ciphertext: Buffer.from(ciphertext).toString('hex'),
        encPk: Buffer.from(encPk).toString('hex'),
        encSk: Buffer.from(encSk).toString('hex'),
        label: Buffer.from(LABEL).toString('hex'),
    };

    const outPath = path.join(DATA_DIR, 'session.json');
    writeJson(outPath, session);

    console.log(`Session saved to ${outPath}`);
    console.log('');
    console.log('Next: run script 5 to generate a ZK proof and decrypt.');
}

main().catch(err => { console.error(err); process.exit(1); });
