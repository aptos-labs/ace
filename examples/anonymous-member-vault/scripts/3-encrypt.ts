// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Script 3 - Encrypt Member-Only Content
 *
 * Anyone can encrypt. Only a holder of an anonymous membership proof for the
 * configured Merkle root can obtain ACE decryption shares.
 */

import { AccountAddress } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import * as path from 'path';
import { DATA_DIR, bytesToHex, ensureDataDir, readJson, writeJson } from './common.js';

interface Config {
    adminAddress: string;
    aceApiEndpoint: string;
    aceContractAddr: string;
    keypairId: string;
    chainId: number;
    moduleName: string;
    functionName: string;
}

const LABEL = new TextEncoder().encode('strategy-memo-2026');
const PLAINTEXT = new TextEncoder().encode(
    'MEMBER-ONLY SECRET: roadmap draft for anonymous members.',
);

async function main() {
    ensureDataDir();

    const cfg = readJson<Config>(path.join(DATA_DIR, 'config.json'));
    const aceDeployment = new ACE.AceDeployment({
        apiEndpoint: cfg.aceApiEndpoint,
        contractAddr: AccountAddress.fromString(cfg.aceContractAddr),
    });

    console.log('Encrypting member-only plaintext...');
    console.log(`  Label: "${new TextDecoder().decode(LABEL)}"`);

    const result = await ACE.AptosCustomFlow.encrypt({
        aceDeployment,
        keypairId: AccountAddress.fromString(cfg.keypairId),
        chainId: cfg.chainId,
        moduleAddr: AccountAddress.fromString(cfg.adminAddress),
        moduleName: cfg.moduleName,
        functionName: cfg.functionName,
        domain: LABEL,
        plaintext: PLAINTEXT,
    });
    const ciphertext = result.unwrapOrThrow('AptosCustomFlow.encrypt failed');

    const sessionPath = path.join(DATA_DIR, 'session.json');
    writeJson(sessionPath, {
        ciphertext: bytesToHex(ciphertext),
        label: bytesToHex(LABEL),
    });

    console.log('Plaintext encrypted.');
    console.log(`Session saved to ${sessionPath}`);
    console.log('');
    console.log('Next: run script 4 to decrypt with an anonymous membership proof.');
}

main().catch(err => { console.error(err); process.exit(1); });
