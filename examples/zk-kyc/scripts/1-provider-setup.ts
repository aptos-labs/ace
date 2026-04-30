// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Script 1 — KYC Provider Setup
 *
 * Generates a Baby JubJub keypair for the KYC provider.
 * The private key is used to issue credentials (sign age values).
 * The public key is stored on-chain inside the Groth16 verification key.
 *
 * In a real system this key would live in a HSM at the KYC provider.
 * For the demo we store it locally in data/provider-key.json.
 *
 * Output: data/provider-key.json
 */

import { buildEddsa } from 'circomlibjs';
import * as path from 'path';
import { DATA_DIR, ensureDataDir, writeJson } from './common.js';

async function main() {
    ensureDataDir();

    const eddsa = await buildEddsa();

    const privKeyBytes = new Uint8Array(32);
    crypto.getRandomValues(privKeyBytes);

    const pubKey = eddsa.prv2pub(Buffer.from(privKeyBytes));
    const F = eddsa.F;

    const keyData = {
        private: Buffer.from(privKeyBytes).toString('hex'),
        public_ax: F.toObject(pubKey[0]).toString(),
        public_ay: F.toObject(pubKey[1]).toString(),
    };

    const outPath = path.join(DATA_DIR, 'provider-key.json');
    writeJson(outPath, keyData);

    console.log('KYC provider keypair generated (Baby JubJub over BN254 Fr).');
    console.log(`  Public key Ax = ${keyData.public_ax}`);
    console.log(`  Public key Ay = ${keyData.public_ay}`);
    console.log(`  Saved to: ${outPath}`);
    console.log('');
    console.log('Next: run script 2 to deploy the on-chain verifier.');
}

main().catch(err => { console.error(err); process.exit(1); });
