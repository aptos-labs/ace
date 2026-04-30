// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Script 3 — Issue KYC Credential
 *
 * The KYC provider signs an age value with their Baby JubJub private key.
 * The signature is the "credential" — a commitment that the holder's age has
 * been verified, without revealing the exact age.
 *
 * Usage:
 *   pnpm 3-issue-credential            # defaults to age 25
 *   pnpm 3-issue-credential -- 30      # age 30
 *
 * Ages below 18 are accepted here — the ZK proof will simply fail to generate
 * at step 5 since the circuit enforces the age >= 18 constraint.
 *
 * Output: data/credential.json
 */

import { buildEddsa, buildPoseidon } from 'circomlibjs';
import * as path from 'path';
import { DATA_DIR, ensureDataDir, readJson, writeJson } from './common.js';

interface ProviderKey {
    private: string;
    public_ax: string;
    public_ay: string;
}

async function main() {
    ensureDataDir();

    const age = parseInt(process.argv[2] ?? '25', 10);
    if (isNaN(age) || age < 0 || age > 255) {
        console.error('age must be an integer 0–255');
        process.exit(1);
    }

    const status = age >= 18 ? 'eligible (18+)' : 'underage (<18)';
    console.log(`Issuing credential for age ${age} — ${status}`);

    const providerKeyPath = path.join(DATA_DIR, 'provider-key.json');
    const providerKey = readJson<ProviderKey>(providerKeyPath);

    const poseidon = await buildPoseidon();
    const eddsa = await buildEddsa();
    const F = eddsa.F;

    const privKey = Buffer.from(providerKey.private, 'hex');

    // Message is Poseidon(age) — must match the circuit's msg_hash component.
    const msgHash = poseidon([BigInt(age)]);

    const sig = eddsa.signPoseidon(privKey, msgHash);

    const credential = {
        age,
        sig_r8x: F.toObject(sig.R8[0]).toString(),
        sig_r8y: F.toObject(sig.R8[1]).toString(),
        sig_s: sig.S.toString(),
    };

    const outPath = path.join(DATA_DIR, 'credential.json');
    writeJson(outPath, credential);

    console.log(`Credential issued and saved to ${outPath}`);
    console.log(`  Age: ${age} (${status})`);
    console.log('');
    console.log('Next: run script 4 to encrypt a secret under this KYC policy.');
}

main().catch(err => { console.error(err); process.exit(1); });
