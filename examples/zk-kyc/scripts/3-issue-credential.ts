// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Script 3 — Issue KYC Credential
 *
 * The KYC provider signs a jurisdiction code with their Baby JubJub private key.
 * The signature is the "credential" — a commitment that the holder's jurisdiction
 * has been verified, without revealing which jurisdiction it is.
 *
 * Usage:
 *   pnpm 3-issue-credential            # defaults to jurisdiction 10 (United States)
 *   pnpm 3-issue-credential -- 20      # jurisdiction 20 (European Union)
 *
 * Blocked codes (0–3) are accepted here — the ZK proof will simply fail to
 * generate at step 5 since the circuit enforces the non-blocked constraint.
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

const JURISDICTION_NAMES: Record<number, string> = {
    0: 'Jurisdiction A (blocked)',
    1: 'Jurisdiction B (blocked)',
    2: 'Jurisdiction C (blocked)',
    3: 'Jurisdiction D (blocked)',
    10: 'Jurisdiction 10 (permitted)',
    20: 'Jurisdiction 20 (permitted)',
    30: 'Jurisdiction 30 (permitted)',
    40: 'Jurisdiction 40 (permitted)',
    50: 'Jurisdiction 50 (permitted)',
    99: 'Jurisdiction 99 (permitted)',
};

async function main() {
    ensureDataDir();

    const jurisdiction = parseInt(process.argv[2] ?? '10', 10);
    if (isNaN(jurisdiction) || jurisdiction < 0 || jurisdiction > 255) {
        console.error('jurisdiction must be an integer 0–255');
        process.exit(1);
    }

    const jurisdictionName = JURISDICTION_NAMES[jurisdiction] ?? `Country code ${jurisdiction}`;
    console.log(`Issuing credential for jurisdiction ${jurisdiction} (${jurisdictionName})`);

    const providerKeyPath = path.join(DATA_DIR, 'provider-key.json');
    const providerKey = readJson<ProviderKey>(providerKeyPath);

    const poseidon = await buildPoseidon();
    const eddsa = await buildEddsa();
    const F = eddsa.F;

    const privKey = Buffer.from(providerKey.private, 'hex');

    // Message is Poseidon(jurisdiction) — must match the circuit's msg_hash component.
    const msgHash = poseidon([BigInt(jurisdiction)]);

    const sig = eddsa.signPoseidon(privKey, msgHash);

    const credential = {
        jurisdiction,
        sig_r8x: F.toObject(sig.R8[0]).toString(),
        sig_r8y: F.toObject(sig.R8[1]).toString(),
        sig_s: sig.S.toString(),
    };

    const outPath = path.join(DATA_DIR, 'credential.json');
    writeJson(outPath, credential);

    console.log(`Credential issued and saved to ${outPath}`);
    console.log(`  Jurisdiction: ${jurisdiction} (${jurisdictionName})`);
    console.log('');
    console.log('Next: run script 4 to encrypt a secret under this KYC policy.');
}

main().catch(err => { console.error(err); process.exit(1); });
