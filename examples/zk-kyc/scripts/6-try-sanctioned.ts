// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Script 6 — Try a Blocked Jurisdiction
 *
 * Demonstrates that the ZK circuit itself enforces the blocklist check.
 * Even if an adversary convinces a corrupt KYC provider to sign a credential
 * for a blocked jurisdiction (codes 0–3), the Groth16 prover will FAIL to
 * generate a valid proof — because the constraint `not_blocked === 1` is
 * violated and the witness is inconsistent.
 *
 * This is the key privacy/security property:
 *   - A blocked jurisdiction cannot produce a valid proof (enforced cryptographically).
 *   - A valid proof does NOT reveal the actual jurisdiction (zero knowledge).
 *
 * Usage:
 *   pnpm 6-try-sanctioned              # tries blocked jurisdiction 0 by default
 *   pnpm 6-try-sanctioned -- 1         # tries blocked jurisdiction 1
 */

import { buildEddsa, buildPoseidon } from 'circomlibjs';
import { groth16 } from 'snarkjs';
import * as path from 'path';
import {
    CIRCUIT_DIR, DATA_DIR, ensureDataDir,
    readJson, packEncPk,
} from './common.js';

interface ProviderKey {
    private: string;
    public_ax: string;
    public_ay: string;
}

interface Session {
    ciphertext: string;
    encPk: string;
    encSk: string;
    label: string;
}

const BLOCKED: Record<number, string> = {
    0: 'Jurisdiction A',
    1: 'Jurisdiction B',
    2: 'Jurisdiction C',
    3: 'Jurisdiction D',
};

async function main() {
    ensureDataDir();

    const jurisdiction = parseInt(process.argv[2] ?? '0', 10);
    const name = BLOCKED[jurisdiction];
    if (!name) {
        console.error(`Jurisdiction ${jurisdiction} is not on the blocked list.`);
        console.error('Use 0, 1, 2, or 3 (the four blocked codes).');
        process.exit(1);
    }

    console.log(`Attempting to obtain a credential for blocked jurisdiction ${jurisdiction} (${name})...`);

    const providerKey = readJson<ProviderKey>(path.join(DATA_DIR, 'provider-key.json'));
    const session     = readJson<Session>(path.join(DATA_DIR, 'session.json'));
    const encPk       = Uint8Array.from(Buffer.from(session.encPk, 'hex'));

    const poseidon = await buildPoseidon();
    const eddsa    = await buildEddsa();
    const F        = eddsa.F;

    // Issue credential for the blocked jurisdiction (imagine a corrupt provider)
    const privKey  = Buffer.from(providerKey.private, 'hex');
    const msgHash  = poseidon([BigInt(jurisdiction)]);
    const sig      = eddsa.signPoseidon(privKey, msgHash);

    const [p0, p1, p2] = packEncPk(encPk);

    const circuitInput = {
        pk_provider_ax: providerKey.public_ax,
        pk_provider_ay: providerKey.public_ay,
        enc_pk_p0: p0.toString(),
        enc_pk_p1: p1.toString(),
        enc_pk_p2: p2.toString(),
        jurisdiction: jurisdiction.toString(),
        sig_r8x: F.toObject(sig.R8[0]).toString(),
        sig_r8y: F.toObject(sig.R8[1]).toString(),
        sig_s:   sig.S.toString(),
        enc_pk:  Array.from(encPk).map(String),
    };

    const wasmPath = path.join(CIRCUIT_DIR, 'kyc_js', 'kyc.wasm');
    const zkeyPath = path.join(CIRCUIT_DIR, 'kyc_final.zkey');

    console.log('');
    console.log('Attempting to generate proof for blocked jurisdiction...');
    try {
        await groth16.fullProve(circuitInput, wasmPath, zkeyPath);
        console.error('');
        console.error('ERROR: Proof generation SHOULD have failed for a blocked jurisdiction!');
        process.exit(1);
    } catch (_err) {
        console.log('');
        console.log('=== Proof generation FAILED as expected! ===');
        console.log('');
        console.log(`The circuit constraint "not_blocked === 1" is violated for ${name}.`);
        console.log('The witness is inconsistent — no valid proof can be produced.');
        console.log('');
        console.log('Key insight:');
        console.log('  Even if a corrupt KYC provider issues a credential for a blocked');
        console.log('  jurisdiction, the prover cannot construct a valid ZK proof. The');
        console.log('  blocklist check is enforced by the circuit\'s arithmetic constraints,');
        console.log('  not by trusting any party at proof time.');
    }
}

main().catch(err => { console.error(err); process.exit(1); });
