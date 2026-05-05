// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Script 6 — Try an Underage Credential
 *
 * Demonstrates that the ZK circuit itself enforces the age check.
 * Even if an adversary convinces a KYC provider to sign a credential for
 * age 16, the Groth16 prover will FAIL to generate a valid proof — because
 * the constraint `ageCheck.out === 1` (age >= 18) is violated and the
 * witness is inconsistent.
 *
 * This is the key property:
 *   - An underage credential cannot produce a valid proof (enforced cryptographically).
 *   - A valid proof does NOT reveal the actual age (zero knowledge).
 *
 * Usage:
 *   pnpm 6-try-underage              # tries age 16 by default
 *   pnpm 6-try-underage -- 17        # tries age 17
 */

import { buildEddsa, buildPoseidon } from 'circomlibjs';
import * as ACE from '@aptos-labs/ace-sdk';
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

async function main() {
    ensureDataDir();

    const rawArg = process.argv.slice(2).find(a => a !== '--');
    const age = parseInt(rawArg ?? '16', 10);
    if (isNaN(age) || age < 0 || age > 255) {
        console.error('age must be an integer 0–255');
        process.exit(1);
    }
    if (age >= 18) {
        console.error(`Age ${age} is already eligible (>= 18). Use an age below 18.`);
        process.exit(1);
    }

    console.log(`Attempting to obtain a credential for age ${age} (underage)...`);

    const providerKey = readJson<ProviderKey>(path.join(DATA_DIR, 'provider-key.json'));
    const callerKeypair = await ACE.pke.keygen();
    const encPk = new Uint8Array(callerKeypair.encryptionKey.toBytes());

    const poseidon = await buildPoseidon();
    const eddsa    = await buildEddsa();
    const F        = eddsa.F;

    // Generate a user_secret and have the (corrupt) provider sign Poseidon(user_secret, age)
    const userSecretBytes = new Uint8Array(31);
    crypto.getRandomValues(userSecretBytes);
    const userSecret = BigInt('0x' + Buffer.from(userSecretBytes).toString('hex'));

    const privKey  = Buffer.from(providerKey.private, 'hex');
    const msgHash  = poseidon([userSecret, BigInt(age)]);
    const sig      = eddsa.signPoseidon(privKey, msgHash);

    const [p0, p1, p2] = packEncPk(encPk);

    const circuitInput = {
        pk_provider_ax: providerKey.public_ax,
        pk_provider_ay: providerKey.public_ay,
        enc_pk_p0: p0.toString(),
        enc_pk_p1: p1.toString(),
        enc_pk_p2: p2.toString(),
        user_secret: userSecret.toString(),
        age: age.toString(),
        sig_r8x: F.toObject(sig.R8[0]).toString(),
        sig_r8y: F.toObject(sig.R8[1]).toString(),
        sig_s:   sig.S.toString(),
    };

    const wasmPath = path.join(CIRCUIT_DIR, 'kyc_js', 'kyc.wasm');
    const zkeyPath = path.join(CIRCUIT_DIR, 'kyc_final.zkey');

    console.log('');
    console.log('Attempting to generate proof for underage credential...');
    try {
        await groth16.fullProve(circuitInput, wasmPath, zkeyPath);
        console.error('');
        console.error('ERROR: Proof generation SHOULD have failed for an underage credential!');
        process.exit(1);
    } catch (_err) {
        console.log('');
        console.log('=== Proof generation FAILED as expected! ===');
        console.log('');
        console.log(`The circuit constraint "age >= 18" is violated for age ${age}.`);
        console.log('The witness is inconsistent — no valid proof can be produced.');
        console.log('');
        console.log('Key insight:');
        console.log('  Even if a corrupt KYC provider issues a credential for an underage');
        console.log('  holder, the prover cannot construct a valid ZK proof. The age check');
        console.log('  is enforced by the circuit\'s arithmetic constraints, not by trusting');
        console.log('  any party at proof time.');
    }
}

main().catch(err => { console.error(err); process.exit(1); });
