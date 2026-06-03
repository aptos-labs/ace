// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Script 5 - Try a Non-Member
 *
 * Demonstrates the negative path. A random secret that is not in the Merkle
 * tree cannot satisfy the circuit's `computed_root === public_root` constraint.
 */

import * as ACE from '@aptos-labs/ace-sdk';
import { groth16 } from 'snarkjs';
import * as path from 'path';
import {
    CIRCUIT_DIR, DATA_DIR,
    buildCircuitInput, ensureDataDir, hexToBytes, randomFr, readJson,
    type GroupData, type MemberCredential,
} from './common.js';

interface Session {
    label: string;
}

async function main() {
    ensureDataDir();

    const group = readJson<GroupData>(path.join(DATA_DIR, 'group.json'));
    const realCredential = readJson<MemberCredential>(path.join(DATA_DIR, 'member-credential.json'));
    const session = readJson<Session>(path.join(DATA_DIR, 'session.json'));
    const callerKeypair = await ACE.pke.keygen();
    const encPk = new Uint8Array(callerKeypair.encryptionKey.toBytes());

    const fakeCredential: MemberCredential = {
        ...realCredential,
        name: 'mallory',
        secret: randomFr().toString(),
        commitment: '(not in tree)',
    };

    const circuitInput = buildCircuitInput({
        group,
        credential: fakeCredential,
        label: hexToBytes(session.label),
        encPk,
    });

    const wasmPath = path.join(CIRCUIT_DIR, 'member_vault_js', 'member_vault.wasm');
    const zkeyPath = path.join(CIRCUIT_DIR, 'member_vault_final.zkey');

    console.log('Attempting to prove membership with a random non-member secret...');
    try {
        await groth16.fullProve(circuitInput, wasmPath, zkeyPath);
        console.error('');
        console.error('ERROR: proof generation unexpectedly succeeded for a non-member.');
        process.exit(1);
    } catch (_err) {
        console.log('');
        console.log('=== Proof generation failed as expected ===');
        console.log('The fake leaf does not reconstruct the public Merkle root, so no');
        console.log('valid custom-flow payload can be produced for this non-member.');
        process.exit(0);
    }
}

main().catch(err => { console.error(err); process.exit(1); });
