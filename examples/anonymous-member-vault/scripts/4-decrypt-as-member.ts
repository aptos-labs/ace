// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Script 4 - Decrypt as an Anonymous Member
 *
 * The user proves membership locally, sends only the proof payload to ACE, and
 * recovers the plaintext. The worker and Move verifier learn that some member
 * passed the policy, not which member generated the proof.
 */

import { AccountAddress } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { groth16 } from 'snarkjs';
import * as path from 'path';
import {
    CIRCUIT_DIR, DATA_DIR,
    buildCircuitInput, ensureDataDir, hexToBytes, proofToBytes, readJson,
    uint256ToLeBytes,
    type GroupData, type MemberCredential,
} from './common.js';

interface Config {
    adminAddress: string;
    aceApiEndpoint: string;
    aceContractAddr: string;
    keypairId: string;
    chainId: number;
    moduleName: string;
    functionName: string;
}

interface Session {
    ciphertext: string;
    label: string;
}

async function main() {
    ensureDataDir();

    const cfg = readJson<Config>(path.join(DATA_DIR, 'config.json'));
    const group = readJson<GroupData>(path.join(DATA_DIR, 'group.json'));
    const credential = readJson<MemberCredential>(path.join(DATA_DIR, 'member-credential.json'));
    const session = readJson<Session>(path.join(DATA_DIR, 'session.json'));

    const callerKeypair = await ACE.pke.keygen();
    const encPk = new Uint8Array(callerKeypair.encryptionKey.toBytes());
    const encSk = new Uint8Array(callerKeypair.decryptionKey.toBytes());
    const label = hexToBytes(session.label);

    const circuitInput = buildCircuitInput({ group, credential, label, encPk });
    const wasmPath = path.join(CIRCUIT_DIR, 'member_vault_js', 'member_vault.wasm');
    const zkeyPath = path.join(CIRCUIT_DIR, 'member_vault_final.zkey');

    console.log('Generating anonymous membership proof...');
    console.log(`  Member credential used locally: ${credential.name}`);
    console.log('  Publicly revealed: root, label binding, enc_pk binding, nullifier');
    const { proof, publicSignals } = await groth16.fullProve(circuitInput, wasmPath, zkeyPath);
    const nullifier = BigInt(publicSignals[0]!);
    console.log(`  Request nullifier: 0x${nullifier.toString(16)}`);
    console.log('');

    const payload = new Uint8Array(288);
    payload.set(proofToBytes(proof), 0);
    payload.set(uint256ToLeBytes(nullifier), 256);

    const aceDeployment = new ACE.AceDeployment({
        apiEndpoint: cfg.aceApiEndpoint,
        contractAddr: AccountAddress.fromString(cfg.aceContractAddr),
    });

    console.log('Sending proof payload to ACE workers...');
    const decrypted = await ACE.AptosCustomFlow.decrypt({
        ciphertext: hexToBytes(session.ciphertext),
        label,
        encPk,
        encSk,
        payload,
        aceDeployment,
        keypairId: AccountAddress.fromString(cfg.keypairId),
        chainId: cfg.chainId,
        moduleAddr: AccountAddress.fromString(cfg.adminAddress),
        moduleName: cfg.moduleName,
        functionName: cfg.functionName,
    });

    console.log('');
    console.log('=== Decryption successful ===');
    console.log(`Plaintext: "${new TextDecoder().decode(decrypted)}"`);
    console.log('');
    console.log('The verifier accepted membership without learning which member decrypted.');
}

main().catch(err => { console.error(err); process.exit(1); });
