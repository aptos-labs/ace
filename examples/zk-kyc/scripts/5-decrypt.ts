// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Script 5 — Generate ZK Proof and Decrypt
 *
 * This is the core of the ZK-KYC demo.
 *
 * 1. Reads the credential (age + EdDSA signature from the provider).
 * 2. Generates an ephemeral PKE keypair for this decrypt request (bound in the proof).
 * 3. Packs the caller's enc_pk into the three BN254 Fr public inputs.
 * 4. Generates a Groth16 proof using snarkjs — this is where the ZK magic
 *    happens: the proof asserts that the holder has a valid credential and is
 *    18 or older, WITHOUT revealing the actual age.
 * 5. Sends the proof as the `payload` to `AptosCustomFlow.decrypt`.
 *    ACE workers call `kyc_verifier::check_acl` on-chain; if the proof
 *    verifies, they release their key shares.
 * 6. Reconstructs the threshold key and decrypts the ciphertext.
 */

import { AccountAddress } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { groth16 } from 'snarkjs';
import * as path from 'path';
import {
    CIRCUIT_DIR, DATA_DIR, ensureDataDir,
    readJson, packEncPk, proofToBytes, uint256ToLeBytes,
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

interface ProviderKey {
    private: string;
    public_ax: string;
    public_ay: string;
}

interface Credential {
    user_secret: string;
    age: number;
    sig_r8x: string;
    sig_r8y: string;
    sig_s: string;
}

interface Session {
    ciphertext: string;
    label: string;
}

async function main() {
    ensureDataDir();

    const cfg          = readJson<Config>(path.join(DATA_DIR, 'config.json'));
    const providerKey  = readJson<ProviderKey>(path.join(DATA_DIR, 'provider-key.json'));
    const credential   = readJson<Credential>(path.join(DATA_DIR, 'credential.json'));
    const session      = readJson<Session>(path.join(DATA_DIR, 'session.json'));

    const ciphertext = Uint8Array.from(Buffer.from(session.ciphertext, 'hex'));
    const label      = Uint8Array.from(Buffer.from(session.label, 'hex'));

    const callerKeypair = await ACE.pke.keygen();
    const encPk = new Uint8Array(callerKeypair.encryptionKey.toBytes());
    const encSk = new Uint8Array(callerKeypair.decryptionKey.toBytes());

    // ── Build circuit inputs ──────────────────────────────────────────────────
    const [p0, p1, p2] = packEncPk(encPk);

    const circuitInput = {
        // Public inputs (also verified on-chain by check_acl)
        pk_provider_ax: providerKey.public_ax,
        pk_provider_ay: providerKey.public_ay,
        enc_pk_p0: p0.toString(),
        enc_pk_p1: p1.toString(),
        enc_pk_p2: p2.toString(),
        // Private inputs (never revealed)
        user_secret: credential.user_secret,
        age: credential.age.toString(),
        sig_r8x: credential.sig_r8x,
        sig_r8y: credential.sig_r8y,
        sig_s:   credential.sig_s,
    };

    const wasmPath = path.join(CIRCUIT_DIR, 'kyc_js', 'kyc.wasm');
    const zkeyPath = path.join(CIRCUIT_DIR, 'kyc_final.zkey');

    // ── Generate ZK proof ─────────────────────────────────────────────────────
    console.log('Generating Groth16 proof (this may take a few seconds)...');
    console.log('  Proving:');
    console.log('    ✓ I hold a credential signed by the registered KYC provider');
    console.log('    ✓ My age is 18 or older');
    console.log('    ✓ The proof is bound to my enc_pk (no replay possible)');
    console.log('  The actual age remains private.');
    console.log('');

    const { proof, publicSignals } = await groth16.fullProve(circuitInput, wasmPath, zkeyPath);
    console.log('Proof generated.');

    // publicSignals[0] is the nullifier (circom outputs come before inputs).
    // A real app would record this on-chain and reject any future request that
    // presents the same nullifier — preventing credential reuse.
    const nullifier = BigInt(publicSignals[0]!);
    console.log(`  Nullifier: 0x${nullifier.toString(16)}`);
    console.log('  (a real app records this on-chain to prevent credential reuse)');
    console.log('');

    // Payload: proof (256B) || nullifier (32B LE Fr)
    const payload = new Uint8Array(288);
    payload.set(proofToBytes(proof), 0);
    payload.set(uint256ToLeBytes(nullifier), 256);

    // ── ACE decrypt ───────────────────────────────────────────────────────────
    const aceDeployment = new ACE.AceDeployment({
        apiEndpoint: cfg.aceApiEndpoint,
        contractAddr: AccountAddress.fromString(cfg.aceContractAddr),
    });
    const keypairId  = AccountAddress.fromString(cfg.keypairId);
    const moduleAddr = AccountAddress.fromString(cfg.adminAddress);

    console.log('Sending proof to ACE workers for on-chain verification...');
    const decrypted = await ACE.AptosCustomFlow.decrypt({
        ciphertext,
        label,
        encPk,
        encSk,
        payload,
        aceDeployment,
        keypairId,
        chainId:      cfg.chainId,
        moduleAddr,
        moduleName:   cfg.moduleName,
        functionName: cfg.functionName,
    });

    console.log('');
    console.log('=== Decryption successful! ===');
    console.log(`Plaintext: "${new TextDecoder().decode(decrypted)}"`);
}

main().catch(err => { console.error(err); process.exit(1); });
