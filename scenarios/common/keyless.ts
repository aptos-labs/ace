// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Regular keyless test helpers — used by `test-access-failures-keyless.ts`
 * (and a parallel for [`./federated-keyless.ts`]).
 *
 * Two pieces live here:
 *
 *   1. `runKeylessFrameworkBootstrap` — invokes `keyless-bootstrap.move` as
 *      the localnet's `core_resources` account to install the test RSA JWK,
 *      the Groth16 VK, and a relaxed `Configuration.max_exp_horizon_secs`.
 *      Should run right after `startLocalnet()`, before any ACE setup.
 *
 *   2. `buildBobKeylessAccount` — factory that produces a `KeylessAccount`
 *      tied to the same sample Groth16 proof / JWT / pepper / ephemeral key
 *      used across the keyless tests (see `keyless-fixtures.ts`).
 */

import {
    Ed25519PrivateKey,
    EphemeralKeyPair,
    Groth16Zkp,
    KeylessAccount,
    ZeroKnowledgeSig,
    ZkProof,
    ZkpVariant,
} from '@aptos-labs/ts-sdk';
import { execFile } from 'child_process';
import { existsSync } from 'fs';
import * as os from 'os';
import * as path from 'path';
import { promisify } from 'util';

import { LOCALNET_URL, REPO_ROOT } from './config';
import {
    SAMPLE_EPHEMERAL_SK_HEX,
    SAMPLE_EPK_BLINDER_HEX,
    SAMPLE_EXP_DATE_SECS,
    SAMPLE_EXP_HORIZON_SECS,
    SAMPLE_JWT,
    SAMPLE_PEPPER_HEX,
    SAMPLE_PROOF_A_HEX,
    SAMPLE_PROOF_B_HEX,
    SAMPLE_PROOF_C_HEX,
    SAMPLE_UID_KEY,
} from './keyless-fixtures';

const execFileAsync = promisify(execFile);

function hexToBytes(hex: string): Uint8Array {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
}

/** Walks cwd→root looking for `.aptos/testnet/mint.key`, falling back to
 *  `~/.aptos/testnet/mint.key`. Matches `get_derived_test_dir` in aptos-core
 *  so we never pick up a stale mint key from a different localnet. */
function resolveLocalnetMintKeyPath(): string {
    let dir = process.cwd();
    while (true) {
        const candidate = path.join(dir, '.aptos', 'testnet', 'mint.key');
        if (existsSync(candidate)) return candidate;
        const parent = path.dirname(dir);
        if (parent === dir) break;
        dir = parent;
    }
    const fallback = path.join(os.homedir(), '.aptos', 'testnet', 'mint.key');
    if (existsSync(fallback)) return fallback;
    throw new Error(
        `Localnet mint key not found (searched cwd→root for .aptos/testnet/mint.key, ` +
        `and ${fallback}). Did startLocalnet() run?`
    );
}

/** Runs `scenarios/keyless-bootstrap.move` against `0xA550C18` to install the
 *  insecure test JWK, the Groth16 VK matching `SAMPLE_PROOF`, and a relaxed
 *  `max_exp_horizon_secs`. Should be invoked right after `startLocalnet()`. */
export async function runKeylessFrameworkBootstrap(): Promise<void> {
    const mintKeyPath = resolveLocalnetMintKeyPath();
    const scriptPath = path.join(REPO_ROOT, 'scenarios', 'keyless-bootstrap.move');
    console.log('  Running keyless bootstrap script (installs JWK + Groth16 VK + config patch)...');
    const { stdout, stderr } = await execFileAsync(
        'aptos',
        [
            'move', 'run-script',
            '--script-path', scriptPath,
            // mint.key is BCS-encoded `Ed25519PrivateKey` (33 bytes:
            // uleb128(32) || 32 raw bytes); --encoding bcs unwraps it.
            '--private-key-file', mintKeyPath,
            '--encoding', 'bcs',
            '--sender-account', '0xA550C18',
            '--url', LOCALNET_URL,
            '--assume-yes',
            '--skip-fetch-latest-git-deps',
        ],
        { maxBuffer: 16 * 1024 * 1024 },
    );
    if (stdout) process.stdout.write(`  [keyless-bootstrap] ${stdout}`);
    if (stderr) process.stderr.write(`  [keyless-bootstrap] ${stderr}`);
    console.log('  Keyless bootstrap script: OK');
}

/** Build a `KeylessAccount` from the hard-coded sample fixtures. All inputs
 *  are tied to `SAMPLE_PROOF`; do not vary them independently or the Groth16
 *  proof will not verify. */
export function buildBobKeylessAccount(): KeylessAccount {
    const sk = new Ed25519PrivateKey(hexToBytes(SAMPLE_EPHEMERAL_SK_HEX));
    const ephemeralKeyPair = new EphemeralKeyPair({
        privateKey: sk,
        expiryDateSecs: Number(SAMPLE_EXP_DATE_SECS),
        blinder: hexToBytes(SAMPLE_EPK_BLINDER_HEX),
    });
    const groth16Zkp = new Groth16Zkp({
        a: SAMPLE_PROOF_A_HEX,
        b: SAMPLE_PROOF_B_HEX,
        c: SAMPLE_PROOF_C_HEX,
    });
    // SAMPLE_PROOF_NO_EXTRA_FIELD: extraField intentionally omitted — the
    // proof was generated without revealing any extra JWT claim.
    const proof = new ZeroKnowledgeSig({
        proof: new ZkProof(groth16Zkp, ZkpVariant.Groth16),
        expHorizonSecs: Number(SAMPLE_EXP_HORIZON_SECS),
    });
    return KeylessAccount.create({
        proof,
        jwt: SAMPLE_JWT,
        ephemeralKeyPair,
        pepper: hexToBytes(SAMPLE_PEPPER_HEX),
        uidKey: SAMPLE_UID_KEY,
    });
}
