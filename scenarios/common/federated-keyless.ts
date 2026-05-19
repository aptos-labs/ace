// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Federated-keyless test helpers — used by `test-access-failures-federated-keyless.ts`.
 *
 * Two phases live here:
 *
 *   1. Chain init (framework-signer scope):
 *      `runFederatedKeylessFrameworkBootstrap` — invokes
 *      `federated-keyless-bootstrap.move` to clear `0x1::jwks::PatchedJWKs`
 *      and install the Groth16 VK + Configuration. Should run right after
 *      `startLocalnet()`, before any ACE setup.
 *
 *   2. App init (dapp signer scope):
 *      `installFederatedJwk` — has the dapp publish the test RSA JWK at its
 *      own `FederatedJWKs` resource via `0x1::jwks::update_federated_jwk_set`.
 *      Should run only when the federated identity is about to be used (e.g.
 *      right before access-control blob registration), not in the chain-init
 *      phase.
 *
 * Plus a `buildBobFederatedKeylessAccount` factory tied to the sample fixtures.
 */

import {
    Account,
    AccountAddress,
    Ed25519PrivateKey,
    EphemeralKeyPair,
    FederatedKeylessAccount,
    Groth16Zkp,
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
import { assertTxnSuccess, submitTxn } from './helpers';
import {
    SAMPLE_EPHEMERAL_SK_HEX,
    SAMPLE_EPK_BLINDER_HEX,
    SAMPLE_EXP_DATE_SECS,
    SAMPLE_EXP_HORIZON_SECS,
    SAMPLE_ISS,
    SAMPLE_JWK_ALG,
    SAMPLE_JWK_E,
    SAMPLE_JWK_KID,
    SAMPLE_JWK_N,
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

/**
 * The `aptos` CLI resolves its test-dir from the nearest `.aptos` folder
 * walking from cwd upward (matches `get_derived_test_dir` in aptos-core); it
 * only falls back to `~/.aptos` if none is found. We mirror that to avoid
 * picking up a stale `~/.aptos/testnet/mint.key` from a different localnet.
 */
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

/**
 * Runs `scenarios/federated-keyless-bootstrap.move` against the localnet's
 * `core_resources` (`0xA550C18`) account. See the script for what it installs.
 * Chain-level — should be one of the first things called after localnet is up.
 */
export async function runFederatedKeylessFrameworkBootstrap(): Promise<void> {
    const mintKeyPath = resolveLocalnetMintKeyPath();
    const scriptPath = path.join(REPO_ROOT, 'scenarios', 'federated-keyless-bootstrap.move');

    console.log('  Running federated-keyless bootstrap script (clears system JWKs, installs Groth16 VK + config)...');
    const { stdout, stderr } = await execFileAsync(
        'aptos',
        [
            'move',
            'run-script',
            '--script-path', scriptPath,
            // mint.key is the BCS-encoded `Ed25519PrivateKey` (33 bytes:
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
    if (stdout) process.stdout.write(`  [federated-keyless-bootstrap] ${stdout}`);
    if (stderr) process.stderr.write(`  [federated-keyless-bootstrap] ${stderr}`);
    console.log('  Federated-keyless bootstrap script: OK');
}

/**
 * Publishes the test RSA JWK at `jwk_owner::0x1::jwks::FederatedJWKs`. Plain
 * `public entry fun` — no governance involved. Mirrors the install step in
 * `aptos-core/testsuite/smoke-test/src/keyless.rs::federated_keyless_scenario`.
 *
 * Must be live before any signature from a `FederatedKeylessAccount` whose
 * `jwkAddress` is `jwk_owner.accountAddress` is verified.
 */
export async function installFederatedJwk(jwk_owner: Account): Promise<void> {
    assertTxnSuccess(
        await submitTxn({
            signer: jwk_owner,
            entryFunction: '0x1::jwks::update_federated_jwk_set',
            args: [
                Array.from(new TextEncoder().encode(SAMPLE_ISS)),
                [SAMPLE_JWK_KID],
                [SAMPLE_JWK_ALG],
                [SAMPLE_JWK_E],
                [SAMPLE_JWK_N],
            ],
        }),
        '0x1::jwks::update_federated_jwk_set',
    );
}

/**
 * Build a `FederatedKeylessAccount` from the hard-coded sample fixtures. All
 * inputs are tied to `SAMPLE_PROOF`; do not vary them independently or the
 * Groth16 proof will not verify.
 *
 * `jwkAddress` is the on-chain account where the dapp's `FederatedJWKs`
 * resource lives. The worker (and the chain VM) hashes it into the auth-key,
 * so this MUST match the account `installFederatedJwk` was called on.
 */
export function buildBobFederatedKeylessAccount(jwkAddress: AccountAddress): FederatedKeylessAccount {
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
    const proof = new ZeroKnowledgeSig({
        proof: new ZkProof(groth16Zkp, ZkpVariant.Groth16),
        expHorizonSecs: Number(SAMPLE_EXP_HORIZON_SECS),
    });

    return FederatedKeylessAccount.create({
        proof,
        jwt: SAMPLE_JWT,
        ephemeralKeyPair,
        pepper: hexToBytes(SAMPLE_PEPPER_HEX),
        uidKey: SAMPLE_UID_KEY,
        jwkAddress,
    });
}
