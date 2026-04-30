// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Script 2 — Deploy KYC Verifier Contract
 *
 * Reads circuit/vk.json and data/provider-key.json, then:
 *   1. Creates a fresh admin account and funds it via the faucet.
 *   2. Deploys the `kyc_verifier` Move module.
 *   3. Calls `initialize` with the Groth16 VK and provider public key.
 *   4. Writes deployment info to data/config.json.
 *
 * Prerequisites:
 *   - Aptos localnet running (from `pnpm run-local-network-forever` in scenarios/).
 *   - circuit/setup.sh has been run (vk.json must exist).
 *   - scripts/1-provider-setup.ts has been run (provider-key.json must exist).
 */

import { Account, Aptos, AptosConfig, Network } from '@aptos-labs/ts-sdk';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import * as os from 'os';
import * as path from 'path';
import { spawnSync } from 'child_process';
import {
    CHAIN_ID, CIRCUIT_DIR, CONTRACT_DIR, DATA_DIR, LOCALNET_URL,
    ensureDataDir, g1ToBytes, g2ToBytes, readJson, uint256ToLeBytes, writeJson,
} from './common.js';

interface VkJson {
    protocol: string;
    curve: string;
    nPublic: number;
    vk_alpha_1: string[];
    vk_beta_2: string[][];
    vk_gamma_2: string[][];
    vk_delta_2: string[][];
    IC: string[][];
}

interface ProviderKey {
    private: string;
    public_ax: string;
    public_ay: string;
}

async function main() {
    ensureDataDir();

    const vkPath = path.join(CIRCUIT_DIR, 'vk.json');
    const providerKeyPath = path.join(DATA_DIR, 'provider-key.json');

    const vk = readJson<VkJson>(vkPath);
    const providerKey = readJson<ProviderKey>(providerKeyPath);

    if (vk.IC.length !== 7) {
        throw new Error(
            `Expected 7 IC points (1 constant + 1 nullifier output + 5 public inputs), got ${vk.IC.length}.\n` +
            'Make sure circuit/setup.sh was run against kyc.circom.',
        );
    }

    // ── Encode VK ─────────────────────────────────────────────────────────────
    const vkAlphaG1 = g1ToBytes(vk.vk_alpha_1);
    const vkBetaG2  = g2ToBytes(vk.vk_beta_2);
    const vkGammaG2 = g2ToBytes(vk.vk_gamma_2);
    const vkDeltaG2 = g2ToBytes(vk.vk_delta_2);

    const vkIc = new Uint8Array(7 * 64);
    for (let i = 0; i < 7; i++) {
        vkIc.set(g1ToBytes(vk.IC[i]!), i * 64);
    }

    const pkProviderAx = uint256ToLeBytes(BigInt(providerKey.public_ax));
    const pkProviderAy = uint256ToLeBytes(BigInt(providerKey.public_ay));

    // ── Create and fund admin account ─────────────────────────────────────────
    console.log('Generating admin account...');
    const admin = Account.generate();
    const adminAddress = admin.accountAddress.toStringLong();
    const adminPrivKeyHex = Buffer.from(admin.privateKey.toUint8Array()).toString('hex');
    console.log(`  Admin address: ${adminAddress}`);

    const aptos = new Aptos(new AptosConfig({ network: Network.CUSTOM, fullnode: LOCALNET_URL, faucet: 'http://127.0.0.1:8081' }));
    console.log('Funding admin via faucet...');
    const faucetResp = await fetch(`http://127.0.0.1:8081/mint?amount=200000000&address=${adminAddress}`, { method: 'POST' });
    if (!faucetResp.ok) throw new Error(`Faucet failed: ${await faucetResp.text()}`);
    await new Promise(r => setTimeout(r, 2000)); // let the funding confirm

    // ── Deploy Move contract ──────────────────────────────────────────────────
    console.log('Deploying kyc_verifier module...');
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'kyc-'));
    const tmpContract = path.join(tmpDir, 'contract');
    cpSync(CONTRACT_DIR, tmpContract, { recursive: true });

    // Replace placeholder address in Move.toml
    const moveTomlPath = path.join(tmpContract, 'Move.toml');
    writeFileSync(
        moveTomlPath,
        readFileSync(moveTomlPath, 'utf8').replaceAll('0xcafe', adminAddress),
    );

    try {
        const result = spawnSync('aptos', [
            'move', 'publish',
            '--package-dir', tmpContract,
            '--private-key', `0x${adminPrivKeyHex}`,
            '--url', LOCALNET_URL,
            '--assume-yes',
            '--skip-fetch-latest-git-deps',
        ], { stdio: 'inherit', encoding: 'utf8' });
        if (result.status !== 0) throw new Error('`aptos move publish` failed');
    } finally {
        rmSync(tmpDir, { recursive: true, force: true });
    }
    console.log('Module deployed.');

    // ── Call initialize ───────────────────────────────────────────────────────
    console.log('Initializing contract with VK and provider public key...');
    const txn = await aptos.transaction.build.simple({
        sender: admin.accountAddress,
        data: {
            function: `${adminAddress}::kyc_verifier::initialize` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [
                Array.from(vkAlphaG1),
                Array.from(vkBetaG2),
                Array.from(vkGammaG2),
                Array.from(vkDeltaG2),
                Array.from(vkIc),
                Array.from(pkProviderAx),
                Array.from(pkProviderAy),
            ],
        },
    });
    const signed = aptos.transaction.sign({ signer: admin, transaction: txn });
    const submitted = await aptos.transaction.submit.simple({ transaction: txn, senderAuthenticator: signed });
    await aptos.waitForTransaction({ transactionHash: submitted.hash });
    console.log('Contract initialized.');

    // ── Read ACE config ───────────────────────────────────────────────────────
    const aceConfig = readJson<{ apiEndpoint: string; contractAddr: string; keypairId: string }>(
        '/tmp/ace-localnet-config.json',
    );

    // ── Write config ──────────────────────────────────────────────────────────
    const config = {
        adminAddress,
        adminPrivKeyHex,
        aceApiEndpoint: aceConfig.apiEndpoint,
        aceContractAddr: aceConfig.contractAddr,
        keypairId: aceConfig.keypairId,
        chainId: CHAIN_ID,
        moduleName: 'kyc_verifier',
        functionName: 'check_acl',
    };
    const configPath = path.join(DATA_DIR, 'config.json');
    writeJson(configPath, config);

    console.log('');
    console.log('Deployment complete!');
    console.log(`  Admin address  : ${adminAddress}`);
    console.log(`  ACE contract   : ${aceConfig.contractAddr}`);
    console.log(`  Keypair ID     : ${aceConfig.keypairId}`);
    console.log(`  Config saved to: ${configPath}`);
    console.log('');
    console.log('Next: run script 3 to issue a KYC credential.');
}

main().catch(err => { console.error(err); process.exit(1); });
