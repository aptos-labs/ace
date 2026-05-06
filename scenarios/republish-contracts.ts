// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Republish all 11 ACE Move packages to an existing deployment.
 *
 * Reads admin private key + RPC URL (and optional shared-node API key) from
 * a deployment JSON of the shape produced by `pnpm new-{devnet,testnet}-deployment`.
 *
 * Usage:
 *   pnpm republish-contracts <path-to-deployment-json> [--yes]
 *
 * Notes:
 * - Assumes the on-chain modules are still publishable under their existing
 *   upgrade policy (default = `compatible`). If you've made an incompatible
 *   change, the first affected `aptos move publish` will fail with a
 *   compatibility error; either revise the change or set
 *   `upgrade_policy = "arbitrary"` in the package's Move.toml.
 * - Order is the canonical dep order from the new-deployment wizards;
 *   `vss → dkg → dkr → epoch-change → network` must be preserved.
 */

import * as readline from 'readline';
import { readFileSync } from 'fs';
import { Account, Ed25519PrivateKey } from '@aptos-labs/ts-sdk';

import { deployContracts, log } from './common/helpers';

// Canonical dep order — must match the new-{devnet,testnet}-deployment scripts.
const PACKAGES = [
    'pke', 'worker_config', 'group', 'fiat-shamir-transform',
    'sigma-dlog-eq', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network',
];

interface DeploymentJson {
    rpcUrl: string;
    adminAddress: string;
    adminPrivateKey: string;
    sharedNodeApiKey?: string;
    network?: string;
}

function usage(): never {
    console.error('Usage: pnpm republish-contracts <path-to-deployment-json> [--yes]');
    process.exit(2);
}

async function confirm(prompt: string): Promise<boolean> {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    try {
        const answer: string = await new Promise(resolve => rl.question(prompt, resolve));
        return /^y(es)?$/i.test(answer.trim());
    } finally {
        rl.close();
    }
}

async function main(): Promise<void> {
    const args = process.argv.slice(2).filter(a => !a.startsWith('-'));
    const flags = new Set(process.argv.slice(2).filter(a => a.startsWith('-')));
    if (args.length !== 1) usage();
    const jsonPath = args[0];

    const json = JSON.parse(readFileSync(jsonPath, 'utf8')) as DeploymentJson;
    if (!json.rpcUrl || !json.adminPrivateKey) {
        console.error(`${jsonPath} is missing rpcUrl or adminPrivateKey`);
        process.exit(2);
    }

    const sk = new Ed25519PrivateKey(json.adminPrivateKey);
    const adminAccount = Account.fromPrivateKey({ privateKey: sk });
    const adminAddr = adminAccount.accountAddress.toStringLong();
    if (json.adminAddress && json.adminAddress.toLowerCase() !== adminAddr.toLowerCase()) {
        console.error(`adminAddress in JSON (${json.adminAddress}) does not match key-derived address (${adminAddr})`);
        process.exit(2);
    }

    if (json.sharedNodeApiKey) {
        // Picked up by `aptos move publish` as `Authorization: Bearer <key>`.
        process.env.NODE_API_KEY = json.sharedNodeApiKey;
    }

    log('');
    log('Republishing ACE contracts:');
    log(`  network : ${json.network ?? '(unspecified)'}`);
    log(`  rpcUrl  : ${json.rpcUrl}`);
    log(`  admin   : ${adminAddr}`);
    log(`  api key : ${json.sharedNodeApiKey ? 'present (NODE_API_KEY set)' : 'none'}`);
    log(`  packages: ${PACKAGES.join(', ')}`);
    log('');

    if (!flags.has('--yes') && !flags.has('-y')) {
        if (!await confirm('Proceed? [y/N] ')) {
            log('Aborted.');
            return;
        }
    }

    await deployContracts(adminAccount, PACKAGES, json.rpcUrl);
    log('');
    log('All 11 packages republished.');
}

main().catch(err => { console.error(err); process.exit(1); });
