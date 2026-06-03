// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 1 - Generate the file owner keypair and wait for testnet funding.
 *
 * The access token account created later is intentionally unfunded. It only
 * signs ACE decryption requests; it never submits an Aptos transaction.
 */

import { existsSync } from 'fs';
import { Account, Aptos, AptosConfig, Ed25519PrivateKey, Network } from '@aptos-labs/ts-sdk';

import {
    AccountFile, OWNER_FILE, SHELBY_ACE_DEPLOYMENT,
    ensureDataDir, log, privateKeyHex, readJson, waitForEnter, writeJson,
} from './common.js';

const REQUIRED_OCTAS = 150_000_000; // 1.5 APT - enough to deploy and register the demo file.
const POLL_INTERVAL_MS = 3_000;
const POLL_TIMEOUT_MS = 60_000;

async function readBalance(aptos: Aptos, account: Account): Promise<number> {
    try {
        return await aptos.getAccountAPTAmount({ accountAddress: account.accountAddress });
    } catch {
        return 0;
    }
}

async function main() {
    ensureDataDir();

    let address: string;
    let ownerPrivateKeyHex: string;
    if (existsSync(OWNER_FILE)) {
        const existing = readJson<AccountFile>(OWNER_FILE);
        address = existing.address;
        ownerPrivateKeyHex = existing.privateKeyHex;
        log(`Reusing existing owner keypair: ${address}`);
    } else {
        const owner = Account.generate();
        address = owner.accountAddress.toStringLong();
        ownerPrivateKeyHex = privateKeyHex(owner);
        writeJson(OWNER_FILE, { address, privateKeyHex: ownerPrivateKeyHex });
        log('Generated owner keypair.');
        log(`  Address:  ${address}`);
        log(`  Saved to: ${OWNER_FILE}`);
    }

    const owner = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(ownerPrivateKeyHex) });
    const aptos = new Aptos(new AptosConfig({
        network: Network.CUSTOM,
        fullnode: SHELBY_ACE_DEPLOYMENT.apiEndpoint,
    }));

    const initialBalance = await readBalance(aptos, owner);
    if (initialBalance >= REQUIRED_OCTAS) {
        log(`Owner already funded: ${initialBalance / 100_000_000} APT`);
        log('');
        log('Next: pnpm 2-deploy-contract');
        return;
    }

    console.log('');
    console.log('='.repeat(72));
    console.log('FUND THE OWNER VIA THE APTOS TESTNET FAUCET');
    console.log('='.repeat(72));
    console.log('');
    console.log('  Address: ' + address);
    console.log('');
    console.log('  Faucet:  https://aptos.dev/en/network/faucet');
    console.log('');
    console.log('='.repeat(72));
    console.log('');

    await waitForEnter('Press Enter once the owner has been funded... ');

    log(`Polling balance (need >= ${REQUIRED_OCTAS / 100_000_000} APT)...`);
    const start = Date.now();
    let balance = 0;
    while (true) {
        balance = await readBalance(aptos, owner);
        if (balance >= REQUIRED_OCTAS) break;
        const elapsed = Date.now() - start;
        if (elapsed >= POLL_TIMEOUT_MS) {
            console.error('');
            console.error(`ERROR: owner has ${balance / 100_000_000} APT after ${POLL_TIMEOUT_MS / 1000}s`);
            console.error('Re-run `pnpm 1-setup` after the faucet transfer lands.');
            process.exit(1);
        }
        log(`  ${balance / 100_000_000} APT - waiting (${Math.floor(elapsed / 1000)}s elapsed)...`);
        await new Promise(resolve => setTimeout(resolve, POLL_INTERVAL_MS));
    }

    log(`Balance: ${balance / 100_000_000} APT`);
    log('');
    log('Next: pnpm 2-deploy-contract');
}

main().catch(err => { console.error(err); process.exit(1); });
