// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 1 — Generate Alice's keypair and wait for the user to fund it.
 *
 * Alice is the only account funded from the testnet faucet. She deploys the
 * contract, lists items, sends Bob a small APT allowance in step 4, and
 * eventually receives Bob's payment in step 5. Bob's keypair is generated in
 * step 4 and funded by Alice — keeping the dev's faucet visit to one trip.
 *
 * The script is idempotent: it reuses `data/alice.json` if present, and skips
 * the faucet prompt entirely if Alice is already funded.
 */

import { existsSync } from 'fs';
import { Account, Aptos, AptosConfig, Ed25519PrivateKey, Network } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import {
    ALICE_FILE, AccountFile, ensureDataDir, log, readJson, waitForEnter, writeJson,
} from './common.js';

const REQUIRED_OCTAS = 150_000_000; // 1.5 APT — enough to deploy, list, fund Bob
const POLL_INTERVAL_MS = 3_000;
const POLL_TIMEOUT_MS = 60_000;

async function readBalance(aptos: Aptos, account: Account): Promise<number> {
    try {
        return await aptos.getAccountAPTAmount({ accountAddress: account.accountAddress });
    } catch {
        return 0; // account doesn't exist yet (no funding has landed)
    }
}

async function main() {
    ensureDataDir();

    let address: string;
    let privateKeyHex: string;
    if (existsSync(ALICE_FILE)) {
        const existing = readJson<AccountFile>(ALICE_FILE);
        address = existing.address;
        privateKeyHex = existing.privateKeyHex;
        log(`Reusing existing Alice keypair: ${address}`);
    } else {
        const alice = Account.generate();
        address = alice.accountAddress.toStringLong();
        privateKeyHex = '0x' + Buffer.from(alice.privateKey.toUint8Array()).toString('hex');
        writeJson(ALICE_FILE, { address, privateKeyHex });
        log('Generated Alice keypair.');
        log(`  Address:    ${address}`);
        log(`  Saved to:   ${ALICE_FILE}`);
    }

    const alice = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(privateKeyHex) });

    const { aceDeployment } = ACE.knownDeployments.preview20260504;
    const aptos = new Aptos(new AptosConfig({
        network: Network.CUSTOM,
        fullnode: aceDeployment.apiEndpoint,
    }));

    const initialBalance = await readBalance(aptos, alice);
    if (initialBalance >= REQUIRED_OCTAS) {
        log(`✓ Alice already funded: ${initialBalance / 100_000_000} APT`);
        log('');
        log('Next: pnpm 2-deploy-contract');
        return;
    }

    console.log('');
    console.log('='.repeat(72));
    console.log('FUND ALICE VIA THE APTOS TESTNET FAUCET');
    console.log('='.repeat(72));
    console.log('');
    console.log('  Address: ' + address);
    console.log('');
    console.log('  Faucet:  https://aptos.dev/en/network/faucet');
    console.log('           (one click drops ~10 APT — plenty for the tutorial)');
    console.log('');
    console.log('='.repeat(72));
    console.log('');

    await waitForEnter('Press Enter once Alice has been funded... ');

    log(`Polling balance (need ≥ ${REQUIRED_OCTAS / 100_000_000} APT, faucet drops can take a few seconds)...`);
    const start = Date.now();
    let balance = 0;
    while (true) {
        balance = await readBalance(aptos, alice);
        if (balance >= REQUIRED_OCTAS) break;
        const elapsed = Date.now() - start;
        if (elapsed >= POLL_TIMEOUT_MS) {
            console.error('');
            console.error(`ERROR: Alice has ${balance / 100_000_000} APT after ${POLL_TIMEOUT_MS / 1000}s ` +
                          `(need ≥ ${REQUIRED_OCTAS / 100_000_000} APT).`);
            console.error('  - The faucet may be slow or rate-limiting you.');
            console.error('  - Re-run `pnpm 1-setup` and click the faucet again — your keypair is preserved.');
            process.exit(1);
        }
        log(`  ${balance / 100_000_000} APT — waiting (${Math.floor(elapsed / 1000)}s elapsed)...`);
        await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
    }
    log(`✓ Balance: ${balance / 100_000_000} APT`);
    log('');
    log('Next: pnpm 2-deploy-contract');
}

main().catch(err => { console.error(err); process.exit(1); });
