// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 1 — Generate Alice's account, fund her, and validate the ACE config
 * the rest of the steps use.
 *
 * Alice is the data owner: she deploys the contract in step 2, encrypts +
 * grants in step 3, rotates in step 5. Bob never gets an on-chain identity
 * — the whole point of the bearer-token pattern is that holding the
 * `accessPrivateKey` is the only thing that matters for read access.
 *
 * Idempotent: reuses `data/alice.json` if present, skips the faucet call
 * if Alice already has APT.
 */

import { existsSync } from 'fs';
import { Account, Ed25519PrivateKey } from '@aptos-labs/ts-sdk';

import {
    ALICE_FILE, AccountFile,
    aptosFromConfig, ensureDataDir, fundViaLocalnetFaucet, log, readAceConfig,
    readJson, waitForEnter, writeJson,
} from './common.js';

const REQUIRED_OCTAS = 200_000_000; // 2 APT — enough to deploy + register + rotate
const POLL_INTERVAL_MS = 3_000;
const POLL_TIMEOUT_MS = 60_000;

async function readBalance(aptos: ReturnType<typeof aptosFromConfig>, account: Account): Promise<number> {
    try {
        return await aptos.getAccountAPTAmount({ accountAddress: account.accountAddress });
    } catch {
        return 0;
    }
}

async function main() {
    ensureDataDir();

    // Sanity: the rest of the demo reads this. Fail loudly here so the user
    // doesn't get a confusing error three steps later.
    const cfg = readAceConfig();

    let alice: Account;
    if (existsSync(ALICE_FILE)) {
        const f = readJson<AccountFile>(ALICE_FILE);
        alice = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(f.privateKeyHex) });
        log(`Reusing Alice from ${ALICE_FILE}`);
    } else {
        alice = Account.generate();
        const privateKeyHex = '0x' + Buffer.from((alice as any).privateKey.toUint8Array()).toString('hex');
        writeJson(ALICE_FILE, {
            address: alice.accountAddress.toStringLong(),
            privateKeyHex,
        } satisfies AccountFile);
        log(`Generated new Alice; wrote ${ALICE_FILE}`);
    }
    log(`Alice address: ${alice.accountAddress.toStringLong()}`);

    const aptos = aptosFromConfig(cfg);
    const balance = await readBalance(aptos, alice);
    if (balance >= REQUIRED_OCTAS) {
        log(`Alice already funded (${balance / 1e8} APT)`);
    } else {
        if (cfg.network === 'localnet') {
            log(`Funding Alice with ${REQUIRED_OCTAS / 1e8} APT from the localnet faucet...`);
            await fundViaLocalnetFaucet(alice.accountAddress, REQUIRED_OCTAS);
            log('Funded.');
        } else {
            console.log('');
            console.log('='.repeat(72));
            console.log('FUND ALICE VIA THE APTOS TESTNET FAUCET');
            console.log('='.repeat(72));
            console.log('');
            console.log('  Address: ' + alice.accountAddress.toStringLong());
            console.log('');
            console.log('  Faucet:  https://aptos.dev/en/network/faucet');
            console.log('');
            console.log('='.repeat(72));
            console.log('');
            await waitForEnter('Press Enter once Alice has been funded... ');

            log(`Polling balance (need >= ${REQUIRED_OCTAS / 1e8} APT)...`);
            const start = Date.now();
            while (true) {
                const freshBalance = await readBalance(aptos, alice);
                if (freshBalance >= REQUIRED_OCTAS) {
                    log(`Alice funded (${freshBalance / 1e8} APT)`);
                    break;
                }
                const elapsed = Date.now() - start;
                if (elapsed >= POLL_TIMEOUT_MS) {
                    throw new Error(
                        `Alice has ${freshBalance / 1e8} APT after ${POLL_TIMEOUT_MS / 1000}s ` +
                        `(need >= ${REQUIRED_OCTAS / 1e8} APT). Re-run after faucet funding lands.`,
                    );
                }
                log(`  ${freshBalance / 1e8} APT — waiting (${Math.floor(elapsed / 1000)}s elapsed)...`);
                await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
            }
        }
    }

    log('');
    log('Next: pnpm 2-deploy-contract');
}

main().catch(err => { console.error(err); process.exit(1); });
