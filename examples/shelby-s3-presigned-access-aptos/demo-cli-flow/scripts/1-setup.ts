// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 1 — Generate Alice's account, fund her, and snapshot the localnet
 * config the rest of the steps use.
 *
 * Alice is the data owner: she deploys the contract in step 2, encrypts +
 * grants in step 3, rotates in step 5. Bob never gets an on-chain identity
 * — the whole point of the bearer-token pattern is that holding the
 * `accessToken` is the only thing that matters for read access.
 *
 * Idempotent: reuses `data/alice.json` if present, skips the faucet call
 * if Alice already has APT.
 */

import { existsSync } from 'fs';
import { Account, Aptos, AptosConfig, Ed25519PrivateKey, Network } from '@aptos-labs/ts-sdk';

import {
    ALICE_FILE, AccountFile,
    ensureDataDir, fundViaFaucet, log, readJson, readLocalnetConfig, writeJson,
} from './common.js';

const REQUIRED_OCTAS = 200_000_000; // 2 APT — enough to deploy + register + rotate

async function main() {
    ensureDataDir();

    // Sanity: the rest of the demo reads this. Fail loudly here so the user
    // doesn't get a confusing error three steps later.
    readLocalnetConfig();

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

    const cfg = readLocalnetConfig();
    const aptos = new Aptos(new AptosConfig({ network: Network.LOCAL, fullnode: cfg.apiEndpoint }));
    const balance = await aptos.getAccountAPTAmount({ accountAddress: alice.accountAddress }).catch(() => 0);
    if (balance >= REQUIRED_OCTAS) {
        log(`Alice already funded (${balance / 1e8} APT)`);
    } else {
        log(`Funding Alice with ${REQUIRED_OCTAS / 1e8} APT from the localnet faucet...`);
        await fundViaFaucet(alice.accountAddress, REQUIRED_OCTAS);
        log('Funded.');
    }

    log('');
    log('Next: pnpm 2-deploy-contract');
}

main().catch(err => { console.error(err); process.exit(1); });
