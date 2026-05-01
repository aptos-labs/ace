// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 1 — Generate Alice's keypair and wait for the user to fund it.
 *
 * Alice is the only account that needs APT in this tutorial: she deploys the
 * contract, registers the blob, and updates its allowlist. Bob's keypair is
 * generated later in step 4 and never sees an on-chain transaction.
 */

import { Account, Aptos, AptosConfig, Network } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { ALICE_FILE, ensureDataDir, log, waitForEnter, writeJson } from './common.js';

async function main() {
    ensureDataDir();

    const alice = Account.generate();
    const address = alice.accountAddress.toStringLong();
    const privateKeyHex = '0x' + Buffer.from(alice.privateKey.toUint8Array()).toString('hex');

    log('Generated Alice keypair.');
    log(`  Address:    ${address}`);

    const { aceDeployment } = ACE.knownDeployments.preview20260501;
    const aptos = new Aptos(new AptosConfig({
        network: Network.CUSTOM,
        fullnode: aceDeployment.apiEndpoint,
    }));

    console.log('');
    console.log('='.repeat(72));
    console.log('FUND ALICE WITH ~2 APT ON APTOS TESTNET');
    console.log('='.repeat(72));
    console.log('');
    console.log('  Address: ' + address);
    console.log('');
    console.log('  Faucet:  https://aptos.dev/en/network/faucet');
    console.log('           (the testnet faucet hands out 1 APT per click — click twice)');
    console.log('');
    console.log('='.repeat(72));
    console.log('');

    await waitForEnter('Press Enter once Alice has been funded... ');

    log('Verifying Alice balance...');
    const balance = await aptos.getAccountAPTAmount({ accountAddress: alice.accountAddress });
    log(`  Balance: ${balance / 100_000_000} APT`);
    if (balance < 100_000_000) {
        console.error('ERROR: Alice has less than 1 APT. Fund her first, then re-run step 1.');
        process.exit(1);
    }

    writeJson(ALICE_FILE, { address, privateKeyHex });
    log(`Saved Alice keypair to ${ALICE_FILE}`);
    log('');
    log('Next: pnpm 2-deploy-contract');
}

main().catch(err => { console.error(err); process.exit(1); });
