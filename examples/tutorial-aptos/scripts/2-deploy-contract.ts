// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 2 — Alice deploys the `marketplace` module and initializes an empty catalog.
 *
 * Copies the Move package to a tempdir, rewrites the placeholder admin address
 * (0xcafe) to Alice's, runs `aptos move publish`, then calls `initialize`.
 */

import { spawnSync } from 'child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import * as os from 'os';
import * as path from 'path';

import { Account, Aptos, AptosConfig, Ed25519PrivateKey, Network } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

import {
    ALICE_FILE, AccountFile, CONFIG_FILE, CONTRACT_DIR,
    ensureDataDir, log, readJson, writeJson,
} from './common.js';

async function main() {
    ensureDataDir();

    const aliceFile = readJson<AccountFile>(ALICE_FILE);
    const alice = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(aliceFile.privateKeyHex) });
    const adminAddress = alice.accountAddress.toStringLong();

    const { aceDeployment } = ACE.knownDeployments.preview20260504;
    const rpcUrl = aceDeployment.apiEndpoint;

    log(`Deploying marketplace with admin = ${adminAddress}`);

    const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'tutorial-aptos-'));
    const tmpContract = path.join(tmpDir, 'contract');
    cpSync(CONTRACT_DIR, tmpContract, { recursive: true });

    const moveTomlPath = path.join(tmpContract, 'Move.toml');
    writeFileSync(
        moveTomlPath,
        readFileSync(moveTomlPath, 'utf8').replaceAll('0xcafe', adminAddress),
    );

    try {
        const result = spawnSync('aptos', [
            'move', 'publish',
            '--package-dir', tmpContract,
            '--private-key', aliceFile.privateKeyHex,
            '--url', rpcUrl,
            '--assume-yes',
            '--skip-fetch-latest-git-deps',
        ], { stdio: 'inherit', encoding: 'utf8' });
        if (result.status !== 0) throw new Error('`aptos move publish` failed');
    } finally {
        rmSync(tmpDir, { recursive: true, force: true });
    }
    log('Module published.');

    const aptos = new Aptos(new AptosConfig({ network: Network.CUSTOM, fullnode: rpcUrl }));
    log('Calling marketplace::initialize...');
    const txn = await aptos.transaction.build.simple({
        sender: alice.accountAddress,
        data: {
            function: `${adminAddress}::marketplace::initialize` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [],
        },
    });
    const submitted = await aptos.signAndSubmitTransaction({ signer: alice, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: submitted.hash });
    log('Catalog initialized.');

    writeJson(CONFIG_FILE, { appContractAddr: adminAddress });
    log(`Saved config to ${CONFIG_FILE}`);
    log('');
    log('Next: pnpm 3-list');
}

main().catch(err => { console.error(err); process.exit(1); });
