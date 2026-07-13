// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 2 — Alice deploys `capability_access` under her own address and
 * initializes the singleton `Registry`.
 *
 * The Move package's `admin = "0xcafe"` is a placeholder; we copy the
 * package to a tempdir and rewrite `0xcafe` -> Alice's actual address
 * before publishing. Same trick `tutorial-aptos` uses.
 */

import { spawnSync } from 'child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import * as os from 'os';
import * as path from 'path';

import { Account, Ed25519PrivateKey } from '@aptos-labs/ts-sdk';

import {
    ALICE_FILE, AccountFile, CONFIG_FILE, CONTRACT_DIR, ConfigFile,
    aptosFromConfig, ensureDataDir, log, readAceConfig, readJson, writeJson,
} from './common.js';

async function main() {
    ensureDataDir();

    const cfg = readAceConfig();
    const aliceFile = readJson<AccountFile>(ALICE_FILE);
    const alice = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(aliceFile.privateKeyHex) });
    const adminAddress = alice.accountAddress.toStringLong();

    log(`Deploying capability_access with admin = ${adminAddress}`);

    const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'bearer-capability-'));
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
            '--url', cfg.apiEndpoint,
            '--assume-yes',
            '--skip-fetch-latest-git-deps',
        ], { stdio: 'inherit', encoding: 'utf8' });
        if (result.status !== 0) throw new Error('`aptos move publish` failed');
    } finally {
        rmSync(tmpDir, { recursive: true, force: true });
    }
    log('Module published.');

    const aptos = aptosFromConfig(cfg);
    log('Calling capability_access::init...');
    const txn = await aptos.transaction.build.simple({
        sender: alice.accountAddress,
        data: {
            function: `${adminAddress}::capability_access::init` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [],
        },
    });
    const submitted = await aptos.signAndSubmitTransaction({ signer: alice, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: submitted.hash });
    log('Registry initialized.');

    writeJson(CONFIG_FILE, { appContractAddr: adminAddress } satisfies ConfigFile);
    log(`Saved config to ${CONFIG_FILE}`);
    log('');
    log('Next: pnpm 3-create-capability');
}

main().catch(err => { console.error(err); process.exit(1); });
