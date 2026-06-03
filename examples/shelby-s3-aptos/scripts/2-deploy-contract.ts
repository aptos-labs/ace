// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Step 2 - Publish `shelby_s3` and initialize the file registry.
 */

import { spawnSync } from 'child_process';
import { cpSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import * as os from 'os';
import * as path from 'path';
import { Account, Aptos, AptosConfig, Ed25519PrivateKey, Network } from '@aptos-labs/ts-sdk';

import {
    AccountFile, CONFIG_FILE, CONTRACT_DIR, OWNER_FILE, SHELBY_ACE_DEPLOYMENT,
    ensureDataDir, log, readJson, writeJson,
} from './common.js';

async function main() {
    ensureDataDir();

    const ownerFile = readJson<AccountFile>(OWNER_FILE);
    const owner = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(ownerFile.privateKeyHex) });
    const adminAddress = owner.accountAddress.toStringLong();
    const rpcUrl = SHELBY_ACE_DEPLOYMENT.apiEndpoint;

    log(`Deploying shelby_s3 with admin = ${adminAddress}`);

    const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'shelby-s3-aptos-'));
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
            '--private-key', ownerFile.privateKeyHex,
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
    log('Calling shelby_s3::initialize...');
    const txn = await aptos.transaction.build.simple({
        sender: owner.accountAddress,
        data: {
            function: `${adminAddress}::shelby_s3::initialize` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [],
        },
    });
    const submitted = await aptos.signAndSubmitTransaction({ signer: owner, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: submitted.hash });
    log(`Registry initialized (tx: ${submitted.hash}).`);

    writeJson(CONFIG_FILE, { appContractAddr: adminAddress });
    log(`Saved config to ${CONFIG_FILE}`);
    log('');
    log('Next: pnpm 3-upload-and-mint-token');
}

main().catch(err => { console.error(err); process.exit(1); });
