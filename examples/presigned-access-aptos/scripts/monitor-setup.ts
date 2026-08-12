// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `pnpm monitor:setup` — one-time, interactive pre-flight you run by hand
 * before pointing a monitor at a deployment. It does everything that costs gas
 * or needs a human (funding, publishing, registering); `monitor:run` is then a
 * pure read-only probe.
 *
 * Steps (each idempotent):
 *   1. Resolve Alice — from `ALICE_PRIVATE_KEY_HEX`, else `data/alice.json`,
 *      else freshly generated. Her key is printed at the end for you to store
 *      in Secret Manager; `monitor:run` must load the SAME Alice.
 *   2. Fund Alice — localnet auto-funds; otherwise print her address and wait
 *      for you to fund via whatever faucet the target network uses.
 *   3. Resolve the `presigned_access` app contract — from `APP_CONTRACT_ADDR`
 *      / `data/config.json`, else publish it under Alice + call `init`.
 *   4. Derive the deterministic `accessPublicKey` via threshold VRF and
 *      `register` it on-chain for `BLOB_SUFFIX`.
 *
 * Finally it prints the exact env block `monitor:run` needs.
 */

import { spawnSync } from 'child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'fs';
import * as os from 'os';
import * as path from 'path';

import {
    Account, AccountAddress, Ed25519PrivateKey, PrivateKey, PrivateKeyVariants,
} from '@aptos-labs/ts-sdk';
import { bytesToHex } from '@noble/hashes/utils';

import {
    ALICE_FILE, AccountFile, CONFIG_FILE, CONTRACT_DIR, ConfigFile,
    DEFAULT_BLOB_SUFFIX, DEFAULT_PLAINTEXT,
    aceDeploymentFromConfig, aptosFromConfig, buildBlobId, deriveAccessKeypair,
    ensureDataDir, fundViaLocalnetFaucet, log, readAceConfig, readJson, waitForEnter, writeJson,
} from './common.js';

const REQUIRED_OCTAS = 200_000_000; // 2 APT — deploy + register headroom
const POLL_INTERVAL_MS = 3_000;
const POLL_TIMEOUT_MS = 120_000;

function loadAlice(): { alice: Account; privateKeyHex: string; source: string } {
    const envKey = process.env.ALICE_PRIVATE_KEY_HEX?.trim();
    if (envKey) {
        const formatted = PrivateKey.formatPrivateKey(envKey, PrivateKeyVariants.Ed25519);
        const alice = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(formatted) });
        return { alice, privateKeyHex: envKey, source: 'ALICE_PRIVATE_KEY_HEX' };
    }
    if (existsSync(ALICE_FILE)) {
        const f = readJson<AccountFile>(ALICE_FILE);
        const alice = Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(f.privateKeyHex) });
        return { alice, privateKeyHex: f.privateKeyHex, source: ALICE_FILE };
    }
    const alice = Account.generate();
    const privateKeyHex = '0x' + Buffer.from((alice as unknown as { privateKey: { toUint8Array(): Uint8Array } }).privateKey.toUint8Array()).toString('hex');
    writeJson(ALICE_FILE, { address: alice.accountAddress.toStringLong(), privateKeyHex } satisfies AccountFile);
    return { alice, privateKeyHex, source: `generated (wrote ${ALICE_FILE})` };
}

async function balanceOctas(aptos: ReturnType<typeof aptosFromConfig>, alice: Account): Promise<number> {
    try {
        return await aptos.getAccountAPTAmount({ accountAddress: alice.accountAddress });
    } catch {
        return 0;
    }
}

async function ensureFunded(cfg: ReturnType<typeof readAceConfig>, alice: Account): Promise<void> {
    const aptos = aptosFromConfig(cfg);
    if (await balanceOctas(aptos, alice) >= REQUIRED_OCTAS) {
        log(`Alice already funded (>= ${REQUIRED_OCTAS / 1e8} APT)`);
        return;
    }
    if (cfg.network === 'localnet') {
        log(`Funding Alice from the localnet faucet...`);
        await fundViaLocalnetFaucet(alice.accountAddress, REQUIRED_OCTAS);
        return;
    }
    console.log('\n' + '='.repeat(72));
    console.log(`FUND ALICE (need >= ${REQUIRED_OCTAS / 1e8} APT) — network: ${cfg.apiEndpoint}`);
    console.log('  Address: ' + alice.accountAddress.toStringLong());
    console.log('='.repeat(72) + '\n');
    await waitForEnter('Press Enter once Alice has been funded... ');

    const start = Date.now();
    for (;;) {
        const bal = await balanceOctas(aptos, alice);
        if (bal >= REQUIRED_OCTAS) { log(`Alice funded (${bal / 1e8} APT)`); return; }
        if (Date.now() - start >= POLL_TIMEOUT_MS) {
            throw new Error(`Alice has ${bal / 1e8} APT after ${POLL_TIMEOUT_MS / 1000}s (need >= ${REQUIRED_OCTAS / 1e8}). Re-run once funding lands.`);
        }
        log(`  ${bal / 1e8} APT — waiting...`);
        await new Promise(r => setTimeout(r, POLL_INTERVAL_MS));
    }
}

function deployContract(cfg: ReturnType<typeof readAceConfig>, aliceFilePrivateKeyHex: string, adminAddress: string): void {
    log(`Publishing presigned_access with admin = ${adminAddress}`);
    const tmpDir = mkdtempSync(path.join(os.tmpdir(), 'presigned-access-'));
    const tmpContract = path.join(tmpDir, 'contract');
    cpSync(CONTRACT_DIR, tmpContract, { recursive: true });
    const moveTomlPath = path.join(tmpContract, 'Move.toml');
    writeFileSync(moveTomlPath, readFileSync(moveTomlPath, 'utf8').replaceAll('0xcafe', adminAddress));
    try {
        const result = spawnSync('aptos', [
            'move', 'publish',
            '--package-dir', tmpContract,
            '--private-key', aliceFilePrivateKeyHex,
            '--url', cfg.apiEndpoint,
            '--assume-yes', '--skip-fetch-latest-git-deps',
        ], { stdio: 'inherit', encoding: 'utf8' });
        if (result.status !== 0) throw new Error('`aptos move publish` failed');
    } finally {
        rmSync(tmpDir, { recursive: true, force: true });
    }
}

async function resolveAppContract(
    cfg: ReturnType<typeof readAceConfig>, alice: Account, alicePrivateKeyHex: string, moduleName: string,
): Promise<string> {
    const fromEnv = process.env.APP_CONTRACT_ADDR?.trim();
    if (fromEnv) { log(`Reusing app contract from APP_CONTRACT_ADDR = ${fromEnv}`); return fromEnv; }
    if (existsSync(CONFIG_FILE)) {
        const conf = readJson<ConfigFile>(CONFIG_FILE);
        log(`Reusing app contract from ${CONFIG_FILE} = ${conf.appContractAddr}`);
        return conf.appContractAddr;
    }

    const adminAddress = alice.accountAddress.toStringLong();
    deployContract(cfg, alicePrivateKeyHex, adminAddress);

    const aptos = aptosFromConfig(cfg);
    log(`Calling ${moduleName}::init...`);
    const txn = await aptos.transaction.build.simple({
        sender: alice.accountAddress,
        data: {
            function: `${adminAddress}::${moduleName}::init` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [],
        },
    });
    const submitted = await aptos.signAndSubmitTransaction({ signer: alice, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: submitted.hash });
    writeJson(CONFIG_FILE, { appContractAddr: adminAddress } satisfies ConfigFile);
    log(`Published + initialized; saved ${CONFIG_FILE}`);
    return adminAddress;
}

async function main(): Promise<void> {
    ensureDataDir();
    const cfg = readAceConfig();
    const moduleName = process.env.APP_MODULE_NAME?.trim() || 'presigned_access';
    const appOrigin = process.env.APP_ORIGIN?.trim() || 'https://example.com';
    const blobSuffix = process.env.BLOB_SUFFIX?.trim() || DEFAULT_BLOB_SUFFIX;
    const expectedPlaintext = process.env.EXPECTED_PLAINTEXT ?? DEFAULT_PLAINTEXT;

    const { alice, privateKeyHex, source } = loadAlice();
    log(`Alice = ${alice.accountAddress.toStringLong()} (${source})`);

    await ensureFunded(cfg, alice);
    const appContractAddr = await resolveAppContract(cfg, alice, privateKeyHex, moduleName);

    const aptos = aptosFromConfig(cfg);
    const aceDeployment = aceDeploymentFromConfig(cfg);
    const chainId = await aptos.getChainId();
    const moduleAddr = AccountAddress.fromString(appContractAddr);

    log('Deriving accessPublicKey via threshold VRF...');
    const { accessPublicKey } = await deriveAccessKeypair({
        aceDeployment, vrfKeypairId: AccountAddress.fromString(cfg.vrfKeypairId),
        chainId, moduleAddr, moduleName, blobSuffix, appOrigin, alice,
    });
    log(`  accessPublicKey = 0x${bytesToHex(accessPublicKey)}`);

    log(`Registering accessPublicKey for "${blobSuffix}"...`);
    const registerTxn = await aptos.transaction.build.simple({
        sender: alice.accountAddress,
        data: {
            function: `${appContractAddr}::${moduleName}::register` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [blobSuffix, accessPublicKey],
        },
    });
    const submitted = await aptos.signAndSubmitTransaction({ signer: alice, transaction: registerTxn });
    await aptos.waitForTransaction({ transactionHash: submitted.hash });
    log('Registered.');

    const blobId = buildBlobId(alice.accountAddress.toStringLong(), blobSuffix);
    log(`Setup complete for blob "${blobId}".`);

    console.log('\n' + '='.repeat(72));
    console.log('monitor:run env — set these on the Cloud Run job');
    console.log('='.repeat(72));
    console.log(`ACE_API_ENDPOINT=${cfg.apiEndpoint}`);
    console.log(`ACE_CONTRACT=${cfg.contractAddr}`);
    console.log(`IBE_KEYPAIR_ID=${cfg.ibeKeypairId}`);
    console.log(`VRF_KEYPAIR_ID=${cfg.vrfKeypairId}`);
    console.log(`APP_CONTRACT_ADDR=${appContractAddr}`);
    console.log(`APP_MODULE_NAME=${moduleName}`);
    console.log(`APP_ORIGIN=${appOrigin}`);
    console.log(`BLOB_SUFFIX=${blobSuffix}`);
    console.log(`EXPECTED_PLAINTEXT=${JSON.stringify(expectedPlaintext)}`);
    console.log('# store this in Secret Manager, mount as ALICE_PRIVATE_KEY_HEX:');
    console.log(`ALICE_PRIVATE_KEY_HEX=${privateKeyHex}`);
    console.log('='.repeat(72));
    console.log('Verify now with:  ALICE_PRIVATE_KEY_HEX=… APP_CONTRACT_ADDR=… pnpm monitor:run');
}

main().catch(err => { console.error(err); process.exit(1); });
