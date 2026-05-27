// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Helpers for publishing the 11 ACE Move packages to a chain.
 *
 * Used by `ace deployment new` (initial deploy) and `ace deployment update-contracts`
 * (republish). The functions are independent copies of the logic in
 * `scenarios/common/helpers.ts` — duplicated rather than shared because:
 *   - cli should not depend on scenarios (which is a private test harness).
 *   - the code is small (~80 LOC), mechanical (subprocess + Move.toml regex), and
 *     low-churn (the contract list and dep order are stable).
 */

import { spawn } from 'child_process';
import {
    cpSync,
    existsSync,
    mkdtempSync,
    readFileSync,
    readdirSync,
    rmSync,
    writeFileSync,
} from 'fs';
import * as os from 'os';
import * as path from 'path';

import {
    Account,
    Aptos,
    AptosConfig,
    AuthenticationKey,
    Network,
    createResourceAddress,
} from '@aptos-labs/ts-sdk';

/** `<repo>` — `cli/src` is two levels deep (cli is CommonJS, so `__dirname` is available). */
export const REPO_ROOT = path.resolve(__dirname, '../..');

/** Placeholder address baked into every package's `Move.toml` `[addresses]` section. */
export const ADMIN_PLACEHOLDER_FOR_MOVE_TOML = '0xcafe';

/** Canonical dep order. `vss → dkg → dkr → epoch-change → network` must be preserved. */
export const ACE_CONTRACT_PACKAGES: readonly string[] = [
    'pke',
    'worker_config',
    'group',
    'fiat-shamir-transform',
    'sigma-dlog-eq',
    'vss',
    'dkg',
    'dkr',
    'epoch-change',
    'voting',
    'network',
];

export type ContractsPublishScratch = {
    /** Temp root; delete entire tree when done. */
    tmpRoot:      string;
    /** Copy of `contractsRoot` with `Move.toml` admin placeholder (and optional version) patched. */
    contractsDir: string;
};

function spawnExitZero(cmd: string, args: string[], label: string): Promise<void> {
    return new Promise((resolve, reject) => {
        const child = spawn(cmd, args, { stdio: 'inherit' });
        child.once('error', reject);
        child.once('close', (code, signal) => {
            if (code === 0) resolve();
            else reject(new Error(`${label} exited with code ${code}${signal ? ` (signal ${signal})` : ''}`));
        });
    });
}

function patchMoveTomlAdminPlaceholders(contractsDir: string, adminAddressStr: string): void {
    const ph = ADMIN_PLACEHOLDER_FOR_MOVE_TOML;
    const walk = (dir: string): void => {
        for (const ent of readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, ent.name);
            if (ent.isDirectory()) {
                walk(full);
            } else if (ent.name === 'Move.toml') {
                const text = readFileSync(full, 'utf8');
                if (!text.includes(ph)) continue;
                writeFileSync(full, text.split(ph).join(adminAddressStr), 'utf8');
            }
        }
    };
    walk(contractsDir);
}

/**
 * Rewrite the `version = "..."` line in every `Move.toml` under `contractsDir` to `versionStr`.
 * Non-global anchored regex: only the package-section `version` line is replaced (any future
 * dep-section version lines are left alone).
 */
function patchMoveTomlVersions(contractsDir: string, versionStr: string): void {
    const re = /^(\s*version\s*=\s*)"[^"]*"/m;
    const walk = (dir: string): void => {
        for (const ent of readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, ent.name);
            if (ent.isDirectory()) {
                walk(full);
            } else if (ent.name === 'Move.toml') {
                const text = readFileSync(full, 'utf8');
                if (!re.test(text)) continue;
                writeFileSync(full, text.replace(re, `$1"${versionStr}"`), 'utf8');
            }
        }
    };
    walk(contractsDir);
}

export function prepareContractsPublishScratch(
    contractsRoot: string,
    adminAddressStr: string,
    versionStr?: string,
): ContractsPublishScratch {
    const tmpRoot = mkdtempSync(path.join(os.tmpdir(), 'ace-contracts-'));
    const contractsDir = path.join(tmpRoot, 'publish-root');
    cpSync(contractsRoot, contractsDir, { recursive: true });
    patchMoveTomlAdminPlaceholders(contractsDir, adminAddressStr);
    if (versionStr) patchMoveTomlVersions(contractsDir, versionStr);
    return { tmpRoot, contractsDir };
}

export function rmContractsPublishScratch(scratch: ContractsPublishScratch): void {
    rmSync(scratch.tmpRoot, { recursive: true, force: true });
}

export async function publishMovePackage(
    packageDir: string,
    privateKeyHex: string,
    rpcUrl: string,
    senderAddr?: string,
): Promise<void> {
    const args = [
        'move', 'publish',
        '--package-dir', packageDir,
        '--private-key', `0x${privateKeyHex}`,
        '--url', rpcUrl,
        '--assume-yes',
        '--skip-fetch-latest-git-deps',
    ];
    if (senderAddr) args.push('--sender-account', senderAddr);
    // Print the command with the private key redacted; the real value is still passed
    // to the spawned process via `args`.
    const redactedArgs = args.map((a, i) => (args[i - 1] === '--private-key' ? '<REDACTED>' : a));
    console.log(`  $ aptos ${redactedArgs.join(' ')}`);
    await spawnExitZero('aptos', args, 'aptos move publish');
}

/** Derive the `@ace` resource account address from (admin, seed). Pure function — no chain calls. */
export function deriveAceAddr(adminAddrStr: string, seed: string): string {
    const { AccountAddress } = require('@aptos-labs/ts-sdk') as typeof import('@aptos-labs/ts-sdk');
    return createResourceAddress(AccountAddress.fromString(adminAddrStr), seed).toStringLong();
}

/** Phase A of sealed bootstrap: submit `0x1::resource_account::create_resource_account` with
 *  `optional_auth_key` = admin's auth_key, so admin's SK signs Phase-B publishes as the resource
 *  account. Returns the resource account address. */
export async function createAceResourceAccount(
    admin: Account,
    seed: string,
    rpcUrl: string,
): Promise<string> {
    const aptos = new Aptos(new AptosConfig({ network: Network.CUSTOM, fullnode: rpcUrl }));
    const seedBytes = new Uint8Array(Buffer.from(seed, 'utf8'));
    const adminAuthKey = AuthenticationKey.fromPublicKey({ publicKey: admin.publicKey });
    const txn = await aptos.transaction.build.simple({
        sender: admin.accountAddress,
        data: {
            function: '0x1::resource_account::create_resource_account',
            functionArguments: [seedBytes, adminAuthKey.toUint8Array()],
        },
    });
    const resp = await aptos.signAndSubmitTransaction({ signer: admin, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: resp.hash, options: { checkSuccess: true } });
    return deriveAceAddr(admin.accountAddress.toStringLong(), seed);
}

/** Hex (no `0x`) for an Ed25519-backed `Account`. */
export function ed25519PrivateKeyHex(account: Account): string {
    if (!('privateKey' in account)) {
        throw new Error('Ed25519-backed Account required (e.g. from generate() or fromPrivateKey())');
    }
    const pk = (account as unknown as { privateKey: { toUint8Array(): Uint8Array } }).privateKey;
    return Buffer.from(pk.toUint8Array()).toString('hex');
}

/**
 * Sealed bootstrap (Phase A + B): create the `@ace` resource account, then publish the
 * canonical 11 ACE packages (or any subset) to that resource account.
 *
 * Phase C (`network::start_initial_epoch`) must be invoked separately by the caller to
 * burn admin's signing path and finish the sealing. After Phase C, contract upgrades
 * are only possible via committee voting (`network::new_upgrade_proposal` → `touch`).
 *
 * If `versionStr` is provided, every `Move.toml`'s `version = "..."` line is rewritten
 * before publishing.
 *
 * Returns the resource account address that became `@ace`.
 */
export async function deployContracts(
    adminAccount: Account,
    rpcUrl: string,
    seed: string,
    packageFolders: readonly string[] = ACE_CONTRACT_PACKAGES,
    versionStr?: string,
): Promise<string> {
    const aceAddr     = await createAceResourceAccount(adminAccount, seed, rpcUrl);
    const adminKeyHex = ed25519PrivateKeyHex(adminAccount);
    const scratch     = prepareContractsPublishScratch(path.join(REPO_ROOT, 'contracts'), aceAddr, versionStr);
    try {
        for (const folder of packageFolders) {
            const packageDir = path.join(scratch.contractsDir, folder);
            if (!existsSync(path.join(packageDir, 'Move.toml'))) {
                throw new Error(`missing Move package at ${packageDir}`);
            }
            await publishMovePackage(packageDir, adminKeyHex, rpcUrl, aceAddr);
        }
    } finally {
        rmContractsPublishScratch(scratch);
    }
    return aceAddr;
}
