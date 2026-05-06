// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `ace deployment update-contracts` — republish all 11 ACE Move packages under the
 * resolved deployment profile.
 *
 * Default version comes from `<repo>/NEXT_RELEASE`. Override with `--version X.Y.Z`.
 * If the profile has a `sharedNodeApiKey`, it's exported as `NODE_API_KEY` so each
 * `aptos move publish` uses `Authorization: Bearer <key>` (avoids unauth rate limits).
 *
 * Like every admin operation, requires that you've already created the deployment
 * profile via `ace deployment new`. The profile holds the admin private key.
 */

import { confirm } from '@inquirer/prompts';
import { readFileSync } from 'fs';
import { join } from 'path';
import { Account, Ed25519PrivateKey } from '@aptos-labs/ts-sdk';

import { deriveRpcLabel, loadConfig, saveConfig } from '../config.js';
import { resolveDeployment } from '../resolve-profile.js';
import { ACE_CONTRACT_PACKAGES, REPO_ROOT, deployContracts } from '../deploy-contracts.js';

function readNextReleaseVersion(): string {
    return readFileSync(join(REPO_ROOT, 'NEXT_RELEASE'), 'utf8').trim();
}

export async function updateContractsCommand(opts: {
    profile?: string;
    account?: string;
    version?: string;
    yes?: boolean;
}): Promise<void> {
    const { deploymentKey, deployment } = resolveDeployment(opts.profile, opts.account);

    const version = opts.version ?? readNextReleaseVersion();
    if (!/^\d+\.\d+\.\d+$/.test(version)) {
        throw new Error(`version "${version}" is not in X.Y.Z form`);
    }

    if (deployment.sharedNodeApiKey) {
        process.env.NODE_API_KEY = deployment.sharedNodeApiKey;
    }

    const sk = new Ed25519PrivateKey(deployment.adminPrivateKey);
    const adminAccount = Account.fromPrivateKey({ privateKey: sk });
    const adminAddr = adminAccount.accountAddress.toStringLong();

    if (deployment.adminAddress.toLowerCase() !== adminAddr.toLowerCase()) {
        throw new Error(
            `Profile inconsistency: stored adminAddress (${deployment.adminAddress}) ` +
            `does not match the address derived from adminPrivateKey (${adminAddr}).`,
        );
    }

    console.log();
    console.log('Republishing ACE contracts:');
    console.log(`  profile : ${deployment.alias ?? deploymentKey}`);
    console.log(`  network : ${deployment.network ?? deriveRpcLabel(deployment.rpcUrl)}`);
    console.log(`  rpcUrl  : ${deployment.rpcUrl}`);
    console.log(`  admin   : ${adminAddr}`);
    console.log(`  api key : ${deployment.sharedNodeApiKey ? 'present (NODE_API_KEY set)' : 'none'}`);
    console.log(`  version : ${version}${opts.version ? ' (--version override)' : ' (from NEXT_RELEASE)'}`);
    console.log(`  packages: ${ACE_CONTRACT_PACKAGES.join(', ')}`);
    console.log();

    if (!opts.yes) {
        const ok = await confirm({ message: 'Proceed?', default: false });
        if (!ok) { console.log('Aborted.'); return; }
    }

    await deployContracts(adminAccount, deployment.rpcUrl, ACE_CONTRACT_PACKAGES, version);

    // Persist the published version into the profile so `deployment ls` shows it.
    const config = loadConfig();
    const dep = config.deployments[deploymentKey];
    if (dep) {
        dep.deployedAt = new Date().toISOString();
        dep.deployedAtTag = `v${version}`;
        saveConfig(config);
    }

    console.log();
    console.log(`✓ All ${ACE_CONTRACT_PACKAGES.length} packages republished at version ${version}.`);
}
