// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `ace deployment update-contracts` — republish all 11 ACE Move packages under the
 * resolved deployment profile.
 *
 * Version selection (in order):
 *   1. `--version X.Y.Z` if passed
 *   2. The vX.Y.Z tag at HEAD (stripped of leading `v`)
 *   3. Otherwise: error. (NEXT_RELEASE is NOT used — at a release-tagged commit it has
 *      already been bumped past the current tag, so reading it stamps the wrong version.)
 *
 * If the profile has a `sharedNodeApiKey`, it's exported as `NODE_API_KEY` so each
 * `aptos move publish` uses `Authorization: Bearer <key>` (avoids unauth rate limits).
 *
 * Like every admin operation, requires that you've already created the deployment
 * profile via `ace deployment new`. The profile holds the admin private key.
 */

import { confirm } from '@inquirer/prompts';
import { execFileSync } from 'child_process';
import { Account, Ed25519PrivateKey } from '@aptos-labs/ts-sdk';

import { deriveRpcLabel, loadConfig, saveConfig } from '../config.js';
import { resolveDeployment } from '../resolve-profile.js';
import { CLI } from '../cli-name.js';
import { ACE_CONTRACT_PACKAGES, REPO_ROOT, deployContracts } from '../deploy-contracts.js';

/** Return the first vX.Y.Z tag pointing at HEAD, or null if none. */
function semverTagAtHead(): string | null {
    let raw: string;
    try {
        raw = execFileSync('git', ['tag', '--points-at', 'HEAD'], { cwd: REPO_ROOT, encoding: 'utf8' }).trim();
    } catch {
        return null;
    }
    const tags = raw.split('\n').filter(Boolean);
    return tags.find(t => /^v?\d+\.\d+\.\d+$/.test(t)) ?? null;
}

export async function updateContractsCommand(opts: {
    profile?: string;
    account?: string;
    version?: string;
    yes?: boolean;
}): Promise<void> {
    const { deploymentKey, deployment } = resolveDeployment(opts.profile, opts.account);

    // Version selection: --version overrides; otherwise read from the git tag at HEAD.
    // NEXT_RELEASE is intentionally NOT used as a fallback — at any release-tagged commit
    // NEXT_RELEASE has already been bumped past the current tag (per the release flow:
    // bump NEXT_RELEASE in the same commit you tag), so reading it stamps the WRONG version.
    let version: string;
    let versionSource: string;
    if (opts.version) {
        version = opts.version.replace(/^v/, '');
        versionSource = '--version override';
    } else {
        const tag = semverTagAtHead();
        if (!tag) {
            throw new Error(
                `Cannot determine a version: HEAD is not at a vX.Y.Z tag, and no --version was given.\n` +
                `Either:\n` +
                `  • check out a release tag (e.g. \`git checkout v2.0.1\`), or\n` +
                `  • pass --version X.Y.Z explicitly (you'll be stamping that into every Move.toml).\n`,
            );
        }
        version = tag.replace(/^v/, '');
        versionSource = `git tag at HEAD: ${tag}`;
    }
    if (!/^\d+\.\d+\.\d+$/.test(version)) {
        throw new Error(`Resolved version "${version}" is not in X.Y.Z form.`);
    }

    if (deployment.sharedNodeApiKey) {
        // Threaded through to `aptos move publish` so RPC calls authenticate via Bearer token
        // and avoid testnet/mainnet rate limits during the 11-package republish.
        process.env.NODE_API_KEY = deployment.sharedNodeApiKey;
    }

    const sk = new Ed25519PrivateKey(deployment.adminPrivateKey);
    const adminAccount = Account.fromPrivateKey({ privateKey: sk });
    const adminAddr = adminAccount.accountAddress.toStringLong();

    if (deployment.adminAddress.toLowerCase() !== adminAddr.toLowerCase()) {
        throw new Error(
            `Profile inconsistency: stored adminAddress (${deployment.adminAddress}) does ` +
            `not match the address derived from the stored adminPrivateKey (${adminAddr}). ` +
            `Refusing to republish — fix the profile via \`${CLI} deployment edit\` or recreate it.`,
        );
    }

    console.log();
    console.log('Republishing ACE contracts:');
    console.log(`  profile     : ${deployment.alias ?? deploymentKey}`);
    console.log(`  network     : ${deployment.network ?? deriveRpcLabel(deployment.rpcUrl)}`);
    console.log(`  rpcUrl      : ${deployment.rpcUrl}`);
    console.log(`  admin addr  : ${adminAddr}`);
    console.log(`  rpc auth    : ${deployment.sharedNodeApiKey ? 'Shared Node API Key from profile (Bearer token)' : 'none — using unauthenticated RPC (may rate-limit)'}`);
    console.log(`  version     : ${version}  (${versionSource})`);
    console.log(`  packages    : all ${ACE_CONTRACT_PACKAGES.length} (${ACE_CONTRACT_PACKAGES.join(', ')})`);
    console.log();
    console.log(`This will run \`aptos move publish\` ${ACE_CONTRACT_PACKAGES.length} times in dependency order. Each publish is`);
    console.log(`an on-chain transaction signed with the admin key. Estimated total: ~2-3 minutes`);
    console.log(`+ ~0.5 APT in gas (real values vary by network and bytecode size).`);
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
    console.log(`  Profile updated: deployedAtTag = v${version}, deployedAt = now.`);
    console.log(`  Confirm via \`${CLI} network-status\` — the contract version line should reflect v${version}.`);
}
