// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `ace deployment new` — full deployment wizard.
 *
 * Flow:
 *   1. Pre-flight: by default, clean tree + release tag at HEAD (strict).
 *   2. Pick a network (mainnet | testnet | devnet | localnet | custom).
 *   3. Generate (or import) the admin keypair.
 *   4. Fund the admin (manual prompt for testnet/mainnet, faucet for dev/local).
 *   5. Optional Geomi inputs (shared-node API key, gas-station API key).
 *   6. Deploy all ACE Move packages at the version from `<repo>/NEXT_RELEASE`.
 *   7. Print operator-onboarding blob; wait for operators to register.
 *   8. Collect committee + threshold + epoch duration; call `network::start_initial_epoch`.
 *   9. Persist the deployment profile to `~/.ace/config.json`.
 *
 * The strict preflight (clean tree + release tag at HEAD) keeps deployments
 * reproducible. For local experiments only, set `ACE_DEPLOYMENT_NEW_SKIP_TAG_CHECK=1`:
 *   • allows a dirty working tree (no warning — opt in knowingly),
 *   • if HEAD has no release tag, reads `NEXT_RELEASE` for the semver in `Move.toml`
 *     and sets `deployedAtTag` to `untagged-<sha>` (those steps still warn).
 */

import * as readline from 'readline';
import { execFileSync } from 'child_process';
import { existsSync, readFileSync } from 'fs';
import * as path from 'path';
import {
    Account,
    AccountAddress,
    Aptos,
    AptosConfig,
    Ed25519PrivateKey,
    Network,
} from '@aptos-labs/ts-sdk';
import { select, input, confirm } from '@inquirer/prompts';
import {
    loadConfig,
    saveConfig,
    makeDeploymentKey,
    type TrackedDeployment,
} from '../config.js';
import {
    ACE_CONTRACT_PACKAGES,
    REPO_ROOT,
    deployContracts,
    ed25519PrivateKeyHex,
} from '../deploy-contracts.js';
import { CLI } from '../cli-name.js';

const NETWORKS: { name: 'mainnet' | 'testnet' | 'devnet' | 'localnet' | 'shelby-private-beta' | 'custom'; rpcUrl?: string; faucet?: string }[] = [
    { name: 'mainnet',  rpcUrl: 'https://api.mainnet.aptoslabs.com/v1' },
    { name: 'testnet',  rpcUrl: 'https://api.testnet.aptoslabs.com/v1' },
    { name: 'devnet',   rpcUrl: 'https://api.devnet.aptoslabs.com/v1',  faucet: 'https://faucet.devnet.aptoslabs.com' },
    { name: 'localnet', rpcUrl: 'http://localhost:8080/v1',              faucet: 'http://localhost:8081' },
    { name: 'shelby-private-beta' },
    { name: 'custom' },
];

// ── Pre-flight ────────────────────────────────────────────────────────────────

function git(args: string[]): string {
    return execFileSync('git', args, { cwd: REPO_ROOT, encoding: 'utf8' }).trim();
}

/** Local-dev escape hatch: relax clean-tree and missing-tag preflights. */
function deploymentNewPreflightRelaxed(): boolean {
    const v = (process.env.ACE_DEPLOYMENT_NEW_SKIP_TAG_CHECK ?? '').toLowerCase();
    return v === '1' || v === 'true' || v === 'yes';
}

/** First X.Y.Z on a non-empty line in repo-root `NEXT_RELEASE`. */
function readNextReleaseVersion(): string {
    const p = path.join(REPO_ROOT, 'NEXT_RELEASE');
    if (!existsSync(p)) {
        throw new Error(
            `Missing ${p} — required when HEAD has no release tag and ACE_DEPLOYMENT_NEW_SKIP_TAG_CHECK is set.`,
        );
    }
    const lines = readFileSync(p, 'utf8').split(/\r?\n/);
    const line = lines.map(l => l.replace(/#.*$/, '').trim()).find(l => l.length > 0);
    if (!line) {
        throw new Error(`${p} has no version line (expected a line like 2.0.1).`);
    }
    const m = line.match(/^(\d+\.\d+\.\d+)/);
    if (!m) {
        throw new Error(`${p} must contain semver X.Y.Z at the start of a line; got: ${line}`);
    }
    return m[1]!;
}

function preflightTagAndCleanCheck(): { tag: string; commit: string; version: string } {
    let status: string;
    try {
        status = git(['status', '--porcelain']);
    } catch (e) {
        throw new Error(`\`git status\` failed — is ${REPO_ROOT} a git repository? (${(e as Error).message})`);
    }
    if (status.length > 0 && !deploymentNewPreflightRelaxed()) {
        throw new Error(
            `Working tree is not clean — \`deployment new\` requires a clean tree at a tagged commit.\n` +
            `Uncommitted/untracked changes:\n${status}\n\n` +
            `Local-only: export ACE_DEPLOYMENT_NEW_SKIP_TAG_CHECK=1 to skip this check (and the tag-at-HEAD rule when untagged).`,
        );
    }

    const commit = git(['rev-parse', 'HEAD']);
    const tagsAtHead = git(['tag', '--points-at', 'HEAD']).split('\n').filter(Boolean);

    if (tagsAtHead.length > 0) {
        // If multiple tags point at HEAD, prefer one that looks like a release version.
        const releaseTag = tagsAtHead.find(t => /^v?\d+\.\d+\.\d+/.test(t)) ?? tagsAtHead[0]!;
        const version = releaseTag.replace(/^v/, '');
        if (!/^\d+\.\d+\.\d+$/.test(version)) {
            throw new Error(
                `Tag at HEAD "${releaseTag}" is not a semver release tag (expected vX.Y.Z, e.g. v2.0.1). ` +
                `Either retag this commit or check out a real release tag and try again.`,
            );
        }
        return { tag: releaseTag, commit, version };
    }

    if (!deploymentNewPreflightRelaxed()) {
        throw new Error(
            `HEAD (${commit.slice(0, 12)}) is not a tagged commit. \`deployment new\` requires the\n` +
            `current commit to carry a release tag — that's how the deployed contracts stay\n` +
            `reproducible (anyone can later \`git checkout <tag>\` and rebuild bit-identical Move\n` +
            `bytecode). Tag the commit and try again, e.g.:\n\n` +
            `    git tag v1.2.3\n` +
            `    git push origin v1.2.3\n\n` +
            `For local-only testing: export ACE_DEPLOYMENT_NEW_SKIP_TAG_CHECK=1\n` +
            `(allows a dirty tree; if HEAD is untagged, version comes from NEXT_RELEASE; deployedAtTag = untagged-<sha>).`,
        );
    }

    const version = readNextReleaseVersion();
    const tag = `untagged-${commit.slice(0, 12)}`;
    console.warn(
        'ACE_DEPLOYMENT_NEW_SKIP_TAG_CHECK: skipping release-tag requirement. ' +
            `Publishing at NEXT_RELEASE version ${version}; profile deployedAtTag = "${tag}".`,
    );
    console.warn('Do not use this for production — create a real release tag for reproducible bytecode.\n');
    return { tag, commit, version };
}

// ── Aptos helpers ─────────────────────────────────────────────────────────────

function inferAptosNetwork(rpcUrl: string): Network {
    const u = rpcUrl.toLowerCase();
    if (u.includes('mainnet')) return Network.MAINNET;
    if (u.includes('testnet')) return Network.TESTNET;
    if (u.includes('devnet')) return Network.DEVNET;
    if (u.includes('localhost') || u.includes('127.0.0.1')) return Network.LOCAL;
    return Network.CUSTOM;
}

function makeAptos(rpcUrl: string, faucet: string | undefined, apiKey: string | undefined): Aptos {
    const headers = apiKey ? { Authorization: `Bearer ${apiKey}` } : undefined;
    return new Aptos(new AptosConfig({
        network: inferAptosNetwork(rpcUrl),
        fullnode: rpcUrl,
        faucet,
        clientConfig: headers ? { HEADERS: headers } : undefined,
    }));
}

async function waitForBalance(aptos: Aptos, addr: string, label: string): Promise<void> {
    const deadline = Date.now() + 30 * 60_000; // 30 min
    while (Date.now() < deadline) {
        try {
            const oct = await aptos.getAccountAPTAmount({ accountAddress: AccountAddress.fromString(addr) });
            if (BigInt(oct) > 0n) return;
        } catch { /* account may not exist yet — keep polling */ }
        process.stdout.write(`.`);
        await new Promise(r => setTimeout(r, 5000));
    }
    throw new Error(`Timed out after 30 min waiting for ${label} ${addr} to be funded. Re-run \`${CLI} deployment new\` once the account has APT.`);
}

async function faucetFund(faucetUrl: string, addr: string, amountOctas: number = 100_000_000_000): Promise<void> {
    const url = `${faucetUrl}/mint?amount=${amountOctas}&address=${addr}`;
    const resp = await fetch(url, { method: 'POST' });
    if (!resp.ok) {
        const body = await resp.text().catch(() => '<no body>');
        throw new Error(`Faucet ${faucetUrl} returned HTTP ${resp.status}. Body: ${body}`);
    }
}

// ── Prompts ───────────────────────────────────────────────────────────────────

async function promptNetwork(): Promise<{ network: typeof NETWORKS[number]['name']; rpcUrl: string; faucet?: string }> {
    const choice = await select({
        message: 'Which network are you deploying to?',
        choices: NETWORKS.map(n => ({ name: n.name, value: n.name })),
    });
    const def = NETWORKS.find(n => n.name === choice)!;
    if (choice !== 'custom' && def.rpcUrl) {
        return { network: choice, rpcUrl: def.rpcUrl!, faucet: def.faucet };
    }
    const rpcUrl = await input({
        message: `${choice === 'custom' ? 'Custom' : choice} fullnode REST API URL (e.g. https://my-aptos-node.example.com/v1):`,
        validate: v => /^https?:\/\//.test(v.trim()) || 'must start with http:// or https://',
    });
    const faucetRaw = await input({
        message: 'Faucet URL (optional — leave blank to fund the admin manually):',
    });
    return { network: choice, rpcUrl: rpcUrl.trim(), faucet: faucetRaw.trim() || undefined };
}

async function promptAdminKey(): Promise<Account> {
    const mode = await select({
        message: 'Admin signing key (controls the contract package — keep this safe):',
        choices: [
            { name: 'Generate a fresh Ed25519 keypair (recommended for new deployments)', value: 'generate' },
            { name: 'Import an existing private key (e.g. for re-deploying to a known address)', value: 'import' },
        ],
    });
    if (mode === 'generate') return Account.generate();
    const keyHex = await input({
        message: 'Admin private key (0x-prefixed, 64 hex chars):',
        validate: v => /^0x[0-9a-fA-F]{64}$/.test(v.trim()) || 'must be 0x followed by exactly 64 hex chars',
    });
    const sk = new Ed25519PrivateKey(keyHex.trim());
    return Account.fromPrivateKey({ privateKey: sk });
}

// ── Main ──────────────────────────────────────────────────────────────────────

export async function deploymentNewCommand(): Promise<void> {
    // 1. Pre-flight.
    const { tag, commit, version } = preflightTagAndCleanCheck();
    const versionNote = tag.startsWith('untagged-')
        ? 'from NEXT_RELEASE — will be stamped into every Move.toml'
        : 'from the tag — will be stamped into every Move.toml';
    console.log(`Repository state:`);
    console.log(`  tag    : ${tag}`);
    console.log(`  commit : ${commit.slice(0, 12)}`);
    console.log(`  version: ${version}  (${versionNote})`);
    console.log();

    // 2. Network.
    const { network, rpcUrl, faucet } = await promptNetwork();

    // 3. Admin key.
    const adminAccount = await promptAdminKey();
    const adminAddr = adminAccount.accountAddress.toStringLong();
    const adminPrivKeyHex = ed25519PrivateKeyHex(adminAccount);
    console.log();
    console.log(`Admin account address: ${adminAddr}`);
    console.log(`(The contract package will be published AT this address; it doubles as the deployment's identity.)`);
    console.log();

    // 4. Fund.
    if (!faucet && network !== 'devnet' && network !== 'localnet') {
        console.log(`This admin account needs APT to publish all ${ACE_CONTRACT_PACKAGES.length} packages.`);
        console.log(`Roughly 5 APT is enough on ${network} (each publish ≈ 0.05 APT in gas).`);
        console.log();
        console.log(`Send funds to:`);
        console.log(`  ${adminAddr}`);
        console.log();
        console.log(`Polling for balance every 5s (Ctrl-C to abort, 30 min timeout)...`);
        await waitForBalance(makeAptos(rpcUrl, undefined, undefined), adminAddr, 'admin');
        console.log();
        console.log('  ✓ Admin balance detected — proceeding.');
        console.log();
    } else if (faucet) {
        console.log(`Auto-funding the admin account via faucet ${faucet} ...`);
        await faucetFund(faucet, adminAddr);
        await waitForBalance(makeAptos(rpcUrl, faucet, undefined), adminAddr, 'admin');
        console.log();
        console.log('  ✓ Admin funded.');
        console.log();
    }

    // 5. Deploy contracts.
    // We optionally accept NODE_API_KEY from the caller's environment to skip rate-limit
    // throttling during the publish step. Geomi inputs (sharedNodeApiKey, gasStationApiKey)
    // are collected AFTER deploy — those are operator-onboarding concerns and asking for
    // them up-front is annoying when the user just wants to see the contracts land first.
    console.log(`Deploying ${ACE_CONTRACT_PACKAGES.length} packages at version ${version} (~2-3 minutes)...`);
    console.log();
    if (process.env.NODE_API_KEY) {
        console.log(`(NODE_API_KEY found in environment — using it as Bearer auth for the publish step's RPC calls.)`);
        console.log();
    } else if (network === 'mainnet' || network === 'testnet') {
        console.log(`(No NODE_API_KEY in environment. Publishes will use unauthenticated RPC — works on ${network}`);
        console.log(` but slower and rate-limited. To speed up: Ctrl-C now, \`export NODE_API_KEY=aptoslabs_...\`, and re-run.)`);
        console.log();
    }
    await deployContracts(adminAccount, rpcUrl, ACE_CONTRACT_PACKAGES, version);
    console.log();
    console.log(`  ✓ All ${ACE_CONTRACT_PACKAGES.length} packages published at version ${version}.`);
    console.log();

    // 6. Geomi inputs (optional, for operator onboarding).
    console.log('══════════════════════════════════════════════════════════════════════');
    console.log('  Optional: Geomi node infrastructure (recommended for testnet/mainnet)');
    console.log();
    console.log('  Geomi (https://geomi.dev) provides managed Aptos full nodes and');
    console.log('  gas stations for committee operators. Both are optional — the network');
    console.log('  works without them, but operators will need their own RPC and APT.');
    console.log();
    console.log('  To set up Geomi-backed infrastructure for this deployment:');
    console.log('    1. Open https://geomi.dev in another tab and sign in.');
    console.log(`    2. Create a "Shared Node API Key" for ${network} (operators share`);
    console.log('       one full-node endpoint via this key).');
    console.log(`    3. Create a "Gas Station" for ${network} (operator txns get`);
    console.log('       sponsored — operators do not need to hold APT).');
    console.log('    4. Paste the keys below.');
    console.log();
    console.log('  Press Enter at either prompt to skip.');
    console.log('══════════════════════════════════════════════════════════════════════');
    console.log();
    const sharedNodeApiKey = (await input({ message: 'Shared Node API Key (aptoslabs_…):' })).trim() || undefined;
    const gasStationApiKey = (await input({ message: 'Gas Station API Key (aptoslabs_…):' })).trim() || undefined;

    // 7. Operator onboarding blob.
    const operatorBlob = JSON.stringify(
        Object.assign({ rpcUrl, aceAddr: adminAddr },
            sharedNodeApiKey ? { rpcApiKey: sharedNodeApiKey } : {},
            gasStationApiKey ? { gasStationKey: gasStationApiKey } : {},
        ),
    );
    console.log();
    console.log('══════════════════════════════════════════════════════════════════════');
    console.log('  Operator onboarding blob');
    console.log();
    console.log('  Share the JSON line below with each operator (e.g. via Slack DM, 1Password');
    console.log('  shared item, or wherever your team treats credentials). Each operator runs');
    console.log(`  \`${CLI} node new\`, pastes the blob when prompted, and follows the wizard to`);
    console.log('  start their node and register on-chain.');
    console.log();
    console.log(`  ${operatorBlob}`);
    console.log('══════════════════════════════════════════════════════════════════════');
    console.log();

    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    const ask = (q: string): Promise<string> => new Promise(r => rl.question(q, r));

    console.log(`When operators run \`${CLI} node new\`, they will print their account address at`);
    console.log('the end. Collect those addresses to assemble the initial committee.');
    console.log();
    await ask('Press Enter once all operators have registered and shared their account addresses... ');
    console.log();

    // 8. Initial epoch.
    console.log('Initial committee — paste each operator\'s account address (the long 0x… one).');
    const rawAddrs = await ask('Committee addresses (space-separated, e.g. "0xabc... 0xdef..."): ');
    const nodeAddresses = rawAddrs.trim().split(/\s+/).filter(Boolean).map(s => AccountAddress.fromString(s));
    if (nodeAddresses.length === 0) { rl.close(); throw new Error('No committee addresses provided.'); }
    if (nodeAddresses.length < 3) {
        console.log(`  ⚠ Only ${nodeAddresses.length} address(es) — committee should be ≥ 3 for any meaningful threshold.`);
    }
    console.log();

    console.log(`Threshold — minimum honest workers needed to derive. Constraints:`);
    console.log(`  2 ≤ t ≤ ${nodeAddresses.length}    (at least 2)`);
    console.log(`  2·t > ${nodeAddresses.length}      (strict majority — Byzantine fault tolerance)`);
    console.log(`  Common choices for n=${nodeAddresses.length}: t=${Math.floor(nodeAddresses.length / 2) + 1} (smallest valid).`);
    const rawT = await ask('Threshold: ');
    const threshold = parseInt(rawT.trim(), 10);
    if (isNaN(threshold) || threshold < 2 || threshold > nodeAddresses.length || 2 * threshold <= nodeAddresses.length) {
        rl.close();
        throw new Error(`Invalid threshold "${rawT}" — must be an integer satisfying 2 ≤ t ≤ ${nodeAddresses.length} and 2·t > ${nodeAddresses.length}.`);
    }
    console.log();

    console.log(`Epoch duration — how often the network auto-rotates secret shares.`);
    console.log(`  Minimum: 30 seconds (the protocol's hardcoded floor).`);
    console.log(`  Typical: 3600 (1 hour) for testnet/devnet, 86400 (24 hours) for mainnet.`);
    console.log(`  Shorter = more rotations = more on-chain gas; longer = secrets stay with the same committee longer.`);
    const rawDur = await ask('Epoch duration in seconds: ');
    const epochDuration = parseInt(rawDur.trim(), 10);
    if (isNaN(epochDuration) || epochDuration < 30) {
        rl.close();
        throw new Error(`Invalid epoch duration "${rawDur}" — must be an integer ≥ 30.`);
    }
    rl.close();
    console.log();

    console.log(`Calling network::start_initial_epoch(nodes=${nodeAddresses.length}, threshold=${threshold}, epoch_duration=${epochDuration}s)...`);
    const aptos = makeAptos(rpcUrl, faucet, sharedNodeApiKey);
    const txn = await aptos.transaction.build.simple({
        sender: adminAccount.accountAddress,
        data: {
            function: `${adminAddr}::network::start_initial_epoch` as `${string}::${string}::${string}`,
            functionArguments: [
                nodeAddresses.map(a => a.toStringLong()),
                threshold,
                epochDuration,
            ],
        },
    });
    const resp = await aptos.signAndSubmitTransaction({ signer: adminAccount, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: resp.hash, options: { checkSuccess: true } });
    console.log(`  ✓ Initial epoch (epoch 0) live. Txn: ${resp.hash}`);
    console.log();

    // 9. Persist profile.
    const config = loadConfig();
    const key = makeDeploymentKey(rpcUrl, adminAddr);
    const dep: TrackedDeployment = {
        rpcUrl,
        aceAddr: adminAddr,
        adminAddress: adminAddr,
        adminPrivateKey: `0x${adminPrivKeyHex}`,
        sharedNodeApiKey,
        gasStationApiKey,
        alias: `${network}-${tag}`,
        network,
        deployedAtTag: tag,
        deployedAtCommit: commit,
        deployedAt: new Date().toISOString(),
    };
    config.deployments[key] = dep;
    if (!config.defaultDeployment) {
        config.defaultDeployment = key;
    } else if (config.defaultDeployment !== key) {
        const currentDefault = config.deployments[config.defaultDeployment];
        const currentLabel = currentDefault?.alias ?? config.defaultDeployment;
        const setDefault = await confirm({
            message: `Set "${dep.alias}" as the default deployment? (current default: ${currentLabel})`,
            default: false,
        });
        if (setDefault) config.defaultDeployment = key;
    }
    saveConfig(config);

    console.log('══════════════════════════════════════════════════════════════════════');
    console.log('  Deployment complete.');
    console.log();
    console.log(`  Profile alias     : ${dep.alias}`);
    console.log(`  Contract address  : ${adminAddr}`);
    console.log(`  Tag / version     : ${tag} / v${version}`);
    console.log(`  Network           : ${network}`);
    console.log(`  Saved profile     : ~/.ace/config.json (entry "${makeDeploymentKey(rpcUrl, adminAddr)}")`);
    console.log();
    console.log('  Admin private key is stored in the profile. Keep ~/.ace/config.json safe — anyone');
    console.log('  with read access can recover the admin signing key and thus control the contract.');
    console.log();
    const pad = (s: string, w: number) => s + ' '.repeat(Math.max(0, w - s.length));
    const nextW = Math.max(`${CLI} network-status -w`.length, `${CLI} deployment update-contracts`.length) + 2;
    console.log('  Next steps:');
    console.log(`    ${pad(`${CLI} network-status -w`, nextW)}# live monitor the running network`);
    console.log(`    ${pad(`${CLI} deployment ls`, nextW)}# list saved deployment profiles`);
    console.log(`    ${pad(`${CLI} deployment update-contracts`, nextW)}# republish at a new tag (e.g. after a hotfix)`);
    console.log('══════════════════════════════════════════════════════════════════════');
}
