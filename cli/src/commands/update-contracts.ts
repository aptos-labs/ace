// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `ace deployment update-contracts` — propose Move-package upgrades through the
 * committee-controlled voting flow.
 *
 * The old behavior (`aptos move publish` 11 times signed by the admin key) no longer
 * works after the sealed-bootstrap migration: the admin's key cannot sign for `@ace`.
 * The new flow is:
 *
 *   1. For each package, compile + serialize a `code::publish_package_txn` payload via
 *      `aptos move build-publish-payload --json-output-file <pkg>.json`.
 *   2. Read each payload JSON; extract the `metadata` blob (args[0]) and `code` chunks
 *      (args[1]).
 *   3. Submit `network::new_upgrade_proposal(package_name, metadata, code, description,
 *      target_epoch)` as the admin EOA — admin still occupies a non-voting "proposer"
 *      slot per the sealing design.
 *   4. Print the voting-session address for each proposal. Committee members vote via
 *      `ace vote <session_addr>`. Once threshold is reached, `network::touch()`
 *      (worker `network-node` runs this periodically) executes the publish.
 */

import { confirm } from '@inquirer/prompts';
import { execFileSync } from 'child_process';
import { readFileSync, mkdtempSync, rmSync } from 'fs';
import * as os from 'os';
import * as path from 'path';

import {
    Account,
    AccountAddress,
    Aptos,
    AptosConfig,
    Ed25519PrivateKey,
    MoveVector,
    Network,
} from '@aptos-labs/ts-sdk';

import { deriveRpcLabel, loadConfig, saveConfig } from '../config.js';
import { resolveDeployment } from '../resolve-profile.js';
import { CLI } from '../cli-name.js';
import {
    ACE_CONTRACT_PACKAGES,
    REPO_ROOT,
    prepareContractsPublishScratch,
    rmContractsPublishScratch,
} from '../deploy-contracts.js';

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

function buildPublishPayload(packageDir: string, jsonOut: string): void {
    execFileSync('aptos', [
        'move', 'build-publish-payload',
        '--package-dir', packageDir,
        '--json-output-file', jsonOut,
        '--assume-yes',
        '--skip-fetch-latest-git-deps',
    ], { stdio: 'inherit' });
}

interface PublishPayload {
    metadata: Uint8Array;
    code: Uint8Array[];
}

/** The `aptos move build-publish-payload` JSON shape: a single entry function call with
 *  args[0] = metadata bytes (hex) and args[1] = code chunks (array of hex). */
function readPublishPayload(jsonPath: string): PublishPayload {
    const raw = JSON.parse(readFileSync(jsonPath, 'utf8')) as {
        args: { type: string; value: string | string[] }[];
    };
    if (!raw.args || raw.args.length < 2) {
        throw new Error(`Malformed publish payload at ${jsonPath} — expected args[0]=metadata, args[1]=code`);
    }
    const hexToBytes = (hex: string): Uint8Array => {
        const stripped = hex.startsWith('0x') ? hex.slice(2) : hex;
        return new Uint8Array(Buffer.from(stripped, 'hex'));
    };
    const metadataRaw = raw.args[0]!.value;
    if (typeof metadataRaw !== 'string') throw new Error(`args[0] must be a hex string, got ${typeof metadataRaw}`);
    const codeRaw = raw.args[1]!.value;
    if (!Array.isArray(codeRaw)) throw new Error(`args[1] must be an array of hex strings, got ${typeof codeRaw}`);
    return {
        metadata: hexToBytes(metadataRaw),
        code: codeRaw.map(hexToBytes),
    };
}

async function fetchCurrentEpoch(aptos: Aptos, aceAddr: string): Promise<bigint> {
    const result = await aptos.view<[string]>({
        payload: {
            function: `${aceAddr}::network::current_epoch` as `${string}::${string}::${string}`,
            functionArguments: [],
        },
    });
    return BigInt(result[0]);
}

async function submitUpgradeProposal(args: {
    aptos: Aptos;
    admin: Account;
    aceAddr: string;
    packageName: string;
    payload: PublishPayload;
    description: string;
    targetEpoch: bigint;
}): Promise<string> {
    const { aptos, admin, aceAddr, packageName, payload, description, targetEpoch } = args;
    const txn = await aptos.transaction.build.simple({
        sender: admin.accountAddress,
        data: {
            function: `${aceAddr}::network::new_upgrade_proposal` as `${string}::${string}::${string}`,
            functionArguments: [
                packageName,
                payload.metadata,
                new MoveVector(payload.code.map(c => MoveVector.U8(c))),
                description,
                targetEpoch,
            ],
        },
    });
    const resp = await aptos.signAndSubmitTransaction({ signer: admin, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: resp.hash, options: { checkSuccess: true } });
    return resp.hash;
}

export async function updateContractsCommand(opts: {
    profile?: string;
    account?: string;
    version?: string;
    yes?: boolean;
}): Promise<void> {
    const { deploymentKey, deployment } = resolveDeployment(opts.profile, opts.account);

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
                `  • pass --version X.Y.Z explicitly.\n`,
            );
        }
        version = tag.replace(/^v/, '');
        versionSource = `git tag at HEAD: ${tag}`;
    }
    if (!/^\d+\.\d+\.\d+$/.test(version)) {
        throw new Error(`Resolved version "${version}" is not in X.Y.Z form.`);
    }

    const sk = new Ed25519PrivateKey(deployment.adminPrivateKey);
    const adminAccount = Account.fromPrivateKey({ privateKey: sk });
    const adminAddr = adminAccount.accountAddress.toStringLong();
    if (deployment.adminAddress.toLowerCase() !== adminAddr.toLowerCase()) {
        throw new Error(
            `Profile inconsistency: stored adminAddress (${deployment.adminAddress}) does ` +
            `not match the address derived from the stored adminPrivateKey (${adminAddr}). ` +
            `Refusing to propose — fix the profile via \`${CLI} deployment edit\`.`,
        );
    }

    console.log();
    console.log('Submitting committee-voting upgrade proposals for ACE contracts:');
    console.log(`  profile     : ${deployment.alias ?? deploymentKey}`);
    console.log(`  network     : ${deployment.network ?? deriveRpcLabel(deployment.rpcUrl)}`);
    console.log(`  rpcUrl      : ${deployment.rpcUrl}`);
    console.log(`  ace addr    : ${deployment.aceAddr}`);
    console.log(`  admin addr  : ${adminAddr}  (non-voting proposer slot)`);
    console.log(`  version     : ${version}  (${versionSource})`);
    console.log(`  packages    : all ${ACE_CONTRACT_PACKAGES.length}`);
    console.log();
    console.log(`This will submit ${ACE_CONTRACT_PACKAGES.length} \`network::new_upgrade_proposal\` txns. Committee`);
    console.log(`members must then vote (\`${CLI} vote <session_addr>\`) until each reaches threshold. \`network::touch()\``);
    console.log(`(workers call this periodically) executes the publish once voting passes.`);
    console.log();
    if (!opts.yes) {
        const ok = await confirm({ message: 'Proceed?', default: false });
        if (!ok) { console.log('Aborted.'); return; }
    }

    const aptosConfig = new AptosConfig({
        network: Network.CUSTOM,
        fullnode: deployment.rpcUrl,
        ...(deployment.sharedNodeApiKey ? { clientConfig: { HEADERS: { Authorization: `Bearer ${deployment.sharedNodeApiKey}` } } } : {}),
    });
    const aptos = new Aptos(aptosConfig);

    const targetEpoch = await fetchCurrentEpoch(aptos, deployment.aceAddr);
    console.log(`  Current on-chain epoch: ${targetEpoch} (target_epoch for all proposals).`);
    console.log();

    const scratch = prepareContractsPublishScratch(
        path.join(REPO_ROOT, 'contracts'),
        deployment.aceAddr,
        version,
    );
    const payloadTmp = mkdtempSync(path.join(os.tmpdir(), 'ace-upgrade-payloads-'));
    const submittedSessions: { pkg: string; txHash: string }[] = [];
    try {
        for (const folder of ACE_CONTRACT_PACKAGES) {
            const packageDir = path.join(scratch.contractsDir, folder);
            const jsonOut = path.join(payloadTmp, `${folder}.json`);
            console.log(`Compiling ${folder} → publish payload...`);
            buildPublishPayload(packageDir, jsonOut);
            const payload = readPublishPayload(jsonOut);
            console.log(`  metadata: ${payload.metadata.length} B, code: ${payload.code.length} chunks (total ${payload.code.reduce((s, c) => s + c.length, 0)} B)`);
            console.log(`  Submitting new_upgrade_proposal(${folder})...`);
            const txHash = await submitUpgradeProposal({
                aptos,
                admin: adminAccount,
                aceAddr: deployment.aceAddr,
                packageName: folder,
                payload,
                description: `${folder} @ v${version}`,
                targetEpoch,
            });
            submittedSessions.push({ pkg: folder, txHash });
            console.log(`  ✓ Submitted. Tx: ${txHash}`);
            console.log();
        }
    } finally {
        rmSync(payloadTmp, { recursive: true, force: true });
        rmContractsPublishScratch(scratch);
    }

    const config = loadConfig();
    const dep = config.deployments[deploymentKey];
    if (dep) {
        dep.deployedAt = new Date().toISOString();
        dep.deployedAtTag = `v${version}`;
        saveConfig(config);
    }

    console.log('══════════════════════════════════════════════════════════════════════');
    console.log(`  ${submittedSessions.length} upgrade proposals submitted at v${version}.`);
    console.log();
    console.log('  Next steps:');
    console.log(`    1. Committee members vote: \`${CLI} proposal ls\` shows the open sessions;`);
    console.log(`       \`${CLI} vote <session_addr>\` casts a vote.`);
    console.log(`    2. Once threshold votes accumulate, the next worker-triggered`);
    console.log(`       \`network::touch()\` invokes \`code::publish_package_txn\` and the new`);
    console.log('       bytecode lands on chain.');
    console.log(`    3. Verify with \`${CLI} network-status\` — version line reflects v${version}.`);
    console.log('══════════════════════════════════════════════════════════════════════');
}
