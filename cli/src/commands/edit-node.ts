// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `ace node edit` — open the resolved node profile in `$EDITOR` as a TOML template.
 *
 * Editable fields (per-platform):
 *   * `alias` — display name in `node-status`/`network-status`.
 *   * `image` — Docker image (ignored on `local` platform).
 *   * `rpcApiKey` — passed as `--ace-deployment-apikey` to the worker.
 *   * `gasStationKey` — passed as `--ace-deployment-gaskey`.
 *   * `[chainRpc]` — per-chain RPC URLs + API keys for the worker's
 *     proof-of-permission verification path. **The Aptos testnet API key here
 *     is what stops the worker from hitting the 40k-CU/300s anonymous IP
 *     rate limit** under any non-trivial decryption load.
 *
 * Identity / platform-tying fields (account, keys, deployment URL, platform,
 * gcp/docker/local subconfig) are surfaced as comments only — uncommenting
 * them is rejected. To change those, recreate the node profile.
 */

import { parse as parseToml } from 'smol-toml';
import * as path from 'path';

import { loadConfig, saveConfig, type ChainRpcOverrides, type TrackedNode } from '../config.js';
import { buildFromEditor } from '../editor.js';
import { resolveProfile } from '../resolve-profile.js';
import { CLI } from '../cli-name.js';
import { gcpDeployCmd, dockerRunCmd, localRunArgs, dockerRpcUrl, writeLogrotateConf, runLogrotate } from '../onboarding.js';
import { spawnLocalNode, killLocalNode, isLocalNodeAlive } from '../local-process.js';
import { fetchDeployment, computeDiff } from '../deployment-check.js';

const G = '\x1b[32m', E = '\x1b[31m', D = '\x1b[2m', R = '\x1b[0m';

const TOP_LEVEL_KEYS = ['alias', 'image', 'rpcApiKey', 'gasStationKey'] as const;
const CHAIN_RPC_KEYS = [
    'aptosMainnetApi', 'aptosMainnetApikey',
    'aptosTestnetApi', 'aptosTestnetApikey',
    'aptosLocalnetApi', 'aptosLocalnetApikey',
    'solanaMainnetBetaRpc', 'solanaTestnetRpc', 'solanaDevnetRpc',
] as const;
type TopKey = typeof TOP_LEVEL_KEYS[number];
type ChainKey = typeof CHAIN_RPC_KEYS[number];

const FORBIDDEN_TOP = [
    'rpcUrl', 'nodeRpcUrl', 'aceAddr', 'accountAddr', 'accountSk',
    'pkeDk', 'pkeEk', 'endpoint', 'platform', 'gcp', 'docker', 'local',
] as const;

function tomlString(v: string | undefined): string {
    return v === undefined ? '""' : `"${v}"`;
}

function generateTemplate(node: TrackedNode, nodeKey: string): string {
    const rpc = node.chainRpc ?? {};
    const imageLine = node.platform === 'local'
        ? `# image           = (ignored — local builds use the binary at \`<repoPath>/target/release/network-node\`)`
        : `image            = ${tomlString(node.image)}      # see \`${CLI} image ls\` for available tags`;

    return `# ACE node profile — edit the values below, then save and quit your editor.
#
#   * Empty string ("") clears an optional field.
#   * Lines starting with "#" are comments and ignored.
#   * Identity / platform fields are shown commented for reference;
#     uncommenting any of them will be rejected when you save.
#
# Profile ID: ${nodeKey}
#
# ── Read-only identity / deployment binding (do NOT uncomment) ────────────────
#  accountAddr   = "${node.accountAddr}"
#  pkeEk         = "${node.pkeEk ?? ''}"
#  aceAddr       = "${node.aceAddr}"
#  rpcUrl        = "${node.rpcUrl}"
#  platform      = "${node.platform ?? ''}"
#
# ── Editable fields ───────────────────────────────────────────────────────────
alias            = ${tomlString(node.alias)}
${imageLine}
rpcApiKey        = ${tomlString(node.rpcApiKey)}      # → --ace-deployment-apikey
gasStationKey    = ${tomlString(node.gasStationKey)}  # → --ace-deployment-gaskey

# Per-chain RPC endpoints + API keys used by the worker's proof-verification
# path (\`verify_basic\` / \`verify_custom\` in worker-components/network-node).
# Empty URL = use the worker binary's compiled-in default endpoint.
# Empty key = anonymous (subject to public IP rate limits — set the key for
# the chains you expect non-trivial decrypt traffic on).
[chainRpc]
aptosMainnetApi      = ${tomlString(rpc.aptosMainnetApi)}
aptosMainnetApikey   = ${tomlString(rpc.aptosMainnetApikey)}
aptosTestnetApi      = ${tomlString(rpc.aptosTestnetApi)}
aptosTestnetApikey   = ${tomlString(rpc.aptosTestnetApikey)}
aptosLocalnetApi     = ${tomlString(rpc.aptosLocalnetApi)}
aptosLocalnetApikey  = ${tomlString(rpc.aptosLocalnetApikey)}
solanaMainnetBetaRpc = ${tomlString(rpc.solanaMainnetBetaRpc)}
solanaTestnetRpc     = ${tomlString(rpc.solanaTestnetRpc)}
solanaDevnetRpc      = ${tomlString(rpc.solanaDevnetRpc)}
`;
}

interface ParsedEdit {
    top: Partial<Pick<TrackedNode, TopKey>>;
    chainRpc: ChainRpcOverrides;
}

function parseEdited(content: string, node: TrackedNode): ParsedEdit | null {
    let doc: Record<string, unknown>;
    try {
        doc = parseToml(content) as Record<string, unknown>;
    } catch (e) {
        throw new Error(`TOML parse error: ${(e as Error).message}`);
    }

    for (const k of FORBIDDEN_TOP) {
        if (k in doc) {
            throw new Error(
                `Field "${k}" is read-only — it binds this profile to a specific deployment / platform. ` +
                `Delete the line (or leave it commented) and re-save. To change it, recreate the profile.`,
            );
        }
    }

    for (const k of Object.keys(doc)) {
        if (k === 'chainRpc') continue;
        if (!(TOP_LEVEL_KEYS as readonly string[]).includes(k)) {
            throw new Error(`Unknown field "${k}" — typo? Allowed: ${TOP_LEVEL_KEYS.join(', ')}, chainRpc.`);
        }
    }

    const top: Partial<Pick<TrackedNode, TopKey>> = {};
    for (const k of TOP_LEVEL_KEYS) {
        if (k === 'image' && node.platform === 'local') continue;  // image is ignored for local builds
        const v = doc[k];
        if (v === undefined) continue;
        if (typeof v !== 'string') {
            throw new Error(`Field "${k}" must be a TOML string in quotes (got ${typeof v}).`);
        }
        (top as Record<string, string | undefined>)[k] = v === '' ? undefined : v;
    }

    const chainRpc: ChainRpcOverrides = {};
    const rpcDoc = doc.chainRpc as Record<string, unknown> | undefined;
    if (rpcDoc !== undefined) {
        if (typeof rpcDoc !== 'object' || Array.isArray(rpcDoc)) {
            throw new Error(`Field "chainRpc" must be a TOML table (use "[chainRpc]" header).`);
        }
        for (const k of Object.keys(rpcDoc)) {
            if (!(CHAIN_RPC_KEYS as readonly string[]).includes(k)) {
                throw new Error(`Unknown chainRpc key "${k}" — typo? Allowed: ${CHAIN_RPC_KEYS.join(', ')}.`);
            }
        }
        for (const k of CHAIN_RPC_KEYS) {
            const v = rpcDoc[k];
            if (v === undefined) continue;
            if (typeof v !== 'string') {
                throw new Error(`chainRpc."${k}" must be a TOML string (got ${typeof v}).`);
            }
            if (v !== '') (chainRpc as Record<string, string>)[k] = v;
        }
    }

    return { top, chainRpc };
}

function applyEdits(node: TrackedNode, edit: ParsedEdit): TrackedNode {
    const merged: TrackedNode = { ...node };
    for (const k of TOP_LEVEL_KEYS) {
        if (k in edit.top) (merged as unknown as Record<string, unknown>)[k] = edit.top[k];
    }
    merged.chainRpc = Object.keys(edit.chainRpc).length > 0 ? edit.chainRpc : undefined;
    return merged;
}

function diffSummary(before: TrackedNode, after: TrackedNode): string[] {
    const lines: string[] = [];
    for (const k of TOP_LEVEL_KEYS) {
        const a = (before as unknown as Record<string, unknown>)[k];
        const b = (after as unknown as Record<string, unknown>)[k];
        if (a !== b) lines.push(`    ${k.padEnd(20)} ${a ?? '(unset)'} → ${b ?? '(unset)'}`);
    }
    const beforeRpc = before.chainRpc ?? {};
    const afterRpc  = after.chainRpc ?? {};
    for (const k of CHAIN_RPC_KEYS) {
        const a = beforeRpc[k];
        const b = afterRpc[k];
        if (a !== b) lines.push(`    chainRpc.${k.padEnd(20)} ${a ?? '(unset)'} → ${b ?? '(unset)'}`);
    }
    return lines;
}

export async function editNodeCommand(opts: { profile?: string; account?: string }): Promise<void> {
    const { nodeKey, node } = resolveProfile(opts.profile, opts.account);
    const label = node.alias ?? nodeKey;

    console.log(`\nEditing node: ${label}\n`);

    const warning =
        `⚠ The editor will display this node's API keys in plaintext.\n` +
        `  Don't share-screen, paste into chat, or commit the file's contents while it's open.\n` +
        `  (Backed by a 0600 temp file that's deleted when you exit the editor.)\n`;

    const edit = await buildFromEditor(
        generateTemplate(node, nodeKey),
        c => parseEdited(c, node),
        { fileTag: 'node-edit', preWarning: warning },
    );
    if (!edit) return;

    const updatedNode = applyEdits(node, edit);
    const changes = diffSummary(node, updatedNode);
    if (changes.length === 0) {
        console.log('No effective changes — nothing to save.');
        return;
    }

    const config = loadConfig();
    config.nodes[nodeKey] = updatedNode;
    saveConfig(config);
    console.log(`\n✓ Profile "${label}" saved:\n${changes.join('\n')}\n`);

    // Emit the deploy command (or restart, for local).
    const nodeArgs = {
        accountAddr: node.accountAddr,
        accountSk:   node.accountSk ?? '',
        pkeDk:       node.pkeDk ?? '',
    };
    const { image, rpcApiKey, gasStationKey } = updatedNode;
    const chainRpc = updatedNode.chainRpc;

    if (node.platform === 'gcp' && node.gcp) {
        console.log('Run this command to apply the changes:\n');
        console.log(gcpDeployCmd(
            node.gcp.serviceName, image!, node.gcp.project, node.gcp.region,
            nodeArgs, node.rpcUrl, node.aceAddr, rpcApiKey, gasStationKey, chainRpc,
        ));
    } else if (node.platform === 'docker' && node.docker) {
        console.log('Run this command to apply the changes:\n');
        console.log(`docker rm -f ${node.docker.containerName} &&`);
        console.log(dockerRunCmd(
            node.docker.containerName, image!, node.docker.port,
            nodeArgs, node.nodeRpcUrl ?? node.rpcUrl, node.aceAddr, rpcApiKey, gasStationKey, chainRpc,
        ));
    } else if (node.platform === 'local' && node.local) {
        if (node.local.pid && isLocalNodeAlive(node.local.pid)) {
            console.log(`Stopping old process (pid=${node.local.pid})...`);
            killLocalNode(node.local.pid);
            await new Promise(r => setTimeout(r, 500));
        }
        const binaryPath = path.join(node.local.repoPath, 'target', 'release', 'network-node');
        const runArgs = localRunArgs(
            node.local.port, nodeArgs, node.rpcUrl, node.aceAddr, rpcApiKey, gasStationKey, chainRpc,
        );
        const logFile = node.local.logFile ?? '';
        if (node.local.logMaxMb && logFile) {
            runLogrotate(writeLogrotateConf(logFile, node.local.logMaxMb));
        }
        const pid = spawnLocalNode(binaryPath, runArgs, logFile);
        const config2 = loadConfig();
        const n2 = config2.nodes[nodeKey];
        if (n2 && n2.local) n2.local.pid = pid;
        saveConfig(config2);
        console.log(`Node restarted in background  pid=${pid}  log=${logFile}`);
        return;
    } else {
        return; // no deployment platform — nothing to deploy or watch
    }

    // For gcp/docker, used Docker, suppress chain warnings, keep silent. Quietly note that we won't auto-detect docker locally.
    if (node.platform !== 'gcp') return;

    // Poll Cloud Run until the live deployment matches the saved profile, or user quits.
    console.log('\nWatching deployment for sync...  [Q to stop]\n');

    if (process.stdin.isTTY) process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');

    let stop = false;
    process.stdin.on('data', (key: string) => {
        if (key === 'q' || key === 'Q' || key === '\x03') stop = true;
    });

    const restore = () => {
        if (process.stdin.isTTY) process.stdin.setRawMode(false);
        process.stdin.pause();
    };
    process.once('SIGINT',  () => { restore(); process.exit(0); });
    process.once('SIGTERM', () => { restore(); process.exit(0); });

    while (!stop) {
        const dep = await fetchDeployment(updatedNode);

        if (dep instanceof Error) {
            process.stdout.write(`\r\x1b[K  ${E}✗ ${dep.message}${R}`);
        } else if (dep === null) {
            break;
        } else {
            const diff = computeDiff(updatedNode, dep);
            const outdated = diff.filter(r => !r.match);
            if (outdated.length === 0) {
                process.stdout.write(`\r\x1b[K${G}✓ Deployment is in sync.${R}\n`);
                stop = true;
                break;
            } else {
                const fields = outdated.map(r => r.field).join(', ');
                process.stdout.write(`\r\x1b[K  ${D}✗ ${outdated.length} field(s) still outdated: ${fields}${R}`);
            }
        }

        const deadline = Date.now() + 2000;
        while (!stop && Date.now() < deadline) {
            await new Promise(r => setTimeout(r, 100));
        }
    }

    restore();
}
