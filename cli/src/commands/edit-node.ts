// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `ace node edit` — open the resolved node profile in `$EDITOR` as a TOML form.
 *
 * The form's schema is picked from the node's stored `(platform, mode)` pair —
 * the same four schemes that `ace node new` offers. Identity / deployment-
 * binding fields (account, keys, deployment URL, platform, mode) are surfaced
 * as comments only; uncommenting them is rejected. To change those, recreate
 * the node profile.
 */

import * as path from 'path';

import { loadConfig, saveConfig, nodeMode, type TrackedNode } from '../config.js';
import { buildFromEditor } from '../editor.js';
import { resolveProfile } from '../resolve-profile.js';
import {
    gcpDeployCmd, gcpDeployCmdMicroservices, dockerRunCmd, localRunArgs,
    writeLogrotateConf, runLogrotate, rpcUrlsNeedVpcEgress,
} from '../onboarding.js';
import { spawnLocalNode, killLocalNode, isLocalNodeAlive } from '../local-process.js';
import { fetchDeployment, computeDiff } from '../deployment-check.js';
import { gcloudReady, dockerReady, maybeAutoRun } from '../auto-deploy.js';
import {
    schemeOf, generateTemplate, parseTemplate,
    type TemplateInputs, type ParsedNodeForm,
} from '../node-schemes.js';

const G = '\x1b[32m', E = '\x1b[31m', D = '\x1b[2m', R = '\x1b[0m';

/** Convert a TrackedNode into the seed values shown in the template. */
function templateInputsFromNode(node: TrackedNode): TemplateInputs {
    return {
        identity: {
            accountAddr: node.accountAddr,
            pkeEk:       node.pkeEk ?? '',
        },
        blob: {
            rpcUrl:        node.rpcUrl,
            aceAddr:       node.aceAddr,
            rpcApiKey:     node.rpcApiKey,
            gasStationKey: node.gasStationKey,
            nodeRpcUrl:    node.nodeRpcUrl,
        },
        defaults: {},
        existing: {
            alias:                  node.alias,
            image:                  node.image,
            rpcApiKey:              node.rpcApiKey,
            gasStationKey:          node.gasStationKey,
            chainRpc:               node.chainRpc,
            project:                node.gcp?.project,
            region:                 node.gcp?.region,
            serviceName:            node.gcp?.serviceName,
            maintainerServiceName:  node.gcp?.maintainerServiceName,
            handlerServiceName:     node.gcp?.handlerServiceName,
            handlerMaxInstances:    node.gcp?.handlerMaxInstances,
            port:                   node.docker?.port ?? node.local?.port,
            containerName:          node.docker?.containerName,
            repoPath:               node.local?.repoPath,
            logMaxMb:               node.local?.logMaxMb,
        },
    };
}

function applyEdits(node: TrackedNode, edit: ParsedNodeForm): TrackedNode {
    const merged: TrackedNode = { ...node };
    merged.alias         = edit.alias;
    merged.image         = edit.image ?? merged.image;
    merged.rpcApiKey     = edit.rpcApiKey;
    merged.gasStationKey = edit.gasStationKey;
    merged.chainRpc      = edit.chainRpc;

    if (node.gcp) {
        merged.gcp = {
            ...node.gcp,
            project:                edit.project               ?? node.gcp.project,
            region:                 edit.region                ?? node.gcp.region,
            serviceName:            edit.serviceName,
            maintainerServiceName:  edit.maintainerServiceName,
            handlerServiceName:     edit.handlerServiceName,
            handlerMaxInstances:    edit.handlerMaxInstances,
        };
    }
    if (node.docker) {
        merged.docker = {
            containerName: edit.containerName ?? node.docker.containerName,
            port:          edit.port          ?? node.docker.port,
        };
    }
    if (node.local) {
        merged.local = {
            ...node.local,
            repoPath:  edit.repoPath ?? node.local.repoPath,
            port:      edit.port     ?? node.local.port,
            logMaxMb:  edit.logMaxMb ?? node.local.logMaxMb,
        };
    }
    return merged;
}

function diffSummary(before: TrackedNode, after: TrackedNode): string[] {
    const lines: string[] = [];
    const keys: (keyof TrackedNode)[] = ['alias', 'image', 'rpcApiKey', 'gasStationKey'];
    for (const k of keys) {
        const a = before[k];
        const b = after[k];
        if (a !== b) lines.push(`    ${String(k).padEnd(20)} ${a ?? '(unset)'} → ${b ?? '(unset)'}`);
    }
    const aRpc = JSON.stringify(before.chainRpc ?? {});
    const bRpc = JSON.stringify(after.chainRpc  ?? {});
    if (aRpc !== bRpc) lines.push(`    chainRpc             changed`);
    const aGcp = JSON.stringify(before.gcp ?? {});
    const bGcp = JSON.stringify(after.gcp  ?? {});
    if (aGcp !== bGcp) lines.push(`    gcp                  changed`);
    const aDocker = JSON.stringify(before.docker ?? {});
    const bDocker = JSON.stringify(after.docker  ?? {});
    if (aDocker !== bDocker) lines.push(`    docker               changed`);
    const aLocal = JSON.stringify(before.local ?? {});
    const bLocal = JSON.stringify(after.local  ?? {});
    if (aLocal !== bLocal) lines.push(`    local                changed`);
    return lines;
}

export async function editNodeCommand(opts: { profile?: string; account?: string }): Promise<void> {
    const { nodeKey, node } = resolveProfile(opts.profile, opts.account);
    const label = node.alias ?? nodeKey;
    const scheme = schemeOf(node);

    console.log(`\nEditing node: ${label} (scheme: ${scheme})\n`);

    const warning =
        `⚠ The editor will display this node's API keys in plaintext.\n` +
        `  Don't share-screen, paste into chat, or commit the file's contents while it's open.\n` +
        `  (Backed by a 0600 temp file that's deleted when you exit the editor.)\n`;

    const inputs = templateInputsFromNode(node);
    const edit = await buildFromEditor(
        generateTemplate(scheme, inputs),
        c => parseTemplate(scheme, c),
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
    const mode = nodeMode(updatedNode);

    if (node.platform === 'gcp' && updatedNode.gcp) {
        if (rpcUrlsNeedVpcEgress(chainRpc)) {
            console.log(`${D}A private RPC URL was detected; the command below adds --network/--subnet/--vpc-egress so Cloud Run can reach it via VPC.${R}`);
        }
        const cmd = mode === 'microservices'
            ? gcpDeployCmdMicroservices(
                {
                    project:                updatedNode.gcp.project,
                    region:                 updatedNode.gcp.region,
                    maintainerServiceName:  updatedNode.gcp.maintainerServiceName!,
                    handlerServiceName:     updatedNode.gcp.handlerServiceName!,
                    handlerMaxInstances:    updatedNode.gcp.handlerMaxInstances!,
                },
                image!, nodeArgs, node.rpcUrl, node.aceAddr, rpcApiKey, gasStationKey, chainRpc,
            )
            : gcpDeployCmd(
                updatedNode.gcp.serviceName!, image!, updatedNode.gcp.project, updatedNode.gcp.region,
                nodeArgs, node.rpcUrl, node.aceAddr, rpcApiKey, gasStationKey, chainRpc,
            );
        console.log('Re-deploy command:\n');
        console.log(cmd.display);
        console.log();
        await maybeAutoRun(cmd.run, gcloudReady(), 'Apply this now?', cmd.env);
    } else if (node.platform === 'docker' && updatedNode.docker) {
        const cmd = [
            `docker rm -f ${updatedNode.docker.containerName} &&`,
            dockerRunCmd(
                updatedNode.docker.containerName, image!, updatedNode.docker.port,
                nodeArgs, node.nodeRpcUrl ?? node.rpcUrl, node.aceAddr, rpcApiKey, gasStationKey, chainRpc,
            ),
        ].join('\n');
        console.log('Restart command:\n');
        console.log(cmd);
        console.log();
        await maybeAutoRun(cmd, dockerReady(), 'Apply this now?');
    } else if (node.platform === 'local' && updatedNode.local) {
        if (updatedNode.local.pid && isLocalNodeAlive(updatedNode.local.pid)) {
            console.log(`Stopping old process (pid=${updatedNode.local.pid})...`);
            killLocalNode(updatedNode.local.pid);
            await new Promise(r => setTimeout(r, 500));
        }
        const binaryPath = path.join(updatedNode.local.repoPath, 'target', 'release', 'network-node');
        const runArgs = localRunArgs(
            updatedNode.local.port, nodeArgs, node.rpcUrl, node.aceAddr, rpcApiKey, gasStationKey, chainRpc,
        );
        const logFile = updatedNode.local.logFile ?? '';
        if (updatedNode.local.logMaxMb && logFile) {
            runLogrotate(writeLogrotateConf(logFile, updatedNode.local.logMaxMb));
        }
        const pid = spawnLocalNode(binaryPath, runArgs, logFile);
        const config2 = loadConfig();
        const n2 = config2.nodes[nodeKey];
        if (n2 && n2.local) n2.local.pid = pid;
        saveConfig(config2);
        console.log(`Node restarted in background  pid=${pid}  log=${logFile}`);
        return;
    } else {
        return;
    }

    // GCP monolith: poll for sync. Microservices: skip (two services; revisit).
    if (node.platform !== 'gcp' || mode !== 'monolith') return;

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
