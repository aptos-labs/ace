// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { input, confirm } from '@inquirer/prompts';
import { resolveProfile } from '../resolve-profile.js';
import { loadConfig, saveConfig, type TrackedNode } from '../config.js';
import { selectImage } from '../docker-hub.js';
import * as path from 'path';
import { gcpDeployCmd, dockerRunCmd, localRunCmd, localRunArgs, promptChainRpcOverrides, dockerRpcUrl, writeLogrotateConf, runLogrotate } from '../onboarding.js';
import { spawnLocalNode, killLocalNode, isLocalNodeAlive } from '../local-process.js';
import { fetchDeployment, computeDiff } from '../deployment-check.js';

const G = '\x1b[32m', E = '\x1b[31m', D = '\x1b[2m', R = '\x1b[0m';

export async function editNodeCommand(opts: { profile?: string; account?: string }): Promise<void> {
    const { nodeKey, node } = resolveProfile(opts.profile, opts.account);
    const label = node.alias ?? nodeKey;

    console.log(`\nEditing node: ${label}\n`);

    // Image (not applicable for local builds)
    let image = node.image;
    if (node.platform !== 'local') {
        console.log(`Current image: ${node.image ?? '(not set)'}`);
        const newImage = await selectImage();
        image = newImage ?? node.image ?? 'aptoslabs/ace-node:latest';
        console.log();
    }

    // API key
    const newApiKey = await input({
        message: 'API key (Enter to keep current, "none" to clear)',
        default: '',
    });
    const rpcApiKey = newApiKey === 'none' ? undefined
        : newApiKey.trim() !== '' ? newApiKey.trim()
        : node.rpcApiKey;

    // Gas station key
    const newGasKey = await input({
        message: 'Gas station key (Enter to keep current, "none" to clear)',
        default: '',
    });
    const gasStationKey = newGasKey === 'none' ? undefined
        : newGasKey.trim() !== '' ? newGasKey.trim()
        : node.gasStationKey;

    // Chain RPC overrides
    let chainRpc = node.chainRpc;
    if (await confirm({ message: 'Edit per-chain RPC overrides?', default: false })) {
        chainRpc = await promptChainRpcOverrides(node.chainRpc, node.platform === 'docker' ? dockerRpcUrl : undefined);
        chainRpc = Object.keys(chainRpc).length > 0 ? chainRpc : undefined;
    }

    // Save updated profile
    const updatedNode: TrackedNode = { ...node, image, rpcApiKey, gasStationKey, chainRpc };
    const config = loadConfig();
    config.nodes[nodeKey] = updatedNode;
    saveConfig(config);
    console.log(`\n✓ Profile "${label}" saved.\n`);

    // Show deploy command
    const nodeArgs = {
        accountAddr: node.accountAddr,
        accountSk:   node.accountSk ?? '',
        pkeDk:       node.pkeDk ?? '',
    };

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
            // brief wait for the port to be released
            await new Promise(r => setTimeout(r, 500));
        }
        const binaryPath = path.join(node.local.repoPath, 'target', 'release', 'network-node');
        const runArgs = localRunArgs(
            node.local.port, nodeArgs, node.rpcUrl, node.aceAddr, rpcApiKey, gasStationKey, chainRpc,
        );
        const logFile = node.local.logFile ?? updatedNode.local?.logFile ?? '';
        if (node.local.logMaxMb && logFile) {
            runLogrotate(writeLogrotateConf(logFile, node.local.logMaxMb));
        }
        const pid = spawnLocalNode(binaryPath, runArgs, logFile);
        updatedNode.local = { ...node.local, pid };
        console.log(`Node restarted in background  pid=${pid}  log=${logFile}`);
        const config = loadConfig();
        config.nodes[nodeKey] = updatedNode;
        saveConfig(config);
        return;
    } else {
        return; // no deployment platform, nothing to watch
    }

    // Poll until running deployment matches updated profile, or user quits.
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
            break; // platform doesn't support introspection
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
