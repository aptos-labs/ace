// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { input } from '@inquirer/prompts';
import { resolveProfile } from '../resolve-profile.js';
import { loadConfig, saveConfig, type TrackedNode } from '../config.js';
import { selectImage } from '../docker-hub.js';
import { gcpDeployCmd, dockerRunCmd } from '../onboarding.js';
import { fetchDeployment, computeDiff } from '../deployment-check.js';

const G = '\x1b[32m', E = '\x1b[31m', D = '\x1b[2m', R = '\x1b[0m';

export async function editNodeCommand(opts: { profile?: string }): Promise<void> {
    const { nodeKey, node } = resolveProfile(opts.profile);
    const label = node.alias ?? nodeKey;

    console.log(`\nEditing node: ${label}\n`);

    // Image
    console.log(`Current image: ${node.image ?? '(not set)'}`);
    const newImage = await selectImage();
    const image = newImage ?? node.image ?? 'aptoslabs/ace-node:latest';
    console.log();

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

    // Save updated profile
    const updatedNode: TrackedNode = { ...node, image, rpcApiKey, gasStationKey };
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
            node.gcp.serviceName, image, node.gcp.project, node.gcp.region,
            nodeArgs, node.rpcUrl, node.aceAddr, rpcApiKey, gasStationKey,
        ));
    } else if (node.platform === 'docker' && node.docker) {
        console.log('Run this command to apply the changes:\n');
        console.log(dockerRunCmd(
            node.docker.containerName, image, node.docker.port,
            nodeArgs, node.rpcUrl, node.aceAddr, rpcApiKey, gasStationKey,
        ));
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
