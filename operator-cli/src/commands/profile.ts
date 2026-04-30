// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { confirm } from '@inquirer/prompts';
import { loadConfig, saveConfig, deriveRpcLabel } from '../config.js';

const D = '\x1b[2m', R = '\x1b[0m', B = '\x1b[1m', G = '\x1b[32m';

export function profileListCommand(): void {
    const config = loadConfig();
    const entries = Object.entries(config.nodes);

    if (entries.length === 0) {
        console.log('No profiles configured. Run `ace new-node` to set one up.');
        return;
    }

    console.log();
    for (const [key, node] of entries) {
        const isDefault = key === config.defaultNode;
        const label = node.alias ? `${B}${node.alias}${R}` : `${D}${key}${R}`;
        const defTag = isDefault ? `  ${G}(default)${R}` : '';
        console.log(`  ${label}${defTag}`);
        console.log(`    Network : ${deriveRpcLabel(node.rpcUrl)}`);
        console.log(`    Account : ${node.accountAddr}`);
        if (node.endpoint) console.log(`    Endpoint: ${node.endpoint}`);
        if (node.platform) {
            const plat = node.platform === 'gcp'
                ? `GCP Cloud Run (${node.gcp?.serviceName ?? '?'})`
                : `Docker (${node.docker?.containerName ?? '?'})`;
            console.log(`    Deploy  : ${plat}`);
        }
        console.log();
    }
}

function findProfile(config: ReturnType<typeof loadConfig>, aliasOrKey: string): [string, (typeof config.nodes)[string]] | undefined {
    return Object.entries(config.nodes).find(([key, n]) =>
        n.alias === aliasOrKey || key === aliasOrKey || n.accountAddr === aliasOrKey,
    );
}

export async function profileDeleteCommand(aliasOrKey: string): Promise<void> {
    const config = loadConfig();
    const entry = findProfile(config, aliasOrKey);
    if (!entry) {
        console.error(`No profile matching "${aliasOrKey}". Run \`ace profile list\` to see available profiles.`);
        process.exit(1);
    }
    const [key, node] = entry;
    const label = node.alias ?? key;

    const ok = await confirm({ message: `Delete profile "${label}"?`, default: false });
    if (!ok) { console.log('Cancelled.'); return; }

    delete config.nodes[key];
    if (config.defaultNode === key) delete config.defaultNode;
    saveConfig(config);
    console.log(`✓ Profile "${label}" deleted.`);

    if (node.platform === 'docker' && node.docker?.containerName) {
        console.log(`\n  Don't forget to stop the container:\n`);
        console.log(`  docker rm -f ${node.docker.containerName}`);
    } else if (node.platform === 'gcp' && node.gcp) {
        console.log(`\n  Don't forget to delete the Cloud Run service:\n`);
        console.log(`  gcloud run services delete ${node.gcp.serviceName} --project ${node.gcp.project} --region ${node.gcp.region}`);
    }
}

export function profileDefaultCommand(aliasOrKey: string): void {
    const config = loadConfig();
    const entry = findProfile(config, aliasOrKey);
    if (!entry) {
        console.error(`No profile matching "${aliasOrKey}". Run \`ace profile list\` to see available profiles.`);
        process.exit(1);
    }
    const [key, node] = entry;
    config.defaultNode = key;
    saveConfig(config);
    console.log(`✓ Default profile set to "${node.alias ?? key}".`);
}
