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

export async function profileDeleteCommand(alias: string): Promise<void> {
    const config = loadConfig();
    const entry = Object.entries(config.nodes).find(([, n]) => n.alias === alias);
    if (!entry) {
        console.error(`No profile with alias "${alias}".`);
        process.exit(1);
    }
    const [key] = entry;

    const ok = await confirm({ message: `Delete profile "${alias}"?`, default: false });
    if (!ok) { console.log('Cancelled.'); return; }

    delete config.nodes[key];
    if (config.defaultNode === key) delete config.defaultNode;
    saveConfig(config);
    console.log(`✓ Profile "${alias}" deleted.`);
}

export function profileDefaultCommand(alias: string): void {
    const config = loadConfig();
    const entry = Object.entries(config.nodes).find(([, n]) => n.alias === alias);
    if (!entry) {
        console.error(`No profile with alias "${alias}". Run \`ace profile list\` to see available profiles.`);
        process.exit(1);
    }
    config.defaultNode = entry[0];
    saveConfig(config);
    console.log(`✓ Default profile set to "${alias}".`);
}
