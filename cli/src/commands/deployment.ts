// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { confirm } from '@inquirer/prompts';
import { loadConfig, saveConfig, deriveRpcLabel } from '../config.js';
import { CLI } from '../cli-name.js';

const D = '\x1b[2m', R = '\x1b[0m', B = '\x1b[1m', G = '\x1b[32m';

export function deploymentListCommand(): void {
    const config = loadConfig();
    const entries = Object.entries(config.deployments);

    if (entries.length === 0) {
        console.log(`No deployment profiles configured. Run \`${CLI} deployment new\` to set one up.`);
        return;
    }

    console.log();
    for (const [key, dep] of entries) {
        const isDefault = key === config.defaultDeployment;
        const label = dep.alias ? `${B}${dep.alias}${R}` : `${D}${key}${R}`;
        const defTag = isDefault ? `  ${G}(default)${R}` : '';
        console.log(`  ${label}${defTag}`);
        console.log(`    Network    : ${dep.network ?? deriveRpcLabel(dep.rpcUrl)}`);
        console.log(`    Contract   : ${dep.aceAddr}`);
        console.log(`    Admin addr : ${dep.adminAddress}`);
        if (dep.deployedAtTag) console.log(`    Deployed   : ${dep.deployedAtTag}${dep.deployedAt ? ` (${dep.deployedAt})` : ''}`);
        console.log();
    }
}

function findDeployment(
    config: ReturnType<typeof loadConfig>,
    aliasOrKey: string,
): [string, (typeof config.deployments)[string]] | undefined {
    return Object.entries(config.deployments).find(([key, d]) =>
        d.alias === aliasOrKey || key === aliasOrKey || d.adminAddress.toLowerCase() === aliasOrKey.toLowerCase(),
    );
}

export async function deploymentDeleteCommand(aliasOrKey: string): Promise<void> {
    const config = loadConfig();
    const entry = findDeployment(config, aliasOrKey);
    if (!entry) {
        console.error(`No deployment profile matching "${aliasOrKey}". Run \`${CLI} deployment ls\`.`);
        process.exit(1);
    }
    const [key, dep] = entry;
    const label = dep.alias ?? key;

    const ok = await confirm({
        message: `Delete deployment profile "${label}"?  ` +
            `This only removes the local profile entry — the on-chain contracts at ${dep.aceAddr} remain published.`,
        default: false,
    });
    if (!ok) { console.log('Cancelled.'); return; }

    delete config.deployments[key];
    if (config.defaultDeployment === key) delete config.defaultDeployment;
    saveConfig(config);
    console.log(`✓ Deployment profile "${label}" deleted.`);
}

export function deploymentDefaultCommand(aliasOrKey: string): void {
    const config = loadConfig();
    const entry = findDeployment(config, aliasOrKey);
    if (!entry) {
        console.error(`No deployment profile matching "${aliasOrKey}". Run \`${CLI} deployment ls\`.`);
        process.exit(1);
    }
    const [key, dep] = entry;
    config.defaultDeployment = key;
    saveConfig(config);
    console.log(`✓ Default deployment profile set to "${dep.alias ?? key}".`);
}
