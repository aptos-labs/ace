// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { loadConfig, type TrackedNode, type TrackedDeployment } from './config.js';
import { CLI } from './cli-name.js';

export interface ResolvedProfile {
    nodeKey: string;
    node: TrackedNode;
}

export interface ResolvedDeployment {
    deploymentKey: string;
    deployment: TrackedDeployment;
}

/**
 * Resolve a profile from an optional alias or account address.
 * Falls back to: default profile → single profile → error.
 */
export function resolveProfile(alias?: string, account?: string): ResolvedProfile {
    const config = loadConfig();
    const entries = Object.entries(config.nodes);

    if (account) {
        const found = entries.find(([, n]) => n.accountAddr === account);
        if (!found) throw new Error(`No node profile with account address "${account}". Run \`${CLI} node ls\` to see available profiles.`);
        return { nodeKey: found[0], node: found[1] };
    }

    if (alias) {
        const found = entries.find(([, n]) => n.alias === alias);
        if (!found) throw new Error(`No node profile with alias "${alias}". Run \`${CLI} node ls\` to see available profiles.`);
        return { nodeKey: found[0], node: found[1] };
    }

    if (config.defaultNode && config.nodes[config.defaultNode]) {
        return { nodeKey: config.defaultNode, node: config.nodes[config.defaultNode]! };
    }

    if (entries.length === 1) {
        return { nodeKey: entries[0]![0], node: entries[0]![1] };
    }

    if (entries.length === 0) {
        throw new Error(`No node profiles configured. Run \`${CLI} node new\` to set one up.`);
    }

    throw new Error(
        `Multiple node profiles configured — use --profile <alias> or set a default with \`${CLI} node default <alias>\`.`,
    );
}

/**
 * Resolve a deployment profile from an optional alias or admin-account address.
 * Falls back to: default deployment → single deployment → error.
 */
export function resolveDeployment(alias?: string, account?: string): ResolvedDeployment {
    const config = loadConfig();
    const entries = Object.entries(config.deployments);

    if (account) {
        const found = entries.find(([, d]) => d.adminAddress.toLowerCase() === account.toLowerCase());
        if (!found) throw new Error(`No deployment profile with admin address "${account}". Run \`${CLI} deployment ls\`.`);
        return { deploymentKey: found[0], deployment: found[1] };
    }

    if (alias) {
        const found = entries.find(([, d]) => d.alias === alias);
        if (!found) throw new Error(`No deployment profile with alias "${alias}". Run \`${CLI} deployment ls\`.`);
        return { deploymentKey: found[0], deployment: found[1] };
    }

    if (config.defaultDeployment && config.deployments[config.defaultDeployment]) {
        return { deploymentKey: config.defaultDeployment, deployment: config.deployments[config.defaultDeployment]! };
    }

    if (entries.length === 1) {
        return { deploymentKey: entries[0]![0], deployment: entries[0]![1] };
    }

    if (entries.length === 0) {
        throw new Error(`No deployment profiles configured. Run \`${CLI} deployment new\` to set one up.`);
    }

    throw new Error(
        `Multiple deployment profiles configured — use --profile <alias> or set a default with \`${CLI} deployment default <alias>\`.`,
    );
}
