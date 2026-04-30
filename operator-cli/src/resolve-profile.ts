// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { loadConfig, type TrackedNode } from './config.js';
import { CLI } from './cli-name.js';

export interface ResolvedProfile {
    nodeKey: string;
    node: TrackedNode;
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
        if (!found) throw new Error(`No profile with account address "${account}". Run \`${CLI} profile list\` to see available profiles.`);
        return { nodeKey: found[0], node: found[1] };
    }

    if (alias) {
        const found = entries.find(([, n]) => n.alias === alias);
        if (!found) throw new Error(`No profile with alias "${alias}". Run \`${CLI} profile list\` to see available profiles.`);
        return { nodeKey: found[0], node: found[1] };
    }

    if (config.defaultNode && config.nodes[config.defaultNode]) {
        return { nodeKey: config.defaultNode, node: config.nodes[config.defaultNode]! };
    }

    if (entries.length === 1) {
        return { nodeKey: entries[0]![0], node: entries[0]![1] };
    }

    if (entries.length === 0) {
        throw new Error(`No profiles configured. Run \`${CLI} new-node\` to set one up.`);
    }

    throw new Error(
        `Multiple profiles configured — use --profile <alias> or set a default with \`${CLI} profile default <alias>\`.`,
    );
}
