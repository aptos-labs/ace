// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { loadConfig } from '../config.js';
import { CLI } from '../cli-name.js';
import { NetworkClient } from '../network-client.js';
import { renderNetworkState } from '../render-state.js';
import { resolveProfile, resolveDeployment } from '../resolve-profile.js';
import { runWatch } from '../watch.js';

/**
 * Try the node namespace first; on failure try the deployment namespace. Returns the
 * minimum the renderer needs: chain connection info plus optional RPC auth. Either
 * profile type works because both store rpcUrl + aceAddr; only the secondary fields
 * differ (per-node SK vs admin SK).
 */
function resolveChainEndpoint(alias?: string, account?: string): { rpcUrl: string; aceAddr: string; rpcApiKey?: string; source: string } {
    let nodeErr: Error | undefined;
    try {
        const { nodeKey, node } = resolveProfile(alias, account);
        return { rpcUrl: node.rpcUrl, aceAddr: node.aceAddr, rpcApiKey: node.rpcApiKey, source: `node profile "${node.alias ?? nodeKey}"` };
    } catch (e) { nodeErr = e as Error; }

    try {
        const { deploymentKey, deployment } = resolveDeployment(alias, account);
        return { rpcUrl: deployment.rpcUrl, aceAddr: deployment.aceAddr, rpcApiKey: deployment.sharedNodeApiKey, source: `deployment profile "${deployment.alias ?? deploymentKey}"` };
    } catch (depErr) {
        // Synthesize a single error covering both namespaces so the user can tell what they have.
        const config = loadConfig();
        const nodeCount = Object.keys(config.nodes).length;
        const depCount  = Object.keys(config.deployments).length;
        throw new Error(
            (alias ? `No profile (node or deployment) matching alias "${alias}".` :
             account ? `No profile (node or deployment) matching account "${account}".` :
             `No node or deployment profile configured, and no default set.`) +
            `\n  Currently configured: ${nodeCount} node profile(s), ${depCount} deployment profile(s).` +
            `\n  See: \`${CLI} node ls\`  or  \`${CLI} deployment ls\`.` +
            `\n  Original errors:` +
            `\n    node:       ${nodeErr?.message ?? '(none)'}` +
            `\n    deployment: ${(depErr as Error).message}`,
        );
    }
}

export async function networkStatusCommand(opts: { profile?: string; account?: string; watch?: boolean }): Promise<void> {
    const render = async (): Promise<string> => {
        // Re-read config from disk each render so profile edits are reflected immediately.
        const { rpcUrl, aceAddr, rpcApiKey } = resolveChainEndpoint(opts.profile, opts.account);
        const profiles = loadConfig().nodes;
        const client = new NetworkClient(rpcUrl, aceAddr, rpcApiKey);
        const [state, version] = await Promise.all([
            client.getNetworkState(),
            client.getDeployedContractVersion(),
        ]);
        return renderNetworkState(state, profiles, rpcUrl, aceAddr, version);
    };

    if (opts.watch) {
        await runWatch(render, { refreshMs: 1000, showFooter: false });
    } else {
        const content = await render();
        console.log(content);
    }
}
