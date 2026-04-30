// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { loadConfig } from '../config.js';
import { NetworkClient } from '../network-client.js';
import { fetchDeployment, computeDiff, type DiffRow } from '../deployment-check.js';
import { renderNodeStatus } from '../render-state.js';
import { resolveProfile } from '../resolve-profile.js';
import { runWatch } from '../watch.js';

export async function nodeStatusCommand(opts: { profile?: string; account?: string; watch?: boolean; reveal?: boolean }): Promise<void> {
    const render = async (): Promise<string> => {
        // Re-read config from disk each render so edits from other processes are reflected.
        const { nodeKey, node } = resolveProfile(opts.profile, opts.account);
        const profiles = loadConfig().nodes;
        const client = NetworkClient.fromNode(node);

        const [stateResult, deployResult] = await Promise.allSettled([
            client.getNetworkState(),
            node.platform ? fetchDeployment(node) : Promise.resolve(null),
        ]);

        const state = stateResult.status === 'fulfilled'
            ? stateResult.value
            : new Error(stateResult.reason instanceof Error ? stateResult.reason.message : String(stateResult.reason));

        let deployDiff: DiffRow[] | Error | null = null;
        if (deployResult.status === 'fulfilled') {
            const dep = deployResult.value;
            if (dep instanceof Error) deployDiff = dep;
            else if (dep !== null)    deployDiff = computeDiff(node, dep);
        } else {
            deployDiff = new Error(String(deployResult.reason));
        }

        return renderNodeStatus(nodeKey, node, state, deployDiff, profiles, opts.reveal ?? false);
    };

    if (opts.watch) {
        await runWatch(render, { refreshMs: 1000, showFooter: false });
    } else {
        const content = await render();
        console.log(content);
    }
}
