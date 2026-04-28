// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { loadConfig } from '../config.js';
import { NetworkClient } from '../network-client.js';
import { renderNetworkState } from '../render-state.js';
import { resolveProfile } from '../resolve-profile.js';
import { runWatch } from '../watch.js';

export async function networkStatusCommand(opts: { profile?: string; watch?: boolean }): Promise<void> {
    const render = async (): Promise<string> => {
        // Re-read config from disk each render so profile edits are reflected immediately.
        const { node } = resolveProfile(opts.profile);
        const profiles = loadConfig().nodes;
        const client = new NetworkClient(node.rpcUrl, node.aceAddr, node.rpcApiKey);
        const state = await client.getNetworkState();
        return renderNetworkState(state, profiles, node.rpcUrl, node.aceAddr);
    };

    if (opts.watch) {
        await runWatch(render);
    } else {
        const content = await render();
        console.log(content);
    }
}
