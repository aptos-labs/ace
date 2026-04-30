// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { confirm } from '@inquirer/prompts';
import { resolveProfile } from '../resolve-profile.js';
import { NetworkClient } from '../network-client.js';
import { deriveRpcLabel } from '../config.js';
import { formatError } from '../format-error.js';
import { buildProposalFor } from './proposal.js';

export async function proposeCommand(opts: { profile?: string; account?: string }): Promise<void> {
    const { node } = resolveProfile(opts.profile, opts.account);
    const client = NetworkClient.fromNode(node);

    let state;
    try {
        state = await client.getNetworkState();
    } catch (e) {
        const msg = String((e as any)?.message ?? e);
        const notFound = msg.includes('resource_not_found') || msg.includes('RESOURCE_DOES_NOT_EXIST') || msg.includes('NOT_FOUND');
        console.error(notFound ? 'Network not initialized.' : `Error fetching network state: ${msg}`);
        process.exit(1);
    }

    const label = node.alias ? `${node.alias}  (${node.accountAddr})` : node.accountAddr;
    const network = deriveRpcLabel(node.rpcUrl);
    console.log(`\nNode       ${label}`);
    console.log(`Contract   ${node.aceAddr}`);
    console.log(`Network    ${network}`);
    console.log(`ACE epoch  ${state.epoch}\n`);

    const isCommitteeMember = state.curNodes.some(n => n.toStringLong() === node.accountAddr);
    if (!isCommitteeMember) {
        console.error('Only current committee members can create proposals.');
        process.exit(1);
    }

    const proposal = await buildProposalFor(state);
    if (!proposal) {
        console.log('Cancelled.');
        return;
    }

    while (true) {
        console.log('\nSubmitting proposal...');
        try {
            const { hash } = await client.submitNewProposal(proposal);
            console.log(`✓ Proposal submitted  (txn: ${hash})`);
            console.log('\nRun `ace network-status` to see the voting session address.');
            break;
        } catch (e) {
            console.error(`✗ Failed: ${formatError(e)}`);
            const retry = await confirm({ message: 'Retry?', default: true });
            if (!retry) break;
        }
    }
}
