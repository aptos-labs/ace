// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { confirm } from '@inquirer/prompts';
import { AccountAddress } from '@aptos-labs/ts-sdk';
import { resolveProfile } from '../resolve-profile.js';
import { NetworkClient } from '../network-client.js';
import { formatError } from '../format-error.js';

export async function voteCommand(sessionAddr: string, opts: { profile?: string; yes?: boolean }): Promise<void> {
    // Validate session address
    let addr: AccountAddress;
    try {
        addr = AccountAddress.fromString(sessionAddr);
    } catch {
        console.error(`Invalid session address: ${sessionAddr}`);
        process.exit(1);
    }

    const { node } = resolveProfile(opts.profile);
    const client = NetworkClient.fromNode(node);

    // Fetch state to validate the session is still active
    let state;
    try {
        state = await client.getNetworkState();
    } catch (e) {
        console.error(`Error fetching network state: ${(e as any)?.message ?? e}`);
        process.exit(1);
    }

    const pv = state.activeProposals().find(p => p.votingSession.toStringLong() === addr.toStringLong());
    if (!pv) {
        console.error(`No active proposal with session address ${sessionAddr}.`);
        console.log('Run `ace network-status` to see current proposals.');
        process.exit(1);
    }

    const isCommitteeMember = state.curNodes.some(n => n.toStringLong() === node.accountAddr);
    if (!isCommitteeMember) {
        console.error('Your account is not a current committee member.');
        process.exit(1);
    }
    if (pv.hasVoted(node.accountAddr, state.curNodes)) {
        console.error('You have already voted on this proposal.');
        process.exit(1);
    }
    if (pv.votingPassed) {
        console.error('This proposal has already passed.');
        process.exit(1);
    }

    const sessionShort = `${addr.toStringLong().slice(0, 10)}...${addr.toStringLong().slice(-6)}`;
    console.log(`\nProposal  : ${pv.proposal.description || `${pv.proposal.nodes.length} nodes, threshold ${pv.proposal.threshold}`}`);
    console.log(`Session   : ${addr.toStringLong()}`);
    console.log(`Votes     : ${pv.voteCount()}/${state.curThreshold}`);
    console.log();

    const proceed = opts.yes || await confirm({ message: 'Submit vote?', default: true });
    if (!proceed) {
        console.log('Cancelled.');
        return;
    }

    console.log('Submitting vote...');
    try {
        const hash = await client.submitVote(addr);
        console.log(`✓ Vote submitted  (txn: ${hash})`);
    } catch (e) {
        console.error(`✗ Failed: ${formatError(e)}`);
        process.exit(1);
    }
}
