// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { select, input, confirm } from '@inquirer/prompts';
import { AccountAddress } from '@aptos-labs/ts-sdk';
import { network as aceNetwork } from '@aptos-labs/ace-sdk';
import { loadConfig, resolveProfile } from '../config.js';
import { NetworkClient, type ProposalInput } from '../network-client.js';

export async function runProposalCommand(opts: { profile?: string }): Promise<void> {
    const config = loadConfig();
    const profile = resolveProfile(config, opts.profile);
    const client = new NetworkClient(profile).withSigner();

    let state = await client.getNetworkState();

    // eslint-disable-next-line no-constant-condition
    while (true) {
        const isCommitteeMember = state.curNodes.some(
            n => n.toStringLong() === profile.accountAddr,
        );

        // Fetch proposal details for the list view
        const proposalItems = await Promise.all(
            state.pendingProposals.map(async addr => {
                try {
                    const ps = await client.getProposalState(addr);
                    return {
                        name: `${proposalLabel(ps.proposal)}  (${ps.voters.length}/${state.curThreshold} votes)`,
                        value: addr.toStringLong(),
                    };
                } catch {
                    return { name: addr.toStringLong(), value: addr.toStringLong() };
                }
            }),
        );

        if (state.isEpochChanging()) {
            console.log('  ⚠  Epoch change in progress — no new proposals until next epoch\n');
        }

        const selected = await select<string>({
            message: `Proposals  (epoch ${state.epoch})`,
            choices: [
                ...proposalItems,
                { name: '+ Create new proposal', value: '__new__' },
                { name: '← Exit',                value: '__exit__' },
            ],
        });

        if (selected === '__exit__') return;

        if (selected === '__new__') {
            if (!isCommitteeMember) {
                console.log('\n  Only current committee members can create proposals.\n');
            } else if (state.isEpochChanging()) {
                console.log('\n  Cannot create proposals while epoch change is in progress.\n');
            } else {
                const proposal = await buildProposal(state);
                if (proposal) {
                    console.log('\n  Submitting proposal...');
                    const { hash, proposalAddr } = await client.submitNewProposal(proposal);
                    console.log(`  ✓ Proposal submitted (txn: ${hash})`);
                    if (proposalAddr) {
                        console.log(`  Proposal address: ${proposalAddr}`);
                        console.log('  Share this address in your coordination channel so committee members can approve.\n');
                    }
                }
            }
            state = await client.getNetworkState();
            continue;
        }

        // Proposal detail view
        const addr = AccountAddress.fromString(selected);
        try {
            const ps = await client.getProposalState(addr);
            printProposalDetails(ps, addr, state.curThreshold, config.profiles);

            const alreadyVoted = ps.voters.some(v => v.toStringLong() === profile.accountAddr);
            const canApprove = isCommitteeMember && !alreadyVoted && !ps.executed;

            type DetailAction = 'approve' | 'back';
            const action = await select<DetailAction>({
                message: 'Action',
                choices: [
                    ...(canApprove ? [{ name: 'Approve', value: 'approve' as DetailAction }] : []),
                    { name: '← Back', value: 'back' },
                ],
            });

            if (action === 'approve') {
                const ok = await confirm({ message: 'Send approval transaction?', default: true });
                if (ok) {
                    console.log('\n  Submitting approval...');
                    const hash = await client.submitApproveProposal(addr);
                    console.log(`  ✓ Approved (txn: ${hash})\n`);
                }
            }
        } catch (e) {
            console.error(`\n  Could not fetch proposal: ${e}\n`);
        }

        state = await client.getNetworkState();
    }
}

function proposalLabel(p: aceNetwork.ProposalVariant): string {
    switch (p.kind) {
        case 'CommitteeChange':
            return `CommitteeChange  nodes=[${p.nodes.map(a => shortAddr(a.toStringLong())).join(', ')}]  threshold=${p.threshold}`;
        case 'ResharingIntervalUpdate':
            return `ResharingIntervalUpdate  interval=${p.newIntervalSecs}s`;
        case 'NewSecret':
            return `NewSecret  scheme=${p.scheme}`;
        case 'SecretDeactivation':
            return `SecretDeactivation  keypair=${shortAddr(p.originalDkgAddr.toStringLong())}`;
    }
}

function printProposalDetails(
    ps: aceNetwork.ProposalState,
    addr: AccountAddress,
    threshold: number,
    profiles: Record<string, { accountAddr: string; name: string }>,
): void {
    console.log();
    console.log(`  Proposal : ${addr.toStringLong()}`);
    console.log(`  Epoch    : ${ps.epoch}`);
    console.log(`  Proposer : ${addrWithName(ps.proposer.toStringLong(), profiles)}`);
    console.log(`  Type     : ${ps.proposal.kind}`);
    switch (ps.proposal.kind) {
        case 'CommitteeChange':
            console.log('  Nodes    :');
            for (const n of ps.proposal.nodes) console.log(`    ${addrWithName(n.toStringLong(), profiles)}`);
            console.log(`  Threshold: ${ps.proposal.threshold}`);
            break;
        case 'ResharingIntervalUpdate':
            console.log(`  Interval : ${ps.proposal.newIntervalSecs}s`);
            break;
        case 'NewSecret':
            console.log(`  Scheme   : ${ps.proposal.scheme}  (${schemeDesc(ps.proposal.scheme)})`);
            break;
        case 'SecretDeactivation':
            console.log(`  Keypair  : ${ps.proposal.originalDkgAddr.toStringLong()}`);
            break;
    }
    console.log(`  Votes    : ${ps.voters.length}/${threshold}`);
    for (const v of ps.voters) console.log(`    ${addrWithName(v.toStringLong(), profiles)}`);
    console.log(`  Executed : ${ps.executed}`);
    console.log();
}

async function buildProposal(state: aceNetwork.State): Promise<ProposalInput | null> {
    type ProposalKind = ProposalInput['kind'] | 'cancel';
    const kind = await select<ProposalKind>({
        message: 'Proposal type',
        choices: [
            { name: 'NewSecret — generate a new keypair',               value: 'NewSecret' },
            { name: 'CommitteeChange — change the node set/threshold',  value: 'CommitteeChange' },
            { name: 'ResharingIntervalUpdate — change epoch duration',  value: 'ResharingIntervalUpdate' },
            { name: 'SecretDeactivation — deactivate a keypair',        value: 'SecretDeactivation' },
            { name: '← Cancel',                                          value: 'cancel' },
        ],
    });

    if (kind === 'cancel') return null;

    switch (kind) {
        case 'NewSecret': {
            const scheme = await select<number>({
                message: 'Scheme',
                choices: [
                    { name: '0 — BF BLS12-381 (short public key)', value: 0 },
                    { name: '1 — BF BLS12-381 (short identity)',   value: 1 },
                ],
            });
            return { kind: 'NewSecret', scheme };
        }

        case 'CommitteeChange': {
            console.log('\nCurrent committee:');
            for (const n of state.curNodes) console.log(`  ${n.toStringLong()}`);
            console.log();
            const raw = await input({
                message: 'New node addresses (comma-separated)',
                validate: v => {
                    const parts = v.split(',').map(s => s.trim()).filter(Boolean);
                    if (parts.length === 0) return 'Enter at least one address';
                    for (const p of parts) {
                        try { AccountAddress.fromString(p); } catch { return `Invalid address: ${p}`; }
                    }
                    return true;
                },
            });
            const nodes = raw.split(',').map(s => AccountAddress.fromString(s.trim()));
            const thresholdStr = await input({
                message: `Threshold (2 ≤ t ≤ ${nodes.length}, 2t > ${nodes.length})`,
                validate: v => {
                    const t = parseInt(v, 10);
                    if (isNaN(t) || t < 2 || t > nodes.length || 2 * t <= nodes.length) {
                        return `Threshold must satisfy 2 ≤ t ≤ n and 2t > n`;
                    }
                    return true;
                },
            });
            return { kind: 'CommitteeChange', nodes, threshold: parseInt(thresholdStr, 10) };
        }

        case 'ResharingIntervalUpdate': {
            const secsStr = await input({
                message: 'New resharing interval (seconds, min 30)',
                validate: v => {
                    const n = parseInt(v, 10);
                    return (!isNaN(n) && n >= 30) || 'Must be at least 30 seconds';
                },
            });
            return { kind: 'ResharingIntervalUpdate', newIntervalSecs: BigInt(secsStr) };
        }

        case 'SecretDeactivation': {
            if (state.secrets.length > 0) {
                console.log('\nActive keypairs (original DKG session address = keypair ID):');
                for (const s of state.secrets) console.log(`  ${s.toStringLong()}`);
                console.log();
            } else {
                console.log('\nNo active keypairs found.\n');
                return null;
            }
            const addr = await input({
                message: 'Original DKG session address (keypair ID)',
                validate: v => {
                    try { AccountAddress.fromString(v.trim()); return true; } catch { return 'Invalid address'; }
                },
            });
            return { kind: 'SecretDeactivation', originalDkgAddr: AccountAddress.fromString(addr.trim()) };
        }
    }
}

function addrWithName(addr: string, profiles: Record<string, { accountAddr: string; name: string }>): string {
    const match = Object.values(profiles).find(p => p.accountAddr === addr);
    return match ? `${addr}  "${match.name}"` : addr;
}

function shortAddr(addr: string): string {
    return `${addr.slice(0, 8)}...${addr.slice(-4)}`;
}

function schemeDesc(scheme: number): string {
    return scheme === 0 ? 'BF BLS12-381 short-pubkey' : scheme === 1 ? 'BF BLS12-381 short-identity' : 'unknown';
}
