// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { input, confirm } from '@inquirer/prompts';
import {
    createPrompt, useState, useKeypress,
    isUpKey, isDownKey, isEnterKey,
} from '@inquirer/core';
import { escSelect, isEscapeKey, useResizeClear } from '../esc-select.js';
import { timedSelect } from '../timed-select.js';
import { AccountAddress } from '@aptos-labs/ts-sdk';
import { network as aceNetwork } from '@aptos-labs/ace-sdk';
import { loadConfig, type TrackedNode } from '../config.js';
import { NetworkClient, type ProposalInput } from '../network-client.js';

export async function runProposalCommand(node: TrackedNode): Promise<void> {
    const client = NetworkClient.fromNode(node);
    const activeAddr = node.accountAddr;

    let state: aceNetwork.State;
    try {
        state = await client.getNetworkState();
    } catch (e) {
        const msg = String((e as any)?.message ?? e);
        const notFound = msg.includes('resource_not_found') || msg.includes('RESOURCE_DOES_NOT_EXIST') || msg.includes('NOT_FOUND') || (e as any)?.data?.vm_error_code === 4008;
        console.log(notFound ? '\n  Network not initialized.\n' : `\n  Error: ${msg}\n`);
        return;
    }

    while (true) {
        const isCommitteeMember = state.curNodes.some(n => n.toStringLong() === activeAddr);

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

        const selected = await timedSelect({
            message: `Proposals  (epoch ${state.epoch})`,
            getTimerLabel: () => epochTimer(state),
            choices: [
                ...proposalItems,
                { name: '+ Create new proposal', value: '__new__' },
                { name: '↺ Refresh',             value: '__refresh__' },
                { name: '← Back',                value: '__back__' },
            ],
        });

        if (selected === null || selected === '__back__') return;
        if (selected === '__refresh__') { state = await client.getNetworkState(); continue; }

        if (selected === '__new__') {
            if (!isCommitteeMember) {
                console.log('\n  Only current committee members can create proposals.\n');
            } else if (state.isEpochChanging()) {
                console.log('\n  Cannot create proposals while epoch change is in progress.\n');
            } else {
                const proposal = await buildProposal(state);
                if (proposal) {
                    console.log('\n  Submitting proposal...');
                    try {
                        const { hash, proposalAddr } = await client.submitNewProposal(proposal);
                        console.log(`  ✓ Proposal submitted (txn: ${hash})`);
                        if (proposalAddr) {
                            console.log(`  Proposal address: ${proposalAddr}`);
                            console.log('  Share this address with committee members so they can approve.');
                        }
                    } catch (e) {
                        console.error(`  ✗ Failed to submit proposal: ${e instanceof Error ? e.message : String(e)}`);
                    }
                    console.log();
                }
            }
            state = await client.getNetworkState();
            continue;
        }

        const addr = AccountAddress.fromString(selected);
        try {
            const ps = await client.getProposalState(addr);
            const cfg = loadConfig();

            const alreadyVoted = ps.voters.some(v => v.toStringLong() === activeAddr);
            const canApprove = isCommitteeMember && !alreadyVoted && !ps.executed;

            const action = await proposalDetailView({
                ps, addr, threshold: state.curThreshold,
                nodes: cfg.nodes, rpcUrl: node.rpcUrl, aceAddr: node.aceAddr, canApprove,
            });

            if (action === 'approve') {
                const ok = await confirm({ message: 'Send approval transaction?', default: true });
                if (ok) {
                    console.log('\n  Submitting approval...');
                    try {
                        const hash = await client.submitApproveProposal(addr);
                        console.log(`  ✓ Approved (txn: ${hash})`);
                    } catch (e) {
                        console.error(`  ✗ Failed to approve: ${e instanceof Error ? e.message : String(e)}`);
                    }
                    console.log();
                }
            }
        } catch (e) {
            console.error(`\n  Could not fetch proposal: ${e}\n`);
        }

        state = await client.getNetworkState();
    }
}

// ── Proposal detail view (createPrompt-based) ─────────────────────────────────

type ProposalDetailAction = 'approve' | 'back';

interface ProposalDetailViewConfig {
    ps: aceNetwork.ProposalState;
    addr: AccountAddress;
    threshold: number;
    nodes: Record<string, TrackedNode>;
    rpcUrl: string;
    aceAddr: string;
    canApprove: boolean;
}

const proposalDetailView: (cfg: ProposalDetailViewConfig) => Promise<ProposalDetailAction> =
    createPrompt<ProposalDetailAction, ProposalDetailViewConfig>((cfg, done) => {
        useResizeClear();
        const [cursor, setCursor] = useState(0);

        const { ps, addr, threshold, nodes, rpcUrl, aceAddr, canApprove } = cfg;

        const choices: Array<{ name: string; value: ProposalDetailAction }> = [
            ...(canApprove ? [{ name: 'Approve', value: 'approve' as ProposalDetailAction }] : []),
            { name: '← Back', value: 'back' as ProposalDetailAction },
        ];
        const safeCursor = Math.min(cursor, choices.length - 1);

        useKeypress(key => {
            if (isEscapeKey(key)) done('back');
            if (isUpKey(key))    setCursor(Math.max(0, safeCursor - 1));
            if (isDownKey(key))  setCursor(Math.min(choices.length - 1, safeCursor + 1));
            if (isEnterKey(key)) done(choices[safeCursor]!.value);
        });

        const lines: string[] = [];
        lines.push(`Proposal : ${addr.toStringLong()}`);
        lines.push(`Epoch    : ${ps.epoch}`);
        lines.push(`Proposer : ${addrWithName(ps.proposer.toStringLong(), nodes, rpcUrl, aceAddr)}`);
        lines.push(`Type     : ${ps.proposal.kind}`);

        switch (ps.proposal.kind) {
            case 'CommitteeChange':
                lines.push('Nodes    :');
                for (const n of ps.proposal.nodes) {
                    lines.push(`  ${addrWithName(n.toStringLong(), nodes, rpcUrl, aceAddr)}`);
                }
                lines.push(`Threshold: ${ps.proposal.threshold}`);
                break;
            case 'ResharingIntervalUpdate':
                lines.push(`Interval : ${ps.proposal.newIntervalSecs}s`);
                break;
            case 'NewSecret':
                lines.push(`Scheme   : ${ps.proposal.scheme}  (${schemeDesc(ps.proposal.scheme)})`);
                break;
            case 'SecretDeactivation':
                lines.push(`Keypair  : ${ps.proposal.originalDkgAddr.toStringLong()}`);
                break;
        }

        lines.push(`Votes    : ${ps.voters.length}/${threshold}`);
        for (const v of ps.voters) {
            lines.push(`  ${addrWithName(v.toStringLong(), nodes, rpcUrl, aceAddr)}`);
        }
        lines.push(`Executed : ${ps.executed}`);

        lines.push('');
        lines.push('─'.repeat(50));
        for (let i = 0; i < choices.length; i++) {
            lines.push(i === safeCursor ? `\x1b[36m❯ ${choices[i]!.name}\x1b[0m` : `  ${choices[i]!.name}`);
        }

        return lines.join('\n');
    });

function epochTimer(state: aceNetwork.State): string {
    if (state.isEpochChanging()) return 'epoch change in progress';
    const nowMs = Date.now();
    const startMs = Number(state.epochStartTimeMicros / 1000n);
    const durationMs = Number(state.epochDurationMicros / 1000n);
    const remainingMs = durationMs - (nowMs - startMs);
    if (remainingMs <= 0) return 'epoch expired';
    const s = Math.round(remainingMs / 1000);
    if (s < 60)   return `${s}s left`;
    if (s < 3600) return `${Math.round(s / 60)}m left`;
    return `${Math.round(s / 3600)}h left`;
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

async function buildProposal(state: aceNetwork.State): Promise<ProposalInput | null> {
    const kind = await escSelect({
        message: 'Proposal type',
        choices: [
            { name: 'NewSecret — generate a new keypair',               value: 'NewSecret' },
            { name: 'CommitteeChange — change the node set/threshold',  value: 'CommitteeChange' },
            { name: 'ResharingIntervalUpdate — change epoch duration',  value: 'ResharingIntervalUpdate' },
            { name: 'SecretDeactivation — deactivate a keypair',        value: 'SecretDeactivation' },
            { name: '← Cancel',                                          value: 'cancel' },
        ],
    });

    if (kind === null || kind === 'cancel') return null;

    switch (kind) {
        case 'NewSecret': {
            const scheme = await escSelect({
                message: 'Scheme',
                choices: [
                    { name: '0 — BF BLS12-381 (short public key)', value: '0' },
                    { name: '1 — BF BLS12-381 (short identity)',   value: '1' },
                ],
            });
            if (scheme === null) return null;
            return { kind: 'NewSecret', scheme: Number(scheme) };
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
                console.log('\nActive keypairs:');
                for (const s of state.secrets) console.log(`  ${s.toStringLong()}`);
                console.log();
            } else {
                console.log('\nNo active keypairs found.\n');
                return null;
            }
            const addr = await input({
                message: 'Keypair ID (original DKG session address)',
                validate: v => {
                    try { AccountAddress.fromString(v.trim()); return true; } catch { return 'Invalid address'; }
                },
            });
            return { kind: 'SecretDeactivation', originalDkgAddr: AccountAddress.fromString(addr.trim()) };
        }

        default: return null;
    }
}

function addrWithName(addr: string, nodes: Record<string, TrackedNode>, rpcUrl: string, aceAddr: string): string {
    const match = Object.values(nodes).find(n => n.accountAddr === addr && n.rpcUrl === rpcUrl && n.aceAddr === aceAddr);
    return match?.alias ? `${addr}  "${match.alias}"` : addr;
}

function shortAddr(addr: string): string {
    return `${addr.slice(0, 8)}...${addr.slice(-4)}`;
}

function schemeDesc(scheme: number): string {
    return scheme === 0 ? 'BF BLS12-381 short-pubkey' : scheme === 1 ? 'BF BLS12-381 short-identity' : 'unknown';
}
