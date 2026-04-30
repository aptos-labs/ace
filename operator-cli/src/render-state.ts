// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { network as aceNetwork } from '@aptos-labs/ace-sdk';
import type { TrackedNode } from './config.js';
import type { DiffRow } from './deployment-check.js';
import { deriveRpcLabel } from './config.js';

const R = '\x1b[0m', D = '\x1b[2m', B = '\x1b[1m';
const G = '\x1b[32m', E = '\x1b[31m', C = '\x1b[36m', Y = '\x1b[33m';

function shortAddr(addr: string): string {
    return `${addr.slice(0, 10)}...${addr.slice(-6)}`;
}

function addrLabel(addr: string, profiles: Record<string, TrackedNode>, rpcUrl: string, aceAddr: string): string {
    const match = Object.values(profiles).find(n => n.accountAddr === addr && n.rpcUrl === rpcUrl && n.aceAddr === aceAddr);
    return match?.alias ? `${addr}  ${D}(${match.alias})${R}` : addr;
}

function epochTimerStr(state: aceNetwork.State): string {
    if (state.isEpochChanging()) return `${Y}⚠ epoch change in progress${R}`;
    const nowMs = Date.now();
    const startMs = Number(state.epochStartTimeMicros / 1000n);
    const durationMs = Number(state.epochDurationMicros / 1000n);
    const remainingMs = durationMs - (nowMs - startMs);
    if (remainingMs <= 0) return `${Y}epoch expired${R}`;
    const s = Math.round(remainingMs / 1000);
    if (s < 60)   return `${s}s remaining`;
    if (s < 3600) return `${Math.round(s / 60)}m remaining`;
    return `${Math.round(s / 3600)}h remaining`;
}

function proposalDesc(p: aceNetwork.ProposedEpochConfig): string {
    return p.description || `${p.nodes.length} nodes, threshold ${p.threshold}`;
}

/**
 * Render on-chain network state as a string.
 * profiles: loaded config.nodes — used to annotate committee addresses with aliases.
 */
export function renderNetworkState(
    state: aceNetwork.State,
    profiles: Record<string, TrackedNode>,
    rpcUrl: string,
    aceAddr: string,
): string {
    const lines: string[] = [];

    const networkLabel = deriveRpcLabel(rpcUrl);
    lines.push(`${B}ACE Network${R}  ${networkLabel}  |  ${B}Epoch ${state.epoch}${R}  ${epochTimerStr(state)}`);
    lines.push(`Contract: ${aceAddr}`);
    lines.push('');

    // Committee
    lines.push(`${B}Committee${R}  (${state.curNodes.length} nodes, threshold ${state.curThreshold})`);
    for (const n of state.curNodes) {
        lines.push(`  ${addrLabel(n.toStringLong(), profiles, rpcUrl, aceAddr)}`);
    }
    lines.push('');

    // Keypairs
    if (state.secrets.length > 0) {
        lines.push(`${B}Keypairs${R}  (${state.secrets.length})`);
        for (const s of state.secrets) {
            lines.push(`  ${s.currentSession.toStringLong()}  ${D}${s.schemeName()} — keypair id: ${s.keypairId.toStringLong()}${R}`);
        }
        lines.push('');
    }

    // Proposals
    const active = state.activeProposals();
    if (active.length === 0) {
        lines.push(`${D}No active proposals.${R}`);
    } else {
        lines.push(`${B}Active Proposals${R}  (${active.length})`);
        for (const pv of active) {
            const sess = pv.votingSession.toStringLong();
            lines.push('');
            lines.push(`  Session  : ${C}${sess}${R}`);
            lines.push(`  Proposal : ${proposalDesc(pv.proposal)}`);
            for (const n of pv.proposal.nodes) {
                lines.push(`    ${addrLabel(n.toStringLong(), profiles, rpcUrl, aceAddr)}`);
            }
            const passed = pv.votingPassed ? `${G}yes${R}` : 'no';
            lines.push(`  Votes    : ${pv.voteCount()}/${state.curThreshold}  passed: ${passed}`);
            lines.push('');
            lines.push(`  ${D}→ ace vote ${sess} [--profile <alias>]${R}`);
        }
    }

    return lines.join('\n');
}

const MASK = '••••••••';

/**
 * Render full node status: profile credentials + committee membership + deployment diff.
 */
export function renderNodeStatus(
    nodeKey: string,
    node: TrackedNode,
    state: aceNetwork.State | Error,
    deployDiff: DiffRow[] | Error | null,
    profiles: Record<string, TrackedNode>,
    reveal = false,
): string {
    const lines: string[] = [];
    const secret = (v: string | undefined) => v ? (reveal ? v : MASK) : `${D}(not set)${R}`;
    const row = (label: string, value: string) => `  ${label.padEnd(14)}: ${value}`;

    // Header
    const label = node.alias ?? shortAddr(node.accountAddr);
    lines.push(`${B}Node: ${label}${R}  ${D}(${nodeKey})${R}`);
    lines.push('');

    // Credentials
    lines.push(row('account addr',  node.accountAddr));
    lines.push(row('account sk',    secret(node.accountSk)));
    lines.push(row('PKE enc key',   node.pkeEk ?? `${D}(not set)${R}`));
    lines.push(row('PKE dec key',   secret(node.pkeDk)));
    lines.push(row('endpoint',      node.endpoint ?? `${D}(not set)${R}`));
    lines.push('');
    lines.push(row('contract',      node.aceAddr));
    lines.push(row('RPC URL',       node.rpcUrl));
    lines.push(row('API key',       secret(node.rpcApiKey)));
    lines.push(row('gas key',       secret(node.gasStationKey)));
    if (!reveal) lines.push(`  ${D}(use --reveal to show secrets)${R}`);
    lines.push('');

    // Network state
    if (state instanceof Error) {
        lines.push(`${E}Network error: ${state.message}${R}`);
    } else {
        const networkLabel = deriveRpcLabel(node.rpcUrl);
        const isCommittee = state.curNodes.some(n => n.toStringLong() === node.accountAddr);
        const epochStatus = state.isEpochChanging() ? `${Y}epoch changing${R}` : '';

        lines.push(`${B}Network${R}  ${networkLabel}  |  Epoch ${state.epoch}  ${epochStatus || epochTimerStr(state)}`);
        lines.push(`  Status   : ${isCommittee ? `${G}active committee member${R}` : `${D}not in committee${R}`}`);

        const active = state.activeProposals();
        if (active.length > 0) {
            const myVotes = active.filter(pv => pv.hasVoted(node.accountAddr, state.curNodes)).length;
            lines.push(`  Proposals: ${active.length} active  (voted on ${myVotes}/${active.length})`);
            for (const pv of active) {
                const sess = pv.votingSession.toStringLong();
                const voted = pv.hasVoted(node.accountAddr, state.curNodes);
                const voteStr = voted ? `${G}voted${R}` : `${D}not voted${R}`;
                lines.push(`    ${C}${sess}${R}  ${voteStr}`);
                lines.push(`    ${D}→ ace vote ${sess} [--profile ${node.alias ?? '<alias>'}]${R}`);
            }
        } else {
            lines.push(`  Proposals: none`);
        }
    }
    lines.push('');

    // Deployment
    if (!node.platform) {
        lines.push(`${D}No deployment platform configured.${R}`);
    } else if (deployDiff instanceof Error) {
        const platformName = node.platform === 'gcp'
            ? `GCP Cloud Run (${node.gcp?.serviceName ?? '?'})`
            : `Docker (${node.docker?.containerName ?? '?'})`;
        lines.push(`${B}Deployment${R}  ${platformName}`);
        lines.push(`  ${E}Error: ${deployDiff.message}${R}`);
    } else if (deployDiff !== null) {
        const platformName = node.platform === 'gcp'
            ? `GCP Cloud Run (${node.gcp?.serviceName ?? '?'})`
            : `Docker (${node.docker?.containerName ?? '?'})`;
        const outdated = deployDiff.filter(r => !r.match);
        const statusStr = outdated.length === 0
            ? `${G}✓ all fields match${R}`
            : `${E}✗ ${outdated.length} field(s) outdated${R}`;

        lines.push(`${B}Deployment${R}  ${platformName}  ${statusStr}`);

        if (outdated.length > 0) {
            lines.push('');
            const FW = 12, VW = 36;
            lines.push(`  ${D}${'Field'.padEnd(FW)}  ${'Profile'.padEnd(VW)}  Running${R}`);
            lines.push('  ' + '─'.repeat(FW + VW * 2 + 6));
            for (const row of deployDiff) {
                const pv = row.secret ? '••••••••' : row.profile;
                const rv = row.secret ? '••••••••' : row.running;
                const tr = (s: string) => s.length > VW ? s.slice(0, VW - 3) + '...' : s.padEnd(VW);
                const line = `  ${row.field.padEnd(FW)}  ${tr(pv)}  ${tr(rv)}`;
                lines.push(row.match ? `${D}${line}${R}` : `${E}${line}  ✗${R}`);
            }
            lines.push('');
            lines.push(`  ${D}Run \`ace edit-node [--profile ${node.alias ?? '<alias>'}]\` to update profile and get new deploy command.${R}`);
        }
    }

    return lines.join('\n');
}
