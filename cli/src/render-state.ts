// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { network as aceNetwork } from '@aptos-labs/ace-sdk';
import type { TrackedNode } from './config.js';
import type { DiffRow } from './deployment-check.js';
import { deriveRpcLabel } from './config.js';
import { CLI } from './cli-name.js';
import { isLocalNodeAlive } from './local-process.js';
import { secretInfoLabel, secretRequestLabel } from './secret-usage.js';

const R = '\x1b[0m', D = '\x1b[2m', B = '\x1b[1m';
const G = '\x1b[32m', E = '\x1b[31m', C = '\x1b[36m', Y = '\x1b[33m';

function shortAddr(addr: string): string {
    return `${addr.slice(0, 10)}...${addr.slice(-6)}`;
}

function renderDiffSection(lines: string[], heading: string | undefined, rows: DiffRow[]): void {
    if (rows.length === 0) return;
    lines.push('');
    if (heading) lines.push(`  ${B}${heading}${R}`);
    const FW = 12, VW = 36;
    lines.push(`  ${D}${'Field'.padEnd(FW)}  ${'Profile'.padEnd(VW)}  Running${R}`);
    lines.push('  ' + '─'.repeat(FW + VW * 2 + 6));
    for (const row of rows) {
        const pv = row.secret ? '••••••••' : row.profile;
        const rv = row.secret ? '••••••••' : row.running;
        const tr = (s: string) => s.length > VW ? s.slice(0, VW - 3) + '...' : s.padEnd(VW);
        const line = `  ${row.field.padEnd(FW)}  ${tr(pv)}  ${tr(rv)}`;
        lines.push(row.match ? `${D}${line}${R}` : `${E}${line}  ✗${R}`);
    }
}

export function deployLabel(node: TrackedNode): string {
    if (node.mode === 'metadata-management-only') return 'external runtime (metadata management only)';
    if (node.platform === 'gcp') {
        if (node.mode === 'microservices') {
            const h = node.gcp?.handlerServiceName ?? '?';
            const m = node.gcp?.maintainerServiceName ?? '?';
            return `GCP Cloud Run microservices (handler=${h}, maintainer=${m})`;
        }
        return `GCP Cloud Run (${node.gcp?.serviceName ?? '?'})`;
    }
    if (node.platform === 'gcp-vm') {
        const vm = node.gce?.instanceName ?? '?';
        const zone = node.gce?.zone ?? '?';
        return `GCP VM monolith (${vm}, ${zone})`;
    }
    if (node.platform === 'docker') return `Docker (${node.docker?.containerName ?? '?'})`;
    return 'local build';
}

function addrLabel(addr: string, profiles: Record<string, TrackedNode>, rpcUrl: string, aceAddr: string): string {
    const match = Object.values(profiles).find(n => n.accountAddr === addr && n.rpcUrl === rpcUrl && n.aceAddr === aceAddr);
    return match?.alias ? `${addr}  ${D}(${match.alias})${R}` : addr;
}

export function fmtSecs(s: number): string {
    if (s < 60)     return `${s}s`;
    if (s < 3600)   { const m = Math.floor(s / 60),  rs = s % 60;  return rs ? `${m}m ${rs}s` : `${m}m`; }
    if (s < 86400)  { const h = Math.floor(s / 3600), rm = Math.floor((s % 3600) / 60); return rm ? `${h}h ${rm}m` : `${h}h`; }
    const d = Math.floor(s / 86400), rh = Math.floor((s % 86400) / 3600);
    return rh ? `${d}d ${rh}h` : `${d}d`;
}

function epochTimerStr(state: aceNetwork.State): string {
    if (state.isEpochChanging()) return `${Y}⚠ epoch change in progress${R}`;
    const nowMs = Date.now();
    const startMs = Number(state.epochStartTimeMicros / 1000n);
    const durationMs = Number(state.epochDurationMicros / 1000n);
    const remainingMs = durationMs - (nowMs - startMs);
    if (remainingMs <= 0) return `${Y}epoch expired${R}`;
    const s = Math.ceil(remainingMs / 1000);
    return `${fmtSecs(s)} remaining`;
}

function proposalDesc(p: aceNetwork.ProposedEpochConfig): string {
    return p.description || `${p.nodes.length} nodes, threshold ${p.threshold}`;
}

/**
 * Lines summarising what would change if the proposal passes, computed as a delta against
 * current state. Returns nothing for fields that are unchanged so the output stays terse.
 */
function proposalChanges(
    p: aceNetwork.ProposedEpochConfig,
    state: aceNetwork.State,
    profiles: Record<string, TrackedNode>,
    rpcUrl: string,
    aceAddr: string,
): string[] {
    const out: string[] = [];

    // Committee delta — only show if changed.
    const cur = new Set(state.curNodes.map(n => n.toStringLong()));
    const nxt = new Set(p.nodes.map(n => n.toStringLong()));
    const added   = [...nxt].filter(a => !cur.has(a));
    const removed = [...cur].filter(a => !nxt.has(a));
    if (added.length > 0 || removed.length > 0) {
        out.push(`  Committee:`);
        for (const a of added)   out.push(`    ${G}+ ${addrLabel(a, profiles, rpcUrl, aceAddr)}${R}`);
        for (const a of removed) out.push(`    ${E}- ${addrLabel(a, profiles, rpcUrl, aceAddr)}${R}`);
    }

    // Threshold delta — only show if changed.
    if (p.threshold !== state.curThreshold) {
        out.push(`  Threshold: ${state.curThreshold} → ${G}${p.threshold}${R}`);
    }

    // Epoch duration delta — only show if changed.
    if (p.epochDurationMicros !== state.epochDurationMicros) {
        const fromS = Number(state.epochDurationMicros / 1_000_000n);
        const toS   = Number(p.epochDurationMicros / 1_000_000n);
        out.push(`  Epoch dur: ${fmtSecs(fromS)} → ${G}${fmtSecs(toS)}${R}`);
    }

    // Secrets delta.
    const retainSet = new Set(p.secretsToRetain.map(a => a.toStringLong()));
    const dropped = state.secrets.filter(s => !retainSet.has(s.currentSession.toStringLong()));
    if (dropped.length > 0) {
        out.push(`  Drop secrets:`);
        for (const s of dropped) {
            out.push(`    ${E}- keypair ${shortAddr(s.keypairId.toStringLong())}  (${secretInfoLabel(s)})${R}`);
        }
    }
    if (p.newSecrets.length > 0) {
        out.push(`  New secrets:`);
        for (const request of p.newSecrets) {
            out.push(`    ${G}+ fresh DKG  (${secretRequestLabel(request)})${R}`);
        }
    }

    return out;
}

/**
 * Render on-chain network state as a string.
 * profiles: loaded config.nodes — used to annotate committee addresses with aliases.
 * deployedVersion: optional Move-package version (read from `0x1::code::PackageRegistry`).
 */
export function renderNetworkState(
    state: aceNetwork.State,
    profiles: Record<string, TrackedNode>,
    rpcUrl: string,
    aceAddr: string,
    deployedVersion?: string | null,
): string {
    const lines: string[] = [];

    const networkLabel = deriveRpcLabel(rpcUrl);
    lines.push(`${B}ACE Network${R}  ${networkLabel}  |  ${B}Epoch ${state.epoch}${R}  ${epochTimerStr(state)}`);
    const versionTag = deployedVersion ? `  ${D}(v${deployedVersion})${R}` : '';
    lines.push(`Contract: ${aceAddr}${versionTag}`);
    lines.push('');

    // Committee
    lines.push(`${B}Committee${R}  (${state.curNodes.length} nodes, threshold ${state.curThreshold})`);
    for (const n of state.curNodes) {
        lines.push(`  ${addrLabel(n.toStringLong(), profiles, rpcUrl, aceAddr)}`);
    }
    lines.push('');

    // Keypairs — keypair_id is the permanent identifier apps encrypt against;
    // current_session is the latest DKG/DKR address for that lineage (changes each reshare).
    if (state.secrets.length > 0) {
        lines.push(`${B}Keypairs${R}  (${state.secrets.length})`);
        for (const s of state.secrets) {
            lines.push(`  ${s.keypairId.toStringLong()}  ${D}(${secretInfoLabel(s)})${R}`);
            lines.push(`  ${D}    last DKG/DKR: ${s.currentSession.toStringLong()}${R}`);
        }
        lines.push('');
    }

    // Proposals
    // Iterate over the raw `state.proposals` array (with indices) so we can identify the
    // proposer. The contract layout: proposals[0..n-1] are per-committee-member slots,
    // proposals[n] is the admin slot. (See contracts/network/sources/network.move:54.)
    const adminIdx = state.proposals.length - 1;
    const activeIdxs = state.proposals
        .map((p, i) => (p ? i : -1))
        .filter(i => i >= 0);
    if (activeIdxs.length === 0) {
        lines.push(`${D}No active proposals.${R}`);
    } else {
        lines.push(`${B}Active Proposals${R}  (${activeIdxs.length})`);
        for (const idx of activeIdxs) {
            const pv = state.proposals[idx]!;
            const sess = pv.votingSession.toStringLong();
            const proposerLine = idx === adminIdx
                ? `admin  ${D}(${aceAddr})${R}`
                : addrLabel(state.curNodes[idx]!.toStringLong(), profiles, rpcUrl, aceAddr);
            lines.push('');
            lines.push(`  Session  : ${C}${sess}${R}`);
            lines.push(`  Proposer : ${proposerLine}`);
            lines.push(`  Proposal : ${proposalDesc(pv.proposal)}`);
            for (const l of proposalChanges(pv.proposal, state, profiles, rpcUrl, aceAddr)) lines.push(l);
            const passed = pv.votingPassed ? `${G}yes${R}` : 'no';
            lines.push(`  Votes    : ${pv.voteCount()}/${state.curThreshold}  passed: ${passed}`);
            // Per-voter checkmarks (votes[i] aligned with state.curNodes[i]).
            // Pad the visible-width portion to "✗ not voted" (11 cols) BEFORE applying
            // ANSI color codes — otherwise padEnd would count escape bytes as visible chars.
            for (let i = 0; i < state.curNodes.length; i++) {
                const voted = pv.votes[i] === true;
                const visible = (voted ? '✓ voted' : '✗ not voted').padEnd(11);
                const mark = voted ? `${G}${visible}${R}` : `${D}${visible}${R}`;
                lines.push(`    ${mark}  ${addrLabel(state.curNodes[i]!.toStringLong(), profiles, rpcUrl, aceAddr)}`);
            }
            lines.push('');
            lines.push(`  ${D}→ ${CLI} proposal review -s ${sess} [--profile <alias>]${R}`);
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
    lines.push(row('sig verify',    node.sigPk ?? `${D}(not set)${R}`));
    lines.push(row('sig sign',      secret(node.sigSk)));
    lines.push(row('endpoint',      node.endpoint ?? `${D}(not set)${R}`));
    lines.push(row('node-msg URL',  node.nodeMsgEndpoint ?? `${D}(not set)${R}`));
    lines.push('');
    lines.push(row('contract',      node.aceAddr));
    lines.push(row('RPC URL',       node.rpcUrl));
    lines.push(row('VSS store',     node.vssStoreUrl ?? `${D}(not set)${R}`));
    if (node.gcp?.cloudSql) {
        lines.push(row('Cloud SQL', `${node.gcp.cloudSql.instanceName}/${node.gcp.cloudSql.databaseName}`));
    }
    lines.push(row('node-msg bind', node.nodeMsgListen ?? `${D}(not set)${R}`));
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
                lines.push(`    ${D}→ ${CLI} vote ${sess} [--profile ${node.alias ?? '<alias>'}]${R}`);
            }
        } else {
            lines.push(`  Proposals: none`);
        }
    }
    lines.push('');

    // Deployment / process status
    if (node.platform === 'local' && node.local) {
        const alive = node.local.pid ? isLocalNodeAlive(node.local.pid) : false;
        const procStatus = node.local.pid
            ? (alive ? `${G}running  pid=${node.local.pid}${R}` : `${E}stopped  (was pid=${node.local.pid})${R}`)
            : `${D}not started${R}`;
        lines.push(`${B}Process${R}  local build  ${procStatus}`);
        if (node.local.logFile) lines.push(`  Log: ${node.local.logFile}`);
        if (!alive) lines.push(`  ${D}Run \`${CLI} node edit\` to restart.${R}`);
    } else if (node.mode === 'metadata-management-only') {
        lines.push(`${B}Deployment${R}  ${deployLabel(node)}`);
        lines.push(`  ${D}Credentials and on-chain metadata are managed by this profile; runtime changes require the external deployment system.${R}`);
    } else if (!node.platform) {
        lines.push(`${D}No deployment platform configured.${R}`);
    } else if (deployDiff instanceof Error) {
        const platformName = deployLabel(node);
        lines.push(`${B}Deployment${R}  ${platformName}`);
        lines.push(`  ${E}Error: ${deployDiff.message}${R}`);
    } else if (deployDiff !== null) {
        const platformName = deployLabel(node);
        const outdated = deployDiff.filter(r => !r.match);
        const statusStr = outdated.length === 0
            ? `${G}✓ all fields match${R}`
            : `${E}✗ ${outdated.length} field(s) outdated${R}`;

        lines.push(`${B}Deployment${R}  ${platformName}  ${statusStr}`);

        if (outdated.length > 0) {
            const isMicro = deployDiff.some(r => r.service !== undefined);
            if (isMicro) {
                renderDiffSection(lines, '[maintainer]', deployDiff.filter(r => r.service === 'maintainer'));
                renderDiffSection(lines, '[handler]',    deployDiff.filter(r => r.service === 'handler'));
            } else {
                renderDiffSection(lines, undefined, deployDiff);
            }
            lines.push('');
            lines.push(`  ${D}Run \`${CLI} node edit [--profile ${node.alias ?? '<alias>'}]\` to update profile and get new deploy command.${R}`);
        }
    }

    return lines.join('\n');
}
