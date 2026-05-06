// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from '@aptos-labs/ts-sdk';
import { network as aceNetwork } from '@aptos-labs/ace-sdk';
import { input } from '@inquirer/prompts';
import { resolveProfile } from '../resolve-profile.js';
import { NetworkClient } from '../network-client.js';
import { formatError } from '../format-error.js';
import { fmtSecs } from '../render-state.js';

const R = '\x1b[0m', D = '\x1b[2m', B = '\x1b[1m';
const G = '\x1b[32m', E = '\x1b[31m', C = '\x1b[36m', Y = '\x1b[33m';
const ADD = '\x1b[32m+\x1b[0m', REM = '\x1b[31m−\x1b[0m', EQ = ' ';

function shortAddr(addr: string): string {
    return `${addr.slice(0, 10)}...${addr.slice(-6)}`;
}

function fmtMicros(us: bigint): string {
    return fmtSecs(Number(us / 1_000_000n));
}

function fmtCountdown(state: aceNetwork.State): string {
    if (state.isEpochChanging()) return `${Y}epoch change in progress — proposal is now moot${R}`;
    const remainingMs = Number(state.epochDurationMicros / 1000n) - (Date.now() - Number(state.epochStartTimeMicros / 1000n));
    if (remainingMs <= 0) return `${Y}epoch overdue — will rotate on next touch()${R}`;
    const s = Math.ceil(remainingMs / 1000);
    const hh = String(Math.floor(s / 3600)).padStart(2, '0');
    const mm = String(Math.floor((s % 3600) / 60)).padStart(2, '0');
    const ss = String(s % 60).padStart(2, '0');
    return `${hh}:${mm}:${ss} until epoch rotates (proposal becomes moot)`;
}

function proposalDiff(p: aceNetwork.ProposedEpochConfig, state: aceNetwork.State): string[] {
    const lines: string[] = [];

    // Description
    lines.push(`  Description : ${p.description ? `${B}${p.description}${R}` : `${D}(none)${R}`}`);
    lines.push('');

    // Committee diff
    const curSet = new Set(state.curNodes.map(n => n.toStringLong()));
    const nxtSet = new Set(p.nodes.map(n => n.toStringLong()));
    const thresholdSame = p.threshold === state.curThreshold;
    lines.push(`  Committee   : ${p.nodes.length} nodes, threshold ${p.threshold}` +
        (thresholdSame ? '' : `  ${Y}(was ${state.curThreshold})${R}`));

    for (const n of state.curNodes) {
        const addr = n.toStringLong();
        const kept = nxtSet.has(addr);
        lines.push(`    ${kept ? EQ : REM} ${shortAddr(addr)}${kept ? '' : `  ${D}(removing)${R}`}`);
    }
    for (const n of p.nodes) {
        const addr = n.toStringLong();
        if (!curSet.has(addr)) {
            lines.push(`    ${ADD} ${shortAddr(addr)}  ${G}(new)${R}`);
        }
    }
    lines.push('');

    // Epoch duration diff
    const durSame = p.epochDurationMicros === state.epochDurationMicros;
    if (!durSame) {
        lines.push(`  Duration    : ${fmtMicros(p.epochDurationMicros)}  ${Y}(was ${fmtMicros(state.epochDurationMicros)})${R}`);
        lines.push('');
    }

    // Secrets diff
    const retainSet = new Set(p.secretsToRetain.map(a => a.toStringLong()));
    const droppedSecrets = state.secrets.filter(s => !retainSet.has(s.currentSession.toStringLong()));
    const hasSecretChanges = droppedSecrets.length > 0 || p.newSecrets.length > 0;

    if (hasSecretChanges) {
        lines.push('  Secrets');
        for (const s of state.secrets) {
            const kept = retainSet.has(s.currentSession.toStringLong());
            lines.push(`    ${kept ? EQ : REM} ${shortAddr(s.currentSession.toStringLong())}  ${D}${s.schemeName()} — keypair id: ${shortAddr(s.keypairId.toStringLong())}${R}${kept ? '' : `  ${E}(deactivating)${R}`}`);
        }
        for (const scheme of p.newSecrets) {
            lines.push(`    ${ADD} new DKG  ${G}${aceNetwork.schemeName(scheme)}${R}`);
        }
        lines.push('');
    }

    return lines;
}

function render(
    state: aceNetwork.State,
    proposalIdx: number,
    pv: aceNetwork.ProposalView,
    myAddr: string,
    canVote: boolean,
    status: string,
    lastAction: string,
): string {
    const lines: string[] = [];

    const isProposer = proposalIdx < state.curNodes.length
        ? state.curNodes[proposalIdx]!.toStringLong() === myAddr
        : false;
    const proposerLabel = proposalIdx < state.curNodes.length
        ? state.curNodes[proposalIdx]!.toStringLong()
        : 'admin';

    lines.push(`${B}  Proposal Review${R}`);
    lines.push('');

    const myRole = state.curNodes.some(n => n.toStringLong() === myAddr)
        ? `${G}committee member${R}`
        : `${D}observer${R}`;
    lines.push(`  You       : ${myAddr}  ${D}(${myRole})${R}`);
    lines.push('');

    // Proposed changes (diff view)
    lines.push(`  ${B}Proposed changes${R}  ${D}(epoch ${pv.proposal.targetEpoch} → ${pv.proposal.targetEpoch + 1})${R}`);
    lines.push(...proposalDiff(pv.proposal, state));

    lines.push(`  Proposer  : ${proposerLabel}${isProposer ? `  ${C}(you)${R}` : ''}`);
    lines.push('');

    // Vote tally
    const voteCount = pv.voteCount();
    const passed = pv.votingPassed;
    const tallyColor = passed ? G : '';
    lines.push(`  Votes     : ${tallyColor}${voteCount} / ${state.curThreshold}${R}  (${state.curNodes.length} committee members)`);
    lines.push('');
    for (let i = 0; i < state.curNodes.length; i++) {
        const addr = state.curNodes[i]!.toStringLong();
        const voted = pv.votes[i] ?? false;
        const isSelf = addr === myAddr;
        const mark = voted ? `${G}✓${R}` : `${D}–${R}`;
        const selfTag = isSelf ? `  ${C}← you${R}` : '';
        lines.push(`    ${mark}  ${shortAddr(addr)}${selfTag}`);
    }
    lines.push('');

    lines.push(`  ${fmtCountdown(state)}`);
    lines.push('');

    if (status) lines.push(`  ${status}`);
    if (lastAction) lines.push(`  ${lastAction}`);
    lines.push('');

    if (canVote) {
        lines.push(`  ${B}[V]${R} Vote   ${D}[Q] Quit${R}`);
    } else {
        lines.push(`  ${D}[Q] Quit${R}`);
    }

    return lines.join('\n');
}

export async function reviewProposalCommand(opts: { session?: string; profile?: string; account?: string }): Promise<void> {
    const sessionStr = opts.session
        ?? (await input({ message: 'Voting session address' })).trim();

    let addr: AccountAddress;
    try {
        addr = AccountAddress.fromString(sessionStr);
    } catch {
        console.error(`Invalid session address: ${sessionStr}`);
        process.exit(1);
    }

    const { node } = resolveProfile(opts.profile, opts.account);
    const client = NetworkClient.fromNode(node);
    const myAddr = node.accountAddr;

    process.stdout.write('\x1b[?1049h');
    process.stdout.write('\x1b[?25l');

    let running = true;
    let voting = false;

    if (process.stdin.isTTY) process.stdin.setRawMode(true);
    process.stdin.resume();
    process.stdin.setEncoding('utf8');

    const restore = () => {
        if (process.stdin.isTTY) process.stdin.setRawMode(false);
        process.stdin.pause();
        process.stdout.write('\x1b[?25h');
        process.stdout.write('\x1b[?1049l');
    };
    process.once('SIGINT',  () => { restore(); process.exit(0); });
    process.once('SIGTERM', () => { restore(); process.exit(0); });

    let state: aceNetwork.State | null = null;
    let proposalIdx = -1;
    let pv: aceNetwork.ProposalView | null = null;
    let fetchError = '';
    let lastAction = '';
    let lastFetch = 0;

    const fetchState = async () => {
        try {
            const s = await client.getNetworkState();
            const idx = s.proposals.findIndex(
                p => p !== null && p.votingSession.toStringLong() === addr.toStringLong(),
            );
            if (idx === -1) {
                fetchError = `${E}No active proposal found for this session address.${R}`;
                state = s;
                pv = null;
            } else {
                state = s;
                proposalIdx = idx;
                pv = s.proposals[idx]!;
                fetchError = '';
            }
        } catch (e) {
            fetchError = `${E}Fetch error: ${formatError(e)}${R}`;
        }
        lastFetch = Date.now();
    };

    process.stdin.on('data', (key: string) => {
        if (key === 'q' || key === 'Q' || key === '\x03') {
            running = false;
        } else if ((key === 'v' || key === 'V') && !voting) {
            if (state && pv && canVoteNow()) {
                voting = true;
                lastAction = `${D}Submitting vote...${R}`;
                client.submitVote(addr)
                    .then(hash => {
                        lastAction = `${G}✓ Vote submitted  (txn: ${hash.slice(0, 10)}...)${R}`;
                        return fetchState();
                    })
                    .catch(e => {
                        lastAction = `${E}✗ Vote failed: ${formatError(e)}${R}`;
                    })
                    .finally(() => { voting = false; });
            }
        }
    });

    const canVoteNow = (): boolean => {
        if (!state || !pv) return false;
        if (pv.votingPassed) return false;
        if (state.isEpochChanging()) return false;
        const myIdx = state.curNodes.findIndex(n => n.toStringLong() === myAddr);
        if (myIdx === -1) return false;
        if (myIdx === proposalIdx) return false;
        if (pv.votes[myIdx]) return false;
        return true;
    };

    const statusLine = (): string => {
        if (fetchError) return fetchError;
        if (!state || !pv) return `${D}Loading...${R}`;
        if (pv.votingPassed) return `${G}✓ Proposal passed${R}`;
        if (state.isEpochChanging()) return `${Y}Epoch change in progress${R}`;
        const myIdx = state.curNodes.findIndex(n => n.toStringLong() === myAddr);
        if (myIdx === -1) return `${D}You are not a committee member — observer only${R}`;
        if (myIdx === proposalIdx) return `${C}You are the proposer (auto-voted)${R}`;
        if (pv.votes[myIdx]) return `${G}You already voted${R}`;
        return '';
    };

    await fetchState();

    try {
        while (running) {
            if (Date.now() - lastFetch >= 3000) await fetchState();

            const content = (state && pv)
                ? render(state, proposalIdx, pv, myAddr, canVoteNow(), statusLine(), lastAction)
                : `  ${fetchError || `${D}Loading...${R}`}\n\n  ${D}[Q] Quit${R}`;

            process.stdout.write('\x1b[H\x1b[2J');
            process.stdout.write('\n' + content + '\n');

            await new Promise(r => setTimeout(r, 250));
        }
    } finally {
        restore();
    }
}
