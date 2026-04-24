// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { loadConfig, resolveProfile } from '../config.js';
import { NetworkClient } from '../network-client.js';

export async function runNetworkStatus(opts: { profile?: string }): Promise<void> {
    const config = loadConfig();
    const profile = resolveProfile(config, opts.profile);
    const client = new NetworkClient(profile);

    process.stdout.write('Fetching network state...\n\n');
    const state = await client.getNetworkState();

    const nowMicros = BigInt(Date.now()) * 1000n;
    const elapsedMs = Number((nowMicros - state.epochStartTimeMicros) / 1000n);
    const durationMs = Number(state.epochDurationMicros / 1000n);
    const remainingMs = Math.max(0, durationMs - elapsedMs);

    console.log(`Network  : ${profile.aceAddr}`);
    console.log(`Epoch    : ${state.epoch}`);

    if (state.isEpochChanging()) {
        console.log(`Timer    : epoch change in progress`);
        console.log(`           session: ${state.epochChangeInfo!.session.toStringLong()}`);
    } else if (elapsedMs >= durationMs) {
        console.log(`Timer    : expired — auto-reshare pending (call \`network::touch\`)`);
    } else {
        console.log(`Timer    : started ${fmtDuration(elapsedMs)} ago, ${fmtDuration(remainingMs)} until auto-reshare`);
    }
    console.log();

    console.log(`Committee (threshold ${state.curThreshold} of ${state.curNodes.length}):`);
    for (const node of state.curNodes) {
        const addr = node.toStringLong();
        const localName = Object.values(config.profiles).find(p => p.accountAddr === addr)?.name;
        const suffix = [
            localName ? `"${localName}"` : '',
            addr === profile.accountAddr ? '← you' : '',
        ].filter(Boolean).join('  ');
        console.log(`  ${addr}${suffix ? '  ' + suffix : ''}`);
    }
    console.log();

    if (state.secrets.length === 0) {
        console.log('Keypairs : none');
    } else {
        console.log(`Keypairs (${state.secrets.length}):`);
        for (const s of state.secrets) {
            console.log(`  ${s.toStringLong()}`);
        }
    }
    console.log();

    if (state.pendingProposals.length === 0) {
        console.log('Pending proposals: none');
    } else {
        console.log(`Pending proposals (${state.pendingProposals.length}):`);
        for (const p of state.pendingProposals) {
            try {
                const ps = await client.getProposalState(p);
                const label = ps.proposal.kind;
                console.log(`  ${p.toStringLong()}  ${label}  ${ps.voters.length}/${state.curThreshold} votes`);
            } catch {
                console.log(`  ${p.toStringLong()}`);
            }
        }
    }
    console.log();
}

function fmtDuration(ms: number): string {
    if (ms < 60_000)     return `${Math.round(ms / 1000)}s`;
    if (ms < 3_600_000)  return `${Math.round(ms / 60_000)}m`;
    return `${Math.round(ms / 3_600_000)}h`;
}
