// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { escSelect, escInput } from '../esc-select.js';
import { AccountAddress } from '@aptos-labs/ts-sdk';
import { network as aceNetwork } from '@aptos-labs/ace-sdk';
import { type ProposalInput } from '../network-client.js';

const RED = '\x1b[31m', R = '\x1b[0m';

/** null = go back to type selection */
type StepResult<T> = T | null;

async function collectNewSecret(): Promise<StepResult<ProposalInput>> {
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

async function collectCommitteeChange(state: aceNetwork.State): Promise<StepResult<ProposalInput>> {
    console.log('\nCurrent committee:');
    for (const n of state.curNodes) console.log(`  ${n.toStringLong()}`);
    console.log();

    // Phase A: collect addresses one by one.
    // Phase B: collect threshold.
    // Esc in phase A at index 0 → back to type selection.
    // Esc in phase A at index N → remove last address, re-prompt index N-1.
    // Esc in phase B → back to phase A (re-prompt for address N+1, empty to finish).

    const addrs: AccountAddress[] = [];
    let phase: 'addr' | 'threshold' = 'addr';
    let addrErr = '';
    let threshStr = '';
    let threshErr = '';

    while (true) {
        if (phase === 'addr') {
            const idx = addrs.length;
            const suffix = idx > 0 ? '  (empty to finish)' : '';
            if (addrErr) console.log(`  ${RED}${addrErr}${R}`);
            const r = await escInput({ message: `Address ${idx + 1}${suffix}`, default: '' });

            if (r === undefined) {
                // Esc: go back one address, or back to type selection if none entered yet
                if (idx === 0) return null;
                addrs.pop();
                addrErr = '';
                continue;
            }

            const trimmed = r.trim();
            if (trimmed === '') {
                if (idx === 0) { addrErr = 'Enter at least one address'; continue; }
                addrErr = '';
                phase = 'threshold';
                continue;
            }

            try {
                addrs.push(AccountAddress.fromString(trimmed));
                addrErr = '';
            } catch {
                addrErr = `Invalid address: ${trimmed}`;
            }
        } else {
            if (threshErr) console.log(`  ${RED}${threshErr}${R}`);
            const r = await escInput({
                message: `Threshold (2 ≤ t ≤ ${addrs.length}, 2t > ${addrs.length})`,
                default: threshStr,
            });
            if (r === undefined) { threshErr = ''; phase = 'addr'; continue; } // Esc → back to address list
            threshStr = r.trim();
            const t = parseInt(threshStr, 10);
            if (isNaN(t) || t < 2 || t > addrs.length || 2 * t <= addrs.length) {
                threshErr = `Must satisfy 2 ≤ t ≤ ${addrs.length} and 2t > ${addrs.length}`;
                continue;
            }
            return { kind: 'CommitteeChange', nodes: addrs, threshold: t };
        }
    }
}

async function collectResharingIntervalUpdate(): Promise<StepResult<ProposalInput>> {
    let secsStr = '';
    let secsErr = '';
    while (true) {
        if (secsErr) console.log(`  ${RED}${secsErr}${R}`);
        const r = await escInput({ message: 'New resharing interval (seconds, min 30)', default: secsStr });
        if (r === undefined) return null; // Esc → back to type selection
        secsStr = r.trim();
        const n = parseInt(secsStr, 10);
        if (isNaN(n) || n < 30) { secsErr = 'Must be at least 30 seconds'; continue; }
        return { kind: 'ResharingIntervalUpdate', newIntervalSecs: BigInt(secsStr) };
    }
}

async function collectSecretDeactivation(state: aceNetwork.State): Promise<StepResult<ProposalInput>> {
    if (state.secrets.length === 0) {
        console.log('No keypairs available to deactivate.');
        return null;
    }
    console.log('\nAvailable keypairs:');
    for (const [i, s] of state.secrets.entries()) console.log(`  [${i}] ${s.toStringLong()}`);
    console.log();

    let addrStr = '';
    let addrErr = '';
    while (true) {
        if (addrErr) console.log(`  ${RED}${addrErr}${R}`);
        const r = await escInput({ message: 'Keypair address (original DKG session address)', default: addrStr });
        if (r === undefined) return null; // Esc → back to type selection
        addrStr = r.trim();
        try {
            AccountAddress.fromString(addrStr);
            return { kind: 'SecretDeactivation', originalDkgAddr: AccountAddress.fromString(addrStr) };
        } catch { addrErr = 'Invalid address'; }
    }
}

export async function buildProposalFor(state: aceNetwork.State): Promise<ProposalInput | null> {
    while (true) {
        const kind = await escSelect({
            message: 'Proposal type',
            choices: [
                { name: 'NewSecret — generate a new keypair',              value: 'NewSecret' },
                { name: 'CommitteeChange — change the node set/threshold', value: 'CommitteeChange' },
                { name: 'ResharingIntervalUpdate — change epoch duration', value: 'ResharingIntervalUpdate' },
                { name: 'SecretDeactivation — deactivate a keypair',       value: 'SecretDeactivation' },
                { name: '← Cancel',                                         value: 'cancel' },
            ],
        });

        if (kind === null || kind === 'cancel') return null;

        let result: ProposalInput | null;
        switch (kind) {
            case 'NewSecret':                result = await collectNewSecret(); break;
            case 'CommitteeChange':          result = await collectCommitteeChange(state); break;
            case 'ResharingIntervalUpdate':  result = await collectResharingIntervalUpdate(); break;
            case 'SecretDeactivation':       result = await collectSecretDeactivation(state); break;
            default: return null;
        }

        if (result !== null) return result;
        // null → Esc was pressed, loop back to type selection
    }
}
