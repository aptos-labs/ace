// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'fs';
import { parse as parseToml } from 'smol-toml';
import { AccountAddress } from '@aptos-labs/ts-sdk';
import { network as aceNetwork } from '@aptos-labs/ace-sdk';

import { buildFromEditor } from '../editor.js';
import type { ProposalInput } from '../network-client.js';

// ── Template generation ───────────────────────────────────────────────────────

function pad(n: bigint | number, width = 20): string {
    return String(n).padStart(width);
}

function generateTemplate(state: aceNetwork.State): string {
    const nodesLines = state.curNodes
        .map(n => `    "${n.toStringLong()}",`)
        .join('\n');

    const secretsLines = state.secrets.length > 0
        ? state.secrets
            .map(s => `    "${s.currentSession.toStringLong()}",  # ${s.schemeName()} — keypair id: ${s.keypairId.toStringLong()}`)
            .join('\n')
        : '';

    return [
        `# ACE Epoch Proposal — generated from epoch ${state.epoch}`,
        `# Edit this file, save, and close your editor to validate and submit.`,
        `# To cancel: delete all content, or quit your editor with a non-zero exit (e.g. :cq in vim).`,
        ``,
        `# Required. A human-readable summary shown in the voting UI.`,
        `description = ""`,
        ``,
        `# ── Committee ─────────────────────────────────────────────────────────────`,
        `# Comment out a node to remove it from the next epoch.`,
        `# Append an address to add a new node (must have a registered PKE key).`,
        `# Constraint: threshold >= 2, 2*threshold > n, threshold <= n`,
        `nodes = [`,
        nodesLines,
        `]`,
        `threshold = ${state.curThreshold}`,
        ``,
        `# ── Epoch Duration ────────────────────────────────────────────────────────`,
        `# In microseconds. Current value: ${state.epochDurationMicros}`,
        `epoch_duration_micros = ${state.epochDurationMicros}`,
        ``,
        `# ── Secrets ───────────────────────────────────────────────────────────────`,
        `# secrets_to_retain: existing secrets carried into the next epoch.`,
        `# Comment out a secret to permanently deactivate it.`,
        state.secrets.length > 0
            ? `secrets_to_retain = [\n${secretsLines}\n]`
            : `secrets_to_retain = []`,
        ``,
        `# new_secrets: generate a new DKG for each listed scheme code.`,
        `# Supported schemes: 0 = bls12381_g1`,
        `new_secrets = []`,
        ``,
    ].join('\n');
}

// ── TOML → ProposalInput ──────────────────────────────────────────────────────

function parseAddr(raw: unknown, field: string): AccountAddress {
    if (typeof raw !== 'string') throw new Error(`${field}: expected a string address, got ${typeof raw}`);
    try {
        return AccountAddress.fromString(raw);
    } catch {
        throw new Error(`${field}: invalid address "${raw}"`);
    }
}

function parseU64(raw: unknown, field: string): bigint {
    if (typeof raw === 'number') return BigInt(Math.trunc(raw));
    if (typeof raw === 'bigint') return raw;
    throw new Error(`${field}: expected a number, got ${typeof raw}`);
}

function parseU8(raw: unknown, field: string): number {
    if (typeof raw !== 'number') throw new Error(`${field}: expected a number, got ${typeof raw}`);
    if (!Number.isInteger(raw) || raw < 0 || raw > 255) throw new Error(`${field}: must be an integer 0–255`);
    return raw;
}

function tomlToProposalInput(doc: Record<string, unknown>, targetEpoch: number): ProposalInput {
    const description = doc['description'];
    if (typeof description !== 'string' || description.trim() === '')
        throw new Error('description: required and must be non-empty');
    if (description.length > 1024)
        throw new Error(`description: exceeds 1024 bytes (got ${description.length})`);

    const rawNodes = doc['nodes'];
    if (!Array.isArray(rawNodes)) throw new Error('nodes: must be an array of addresses');
    const nodes = rawNodes.map((v, i) => parseAddr(v, `nodes[${i}]`));

    const threshold = parseU64(doc['threshold'], 'threshold');
    const n = BigInt(nodes.length);
    if (threshold < 2n || 2n * threshold <= n || threshold > n)
        throw new Error(`threshold: must satisfy threshold >= 2, 2*threshold > ${n}, threshold <= ${n} (got ${threshold})`);

    const epochDurationMicros = parseU64(doc['epoch_duration_micros'], 'epoch_duration_micros');
    if (epochDurationMicros < 30_000_000n)
        throw new Error('epoch_duration_micros: must be at least 30_000_000 (30 seconds)');

    const rawRetain = doc['secrets_to_retain'];
    if (!Array.isArray(rawRetain)) throw new Error('secrets_to_retain: must be an array of addresses');
    const secretsToRetain = rawRetain.map((v, i) => parseAddr(v, `secrets_to_retain[${i}]`));

    const rawNew = doc['new_secrets'];
    if (!Array.isArray(rawNew)) throw new Error('new_secrets: must be an array of scheme numbers');
    const newSecrets = rawNew.map((v, i) => parseU8(v, `new_secrets[${i}]`));

    return {
        nodes,
        threshold: Number(threshold),
        epochDurationMicros,
        secretsToRetain,
        newSecrets,
        description: description.trim(),
        targetEpoch,
    };
}

// ── Public API ────────────────────────────────────────────────────────────────

/**
 * Build a ProposalInput from a pre-existing TOML file (skips editor).
 * Used when the user passes a file path to `proposal new`.
 */
export async function proposalFromFile(filePath: string, state: aceNetwork.State): Promise<ProposalInput | null> {
    let content: string;
    try {
        content = readFileSync(filePath, 'utf8');
    } catch (e) {
        throw new Error(`Cannot read file "${filePath}": ${(e as Error).message}`);
    }
    return parseAndValidate(content, state);
}

/**
 * Open $EDITOR with a pre-filled TOML template, then parse and return the result.
 * Returns null if the user cancelled (empty file or non-zero editor exit).
 */
export async function buildProposalFor(state: aceNetwork.State): Promise<ProposalInput | null> {
    return buildFromEditor(generateTemplate(state), c => parseAndValidate(c, state), { fileTag: 'proposal' });
}

function parseAndValidate(content: string, state: aceNetwork.State): ProposalInput | null {
    if (content.trim() === '') {
        console.log('File is empty — cancelled.');
        return null;
    }

    let doc: Record<string, unknown>;
    try {
        doc = parseToml(content) as Record<string, unknown>;
    } catch (e) {
        throw new Error(`TOML parse error: ${(e as Error).message}`);
    }

    const proposal = tomlToProposalInput(doc, state.epoch);

    // Cross-check secrets_to_retain against on-chain active secrets.
    const activeSessions = new Set(state.secrets.map(s => s.currentSession.toStringLong()));
    for (const addr of proposal.secretsToRetain) {
        if (!activeSessions.has(addr.toStringLong()))
            throw new Error(`secrets_to_retain: "${addr.toStringLong()}" is not an active secret`);
    }

    return proposal;
}
