// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { input, confirm } from '@inquirer/prompts';
import {
    createPrompt, useState, useEffect, useKeypress,
    isUpKey, isDownKey, isEnterKey,
} from '@inquirer/core';
import { escSelect, isEscapeKey, useResizeClear } from '../esc-select.js';
import { execSync } from 'child_process';
import { readFileSync } from 'fs';
import {
    loadConfig, saveConfig, deriveRpcLabel, makeNodeKey,
    displayNode,
    type TrackedNode,
} from '../config.js';
import { NetworkClient } from '../network-client.js';
import { runOnboarding, dockerRunCmd } from '../onboarding.js';
import { selectImage } from '../docker-hub.js';
import { runProposalCommand } from './proposal.js';
import { network as aceNetwork } from '@aptos-labs/ace-sdk';

const BOX_W = 78;

function boxRow(label: string, value: string): string {
    const prefix  = label ? label.padEnd(10) : '          ';
    const content = prefix + value;
    const trimmed = content.length > BOX_W - 2 ? content.slice(0, BOX_W - 5) + '...' : content;
    return '│ ' + trimmed.padEnd(BOX_W - 2) + ' │';
}

function nodeListItem(node: TrackedNode, isDefault: boolean): string {
    const badge  = isDefault ? '  [default]' : '';
    const line1  = (node.alias ?? deriveRpcLabel(node.rpcUrl)) + badge;
    const top  = '┌' + '─'.repeat(BOX_W) + '┐';
    const rest = [
        boxRow('', line1),
        boxRow('contract', node.aceAddr),
        boxRow('account', node.accountAddr),
        '└' + '─'.repeat(BOX_W) + '┘',
    ].map(l => '  ' + l).join('\n');
    return top + '\n' + rest;
}

/** Returns the nodeKey set as session-active, if the user chose "Set as active". */
export async function runNodeCommand(): Promise<string | undefined> {
    let activatedKey: string | undefined;

    while (true) {
        console.clear();
        const config = loadConfig();
        const nodeEntries = Object.entries(config.nodes);

        const selected = await escSelect({
            message: 'Nodes',
            choices: [
                ...nodeEntries.map(([key, node]) => ({
                    name: nodeListItem(node, key === config.defaultNode),
                    value: key,
                })),
                { name: '+ Deploy new node',   value: '__new__' },
                { name: '  Import profile', value: '__import__' },
                { name: '← Back',           value: '__back__' },
            ],
        });

        if (selected === null || selected === '__back__') return activatedKey;

        if (selected === '__new__') {
            const cfg = loadConfig();
            const result = await runOnboarding(cfg);
            const cfg2 = loadConfig();
            cfg2.nodes[result.nodeKey] = result.node;
            if (Object.keys(cfg2.nodes).length === 1) cfg2.defaultNode = result.nodeKey;
            saveConfig(cfg2);
            console.log(`\n  ✓ Node saved.\n`);
            continue;
        }

        if (selected === '__import__') {
            await importProfile();
            continue;
        }

        const result = await nodeDetailLoop(selected);
        if (result) activatedKey = result;
    }
}

// ── Node detail view (merged: node info + live network state) ─────────────────

type NodeDetailAction = 'proposals' | 'set-active' | 'update-image' | 'set-alias' | 'export' | 'delete' | 'back';

type StateSnapshot =
    | { kind: 'ok'; state: aceNetwork.State; proposals: Array<{ addr: string; label: string; votes: number }> }
    | { kind: 'uninitialized' }
    | { kind: 'error'; message: string };

interface NodeDetailViewConfig {
    nodeKey:   string;
    node:      TrackedNode;
    isDefault: boolean;
    allNodes:  Record<string, TrackedNode>;
    client:    NetworkClient;
}

const nodeDetailView: (cfg: NodeDetailViewConfig) => Promise<NodeDetailAction> =
    createPrompt<NodeDetailAction, NodeDetailViewConfig>((cfg, done) => {
        useResizeClear();
        const [cursor, setCursor]           = useState(0);
        const [showSecrets, setShowSecrets] = useState(false);
        const [snapshot, setSnapshot]       = useState<StateSnapshot | 'loading'>('loading');
        const [balance, setBalance]         = useState<bigint | null>(null);

        const { nodeKey, node, isDefault, allNodes, client } = cfg;

        const stateOk = snapshot !== 'loading' && snapshot.kind === 'ok';
        const choices: Array<{ name: string; value: NodeDetailAction }> = [
            ...(stateOk ? [{ name: 'Manage proposals', value: 'proposals' as NodeDetailAction }] : []),
            { name: 'Set as active (this session)', value: 'set-active' },
            { name: 'Update image',                  value: 'update-image' },
            { name: 'Set alias',                     value: 'set-alias' },
            { name: 'Export profile',                value: 'export' },
            { name: 'Delete',                        value: 'delete' },
            { name: '← Back',                        value: 'back' },
        ];
        const safeCursor = Math.min(cursor, choices.length - 1);

        useEffect(() => {
            let cancelled = false;
            async function fetchLoop() {
                while (!cancelled) {
                    const [stateResult, bal] = await Promise.allSettled([
                        (async () => {
                            const state = await client.getNetworkState();
                            const proposals = state.activeProposals().map(pv => ({
                                addr: pv.votingSession.toStringLong(),
                                label: pv.proposal.kind,
                                votes: pv.voteCount(),
                            }));
                            return { state, proposals };
                        })(),
                        client.getAccountBalance(node.accountAddr),
                    ]);

                    if (!cancelled) {
                        if (stateResult.status === 'fulfilled') {
                            setSnapshot({ kind: 'ok', ...stateResult.value });
                        } else {
                            setSnapshot(
                                isNotFound(stateResult.reason)
                                    ? { kind: 'uninitialized' }
                                    : { kind: 'error', message: errMsg(stateResult.reason) },
                            );
                        }
                        if (bal.status === 'fulfilled') setBalance(bal.value);
                    }
                    await new Promise(r => setTimeout(r, 1_000));
                }
            }
            fetchLoop();
            return () => { cancelled = true; };
        }, []);

        useKeypress(key => {
            if (isEscapeKey(key))  done('back');
            if (key.name === 's')  setShowSecrets(!showSecrets);
            if (isUpKey(key))      setCursor(Math.max(0, safeCursor - 1));
            if (isDownKey(key))    setCursor(Math.min(choices.length - 1, safeCursor + 1));
            if (isEnterKey(key))   done(choices[safeCursor]!.value);
        });

        const mask = (v: string) => showSecrets ? v : '••••••••';
        const hasSecrets = !!(node.accountSk || node.pkeDk || node.rpcApiKey || node.gasStationKey);

        const lines: string[] = [];

        // ── Node info ──────────────────────────────────────────────────────────
        lines.push(`${node.alias ?? deriveRpcLabel(node.rpcUrl)}${isDefault ? '  [default]' : ''}`);
        lines.push('');
        lines.push(`Network   : ${node.rpcUrl}`);
        lines.push(`Contract  : ${node.aceAddr}`);
        lines.push(`Account   : ${node.accountAddr}`);
        lines.push(`Balance   : ${balance === null ? '…' : fmtApt(balance)}`);
        if (node.accountSk)      lines.push(`Acct SK   : ${mask(node.accountSk)}`);
        if (node.pkeEk)          lines.push(`PKE enc   : ${node.pkeEk}`);
        if (node.pkeDk)          lines.push(`PKE dec   : ${mask(node.pkeDk)}`);
        if (node.rpcApiKey)      lines.push(`API key   : ${mask(node.rpcApiKey)}`);
        if (node.gasStationKey)  lines.push(`Gas key   : ${mask(node.gasStationKey)}`);
        if (node.endpoint)       lines.push(`Endpoint  : ${node.endpoint}`);
        if (node.platform)       lines.push(`Platform  : ${node.platform === 'gcp' ? 'GCP Cloud Run' : 'Docker'}`);
        if (node.gcp) {
            lines.push(`Project   : ${node.gcp.project}`);
            lines.push(`Region    : ${node.gcp.region}`);
            lines.push(`Service   : ${node.gcp.serviceName}`);
        }
        if (node.docker) {
            lines.push(`Container : ${node.docker.containerName}`);
            lines.push(`Port      : ${node.docker.port}`);
        }
        if (node.image) lines.push(`Image     : ${node.image}`);
        lines.push('');

        // ── Network state ──────────────────────────────────────────────────────
        if (snapshot === 'loading') {
            lines.push('Fetching network state...');
        } else if (snapshot.kind === 'uninitialized') {
            lines.push('Network not initialized.');
        } else if (snapshot.kind === 'error') {
            lines.push(`Error: ${snapshot.message}`);
        } else {
            const { state, proposals } = snapshot;

            const nowUs = BigInt(Date.now()) * 1000n;
            const epochStarted = state.epochStartTimeMicros > 0n && state.epochStartTimeMicros < nowUs;
            const elapsedMs   = epochStarted ? Number((nowUs - state.epochStartTimeMicros) / 1000n) : 0;
            const durationMs  = Number(state.epochDurationMicros / 1000n);
            const remainingMs = Math.max(0, durationMs - elapsedMs);

            lines.push(`Epoch    : ${state.epoch}`);
            if (state.isEpochChanging()) {
                lines.push(`Timer    : epoch change in progress`);
                lines.push(`           session: ${state.epochChangeInfo!.sessionAddr.toStringLong()}`);
            } else if (!epochStarted || durationMs === 0) {
                lines.push(`Timer    : not started`);
            } else if (elapsedMs >= durationMs) {
                lines.push(`Timer    : expired — auto-reshare pending`);
            } else {
                lines.push(`Timer    : ${fmtDuration(elapsedMs)} elapsed, ${fmtDuration(remainingMs)} remaining`);
            }
            lines.push('');

            if (state.curNodes.length === 0) {
                lines.push('Committee: none');
            } else {
                lines.push(`Committee (threshold ${state.curThreshold} of ${state.curNodes.length}):`);
                for (const member of state.curNodes) {
                    const addr = member.toStringLong();
                    const [, peer] = Object.entries(allNodes)
                        .find(([, n]) => n.accountAddr === addr && n.rpcUrl === node.rpcUrl && n.aceAddr === node.aceAddr) ?? [];
                    const parts: string[] = [];
                    if (peer?.alias)               parts.push(`"${peer.alias}"`);
                    else if (peer)                 parts.push('(tracked)');
                    if (addr === node.accountAddr) parts.push('← you');
                    else if (peer?.accountSk)      parts.push('(yours)');
                    lines.push(`  ${addr}${parts.length ? '  ' + parts.join('  ') : ''}`);
                }
            }
            lines.push('');

            if (state.secrets.length === 0) {
                lines.push('Keypairs : none');
            } else {
                lines.push(`Keypairs (${state.secrets.length}):`);
                for (const s of state.secrets) lines.push(`  ${s.toStringLong()}`);
            }
            lines.push('');

            if (proposals.length === 0) {
                lines.push('Pending proposals: none');
            } else {
                lines.push(`Pending proposals (${proposals.length}):`);
                for (const p of proposals) {
                    lines.push(`  ${p.addr}  ${p.label}  ${p.votes}/${state.curThreshold} votes`);
                }
            }
        }

        // ── Actions ────────────────────────────────────────────────────────────
        lines.push('');
        if (hasSecrets) lines.push(`\x1b[2m[s] ${showSecrets ? 'hide secrets' : 'show secrets'}\x1b[0m`);
        lines.push('─'.repeat(50));
        for (let i = 0; i < choices.length; i++) {
            lines.push(i === safeCursor ? `\x1b[36m❯ ${choices[i]!.name}\x1b[0m` : `  ${choices[i]!.name}`);
        }

        return lines.join('\n');
    });

export async function nodeDetailLoop(nodeKey: string): Promise<string | undefined> {
    while (true) {
        console.clear();
        const config = loadConfig();
        const node = config.nodes[nodeKey];
        if (!node) return undefined;

        const client = NetworkClient.fromNode(node);

        const action = await nodeDetailView({
            nodeKey, node,
            isDefault: nodeKey === config.defaultNode,
            allNodes: config.nodes,
            client,
        });

        if (action === 'back') return undefined;

        if (action === 'proposals') {
            try {
                await runProposalCommand(node);
            } catch (e) {
                if ((e as any)?.name === 'ExitPromptError') throw e;
                console.error(`\n  Proposal error: ${e instanceof Error ? e.message : String(e)}\n`);
                await import('@inquirer/prompts').then(m => m.input({ message: 'Press Enter to continue' }));
            }
            continue;
        }

        if (action === 'set-active') {
            console.log(`\n  ✓ Now acting as this node for this session.\n`);
            return nodeKey;
        }

        if (action === 'set-alias') {
            const cfg = loadConfig();
            const n = cfg.nodes[nodeKey];
            if (!n) continue;
            const alias = (await input({ message: 'Alias (Enter to clear)', default: n.alias ?? '' })).trim() || undefined;
            n.alias = alias;
            saveConfig(cfg);
            console.log(`\n  ✓ Alias ${alias ? `set to "${alias}"` : 'cleared'}.\n`);
            continue;
        }

        if (action === 'export') {
            const cfg = loadConfig();
            const n = cfg.nodes[nodeKey];
            if (!n) continue;
            exportProfile(nodeKey, n);
            await input({ message: 'Press Enter to continue' });
            continue;
        }

        if (action === 'update-image') {
            const cfg = loadConfig();
            const n = cfg.nodes[nodeKey];
            if (!n) continue;
            await updateImage(nodeKey, n);
            continue;
        }

        if (action === 'delete') {
            const cfg = loadConfig();
            const n = cfg.nodes[nodeKey];
            if (!n) continue;
            const ok = await confirm({
                message: `Delete "${displayNode(nodeKey, n)}"? This cannot be undone.`,
                default: false,
            });
            if (!ok) continue;
            await terminateNode(n);
            const cfg2 = loadConfig();
            delete cfg2.nodes[nodeKey];
            if (cfg2.defaultNode === nodeKey) cfg2.defaultNode = Object.keys(cfg2.nodes)[0];
            saveConfig(cfg2);
            console.log(`\n  ✓ Node deleted.\n`);
            return undefined;
        }
    }
}

function exportProfile(nodeKey: string, node: TrackedNode): void {
    const json = JSON.stringify({ nodeKey, ...node }, null, 2);
    console.log('\n' + json + '\n');
    console.log('  (Save the above JSON — you can import it with "Import profile".)\n');
}

async function importProfile(): Promise<void> {
    const filePath = await input({ message: 'Path to exported profile JSON' });
    try {
        const raw = readFileSync(filePath.trim(), 'utf8');
        const parsed = JSON.parse(raw) as { nodeKey: string } & TrackedNode;
        const { nodeKey, ...node } = parsed;
        if (!nodeKey || typeof nodeKey !== 'string') throw new Error('Missing nodeKey field');
        const cfg = loadConfig();
        cfg.nodes[nodeKey] = node;
        saveConfig(cfg);
        console.log(`\n  ✓ Profile imported as "${nodeKey}".\n`);
    } catch (e) {
        console.error(`\n  Failed to import profile: ${e}\n`);
    }
}

async function updateImage(nodeKey: string, node: TrackedNode): Promise<void> {
    const newImage = await selectImage(node.image);
    if (newImage === node.image) {
        console.log('\n  Image unchanged.\n');
        return;
    }

    if (node.platform === 'gcp' && node.gcp) {
        const { project, region, serviceName } = node.gcp;
        const cmd = `gcloud run services update ${serviceName} --image docker.io/${newImage} --project ${project} --region ${region}`;
        console.log(`\n  $ ${cmd}\n`);
        execSync(cmd, { stdio: 'inherit' });
    } else if (node.platform === 'docker' && node.docker) {
        const { containerName, port } = node.docker;
        console.log(`\n  Stopping container "${containerName}"...`);
        try { execSync(`docker stop ${containerName} && docker rm ${containerName}`, { stdio: 'inherit' }); } catch { /* already stopped */ }
        const nodeArgs = { accountAddr: node.accountAddr, accountSk: node.accountSk ?? '', pkeDk: node.pkeDk ?? '' };
        const cmd = dockerRunCmd(containerName, newImage, port, nodeArgs, node.rpcUrl, node.aceAddr, node.rpcApiKey, node.gasStationKey);
        console.log(`\n  $ ${cmd}\n`);
        execSync(cmd, { stdio: 'inherit' });
    }

    const cfg = loadConfig();
    if (cfg.nodes[nodeKey]) cfg.nodes[nodeKey]!.image = newImage;
    saveConfig(cfg);
    console.log(`\n  ✓ Image updated to ${newImage}\n`);
}

async function terminateNode(node: TrackedNode): Promise<void> {
    if (node.platform === 'gcp' && node.gcp) {
        const { project, region, serviceName } = node.gcp;
        const cmd = `gcloud run services delete ${serviceName} --project ${project} --region ${region} --quiet`;
        console.log(`\n  Terminating GCP Cloud Run service "${serviceName}"...`);
        try { execSync(cmd, { stdio: 'inherit' }); } catch (e) {
            console.error(`  Warning: ${e}`);
        }
    } else if (node.platform === 'docker' && node.docker) {
        const { containerName } = node.docker;
        console.log(`\n  Stopping Docker container "${containerName}"...`);
        try { execSync(`docker stop ${containerName} && docker rm ${containerName}`, { stdio: 'inherit' }); } catch (e) {
            console.error(`  Warning: ${e}`);
        }
    }
}

function isNotFound(e: unknown): boolean {
    const msg = errMsg(e);
    const vmCode = (e as any)?.data?.vm_error_code ??
        (msg.match(/"vm_error_code":(\d+)/)?.[1] ? Number(msg.match(/"vm_error_code":(\d+)/)?.[1]) : undefined);
    return msg.includes('resource_not_found') ||
        msg.includes('RESOURCE_DOES_NOT_EXIST') ||
        msg.includes('NOT_FOUND') ||
        vmCode === 4008;
}

function errMsg(e: unknown): string {
    return String((e as any)?.message ?? e);
}

function fmtApt(octas: bigint): string {
    const apt = Number(octas) / 1e8;
    return `${apt.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 4 })} APT`;
}

function fmtDuration(ms: number): string {
    if (ms < 60_000)    return `${Math.round(ms / 1000)}s`;
    if (ms < 3_600_000) return `${Math.round(ms / 60_000)}m`;
    return `${Math.round(ms / 3_600_000)}h`;
}
