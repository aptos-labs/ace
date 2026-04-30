// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';

const CONFIG_DIR  = join(homedir(), '.ace');
const CONFIG_PATH = join(CONFIG_DIR, 'config.json');

export type Platform = 'gcp' | 'docker' | 'local';

export interface ChainRpcOverrides {
    aptosMainnetApi?:      string;
    aptosMainnetApikey?:   string;
    aptosTestnetApi?:      string;
    aptosTestnetApikey?:   string;
    aptosLocalnetApi?:     string;
    aptosLocalnetApikey?:  string;
    solanaMainnetBetaRpc?: string;
    solanaTestnetRpc?:     string;
    solanaDevnetRpc?:      string;
}

export interface GcpConfig {
    project: string;
    region: string;
    serviceName: string;
}

export interface DockerConfig {
    containerName: string;
    port: string;
}

export interface LocalConfig {
    repoPath: string;
    port: string;
    pid?: number;      // PID of the background process started by the CLI
    logFile?: string;  // Absolute path to the timestamped log file
}

/** A node you control or watch. Network connection info is embedded directly. */
export interface TrackedNode {
    // Network connection (formerly TrackedNetwork)
    rpcUrl:      string;       // host-facing URL (used by the CLI)
    nodeRpcUrl?: string;       // node-facing URL (used by the container; differs from rpcUrl on localnet+Docker)
    aceAddr:    string;
    rpcApiKey?: string;
    // Node identity
    accountAddr:    string;
    accountSk?:     string;
    pkeDk?:         string;
    pkeEk?:         string;
    alias?:         string;
    endpoint?:      string;
    image?:         string;
    platform?:      Platform;
    gcp?:           GcpConfig;
    docker?:        DockerConfig;
    local?:         LocalConfig;
    gasStationKey?: string;
    chainRpc?:      ChainRpcOverrides;
}

export interface Config {
    defaultNode?: string;
    nodes: Record<string, TrackedNode>;
}

// ── Key derivation ────────────────────────────────────────────────────────────

export function deriveRpcLabel(rpcUrl: string): string {
    const url = rpcUrl.toLowerCase();
    if (url.includes('mainnet')) return 'mainnet';
    if (url.includes('testnet')) return 'testnet';
    if (url.includes('devnet'))  return 'devnet';
    try {
        const u = new URL(rpcUrl);
        const isLocal = u.hostname === 'localhost' || u.hostname === '127.0.0.1';
        if (isLocal) {
            const port = u.port || '80';
            return port === '8080' ? 'localnet' : `localnet:${port}`;
        }
        return u.port ? `${u.hostname}:${u.port}` : u.hostname;
    } catch {
        return rpcUrl;
    }
}

export function makeNodeKey(rpcUrl: string, aceAddr: string, accountAddr: string): string {
    return `${deriveRpcLabel(rpcUrl)}/${aceAddr}/${accountAddr}`;
}

export function displayNode(key: string, node: TrackedNode): string {
    return node.alias ? `${key} (${node.alias})` : key;
}

// ── Persistence ───────────────────────────────────────────────────────────────

export function loadConfig(): Config {
    if (!existsSync(CONFIG_PATH)) return { nodes: {} };
    try {
        const raw = JSON.parse(readFileSync(CONFIG_PATH, 'utf8')) as any;

        // Migrate from old format: { networks: {...}, nodes: { networkKey, ... } }
        if (raw.networks && raw.nodes) {
            const migrated: Config = { defaultNode: raw.defaultNode, nodes: {} };
            for (const [nodeKey, n] of Object.entries(raw.nodes as Record<string, any>)) {
                const net = (raw.networks as Record<string, any>)[n.networkKey];
                if (!net) continue;
                migrated.nodes[nodeKey] = {
                    rpcUrl:       net.rpcUrl,
                    aceAddr:      net.aceAddr,
                    rpcApiKey:    n.rpcApiKey ?? net.rpcApiKey,
                    accountAddr:  n.accountAddr,
                    accountSk:    n.accountSk,
                    pkeDk:        n.pkeDk,
                    pkeEk:        n.pkeEk,
                    alias:        n.alias,
                    endpoint:     n.endpoint,
                    image:        n.image,
                    platform:     n.platform,
                    gcp:          n.gcp,
                    docker:       n.docker,
                    gasStationKey: n.gasStationKey,
                };
            }
            saveConfig(migrated);
            return migrated;
        }

        raw.nodes ??= {};
        return raw as Config;
    } catch {
        return { nodes: {} };
    }
}

export function saveConfig(config: Config): void {
    if (!existsSync(CONFIG_DIR)) mkdirSync(CONFIG_DIR, { recursive: true });
    writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
}

export function resolveDefaultNode(config: Config): TrackedNode | undefined {
    if (!config.defaultNode) return undefined;
    return config.nodes[config.defaultNode];
}
