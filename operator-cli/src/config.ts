// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';

const CONFIG_DIR = join(homedir(), '.ace');
const CONFIG_PATH = join(CONFIG_DIR, 'config.json');

export type Platform = 'gcp' | 'docker';

export interface GcpConfig {
    project: string;
    region: string;
    serviceName: string;
}

export interface DockerConfig {
    containerName: string;
    port: string;
}

export interface TrackedNode {
    name: string;
    // Credentials
    accountAddr: string;
    accountSk: string;
    pkeDk: string;
    pkeEk: string;
    // Deployment
    rpcUrl: string;
    aceAddr: string;
    rpcApiKey?: string;
    gasStationKey?: string;
    image: string;
    platform: Platform;
    gcp?: GcpConfig;
    docker?: DockerConfig;
    endpoint: string;
}

export interface Config {
    defaultProfile?: string;
    profiles: Record<string, TrackedNode>;
}

export function loadConfig(): Config {
    if (!existsSync(CONFIG_PATH)) return { profiles: {} };
    try {
        return JSON.parse(readFileSync(CONFIG_PATH, 'utf8')) as Config;
    } catch {
        return { profiles: {} };
    }
}

export function saveConfig(config: Config): void {
    if (!existsSync(CONFIG_DIR)) mkdirSync(CONFIG_DIR, { recursive: true });
    writeFileSync(CONFIG_PATH, JSON.stringify(config, null, 2) + '\n', { mode: 0o600 });
}

export function resolveProfile(config: Config, name?: string): TrackedNode {
    const profileName = name ?? config.defaultProfile;
    if (!profileName) {
        throw new Error('No profile specified and no default set. Run `ace node` to add one.');
    }
    const profile = config.profiles[profileName];
    if (!profile) {
        throw new Error(`Profile "${profileName}" not found. Run \`ace node\` to manage profiles.`);
    }
    return profile;
}
