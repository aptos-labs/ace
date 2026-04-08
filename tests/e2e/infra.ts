// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Ed25519PrivateKey } from '@aptos-labs/ts-sdk';
import { execSync, spawn, ChildProcess } from 'child_process';
import * as path from 'path';
import { LOCALNET_URL, WORKER_BINARY, REPO_ROOT } from './config.js';
import { waitFor } from './helpers.js';

export function buildWorker(): void {
    const manifestPath = path.join(REPO_ROOT, 'worker-rs', 'Cargo.toml');
    console.log(`  $ cargo build --manifest-path ${manifestPath}`);
    execSync(`cargo build --manifest-path ${manifestPath}`, { stdio: 'inherit' });
}

export function deployContract(contractDir: string, adminAddress: string, privateKeyHex: string, overrideAdmin = true): void {
    const parts = [
        'aptos', 'move', 'publish',
        '--package-dir', contractDir,
        '--private-key', `0x${privateKeyHex}`,
        '--url', LOCALNET_URL,
        '--assume-yes',
        '--skip-fetch-latest-git-deps',
    ];
    if (overrideAdmin) {
        parts.splice(3, 0, '--named-addresses', `admin=${adminAddress}`);
    }
    const cmd = parts.join(' ');
    console.log(`  $ ${cmd}`);
    execSync(cmd, { stdio: 'inherit' });
}

export function spawnWorker(privateKey: Ed25519PrivateKey, port: number, contractAddr: string): ChildProcess {
    const privateKeyHex = Buffer.from(privateKey.toUint8Array()).toString('hex');
    const proc = spawn(WORKER_BINARY, [
        'run-worker-v2',
        '--port', String(port),
        '--rpc-url', LOCALNET_URL,
        '--ace-contract', contractAddr,
    ], {
        env: {
            ...process.env,
            ACE_WORKER_V2_PRIVATE_KEY: `0x${privateKeyHex}`,
            RUST_LOG: 'info',
        },
        stdio: ['ignore', 'pipe', 'pipe'],
    });
    proc.stdout?.on('data', (d: Buffer) => console.log(`  [worker:${port}] ${d.toString().trim()}`));
    proc.stderr?.on('data', (d: Buffer) => console.error(`  [worker:${port}] ERR: ${d.toString().trim()}`));
    return proc;
}

export async function waitWorkerHealthy(port: number): Promise<void> {
    await waitFor(`worker:${port} healthy`, async () => {
        try {
            const r = await fetch(`http://localhost:${port}/health`, { signal: AbortSignal.timeout(1000) });
            return r.status === 200;
        } catch { return false; }
    }, 20_000);
}
