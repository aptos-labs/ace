// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Ed25519PrivateKey } from '@aptos-labs/ts-sdk';
import { execSync, spawn, ChildProcess } from 'child_process';
import { existsSync } from 'fs';
import * as path from 'path';
import { LOCALNET_URL, WORKER_BINARY, REPO_ROOT } from './config';
import {
    prepareContractsPublishScratch,
    publishMovePackage,
    rmContractsPublishScratch,
    waitFor,
} from './helpers';

export function buildWorker(): void {
    const manifestPath = path.join(REPO_ROOT, 'worker-rs', 'Cargo.toml');
    console.log(`  $ cargo build --manifest-path ${manifestPath}`);
    execSync(`cargo build --manifest-path ${manifestPath}`, { stdio: 'inherit' });
}

/** Publish WorkerConfig + AceVss + `vss_e2e` harness only (no `ace_network`). */
export async function deployVssStackOnly(
    contractsRoot: string,
    adminAddress: string,
    privateKeyHex: string,
): Promise<void> {
    const scratch = prepareContractsPublishScratch(contractsRoot, adminAddress);
    try {
        const root = scratch.contractsDir;
        const workerCfg = path.join(root, 'worker_config');
        const aceVss = path.join(root, 'ace_vss');
        const vssE2e = path.join(root, 'vss_e2e');
        if (!existsSync(path.join(workerCfg, 'Move.toml'))) {
            throw new Error(`missing ${workerCfg}`);
        }
        if (!existsSync(path.join(vssE2e, 'Move.toml'))) {
            throw new Error(`missing ${vssE2e}`);
        }
        await publishMovePackage(workerCfg, privateKeyHex);
        await publishMovePackage(aceVss, privateKeyHex);
        await publishMovePackage(vssE2e, privateKeyHex);
    } finally {
        rmContractsPublishScratch(scratch);
    }
}

export async function deployContract(
    contractsRoot: string,
    adminAddress: string,
    privateKeyHex: string,
): Promise<void> {
    const scratch = prepareContractsPublishScratch(contractsRoot, adminAddress);
    try {
        const root = scratch.contractsDir;
        const workerCfg = path.join(root, 'worker_config');
        if (existsSync(path.join(workerCfg, 'Move.toml'))) {
            await publishMovePackage(workerCfg, privateKeyHex);
            const aceVss = path.join(root, 'ace_vss');
            if (existsSync(path.join(aceVss, 'Move.toml'))) {
                await publishMovePackage(aceVss, privateKeyHex);
            }
        }
        const aceNetwork = path.join(root, 'ace_network');
        if (existsSync(path.join(aceNetwork, 'Move.toml'))) {
            await publishMovePackage(aceNetwork, privateKeyHex);
        } else if (existsSync(path.join(root, 'Move.toml')) && !existsSync(path.join(workerCfg, 'Move.toml'))) {
            await publishMovePackage(root, privateKeyHex);
        }
    } finally {
        rmContractsPublishScratch(scratch);
    }
}

/**
 * Register a worker's public endpoint on-chain.
 * Run once per worker after funding, before starting the worker process.
 * endpoint is the public URL peers will use, e.g. "http://localhost:9000".
 */
/** Print `0x` + 96 hex chars: G1 encryption PK derived from `ACE_WORKER_V2_PRIVATE_KEY`. */
export function vssDealerPrintEncryptionPk(privateKey: Ed25519PrivateKey): string {
    const privateKeyHex = Buffer.from(privateKey.toUint8Array()).toString('hex');
    const out = execSync(`${WORKER_BINARY} vss-dealer print-encryption-pk`, {
        env: { ...process.env, ACE_WORKER_V2_PRIVATE_KEY: `0x${privateKeyHex}` },
        encoding: 'utf8',
    }).trim();
    return out;
}

/** Run the full two-phase `vss-dealer` client until the session reaches `DONE` (blocking). */
export function vssDealerRunSync(
    privateKey: Ed25519PrivateKey,
    opts: {
        rpcUrl: string;
        contractAddr: string;
        vssSession: string;
        recipients: string[];
        recipientPksHex: string[];
        recipientIndices: number[];
        threshold: number;
        pollSecs?: number;
        phase2DelaySecs?: number;
    },
): void {
    const privateKeyHex = Buffer.from(privateKey.toUint8Array()).toString('hex');
    const poll = opts.pollSecs ?? 10;
    const delay = opts.phase2DelaySecs ?? 10;
    const parts = [
        WORKER_BINARY,
        'vss-dealer',
        'run',
        '--rpc-url',
        opts.rpcUrl,
        '--ace-contract',
        opts.contractAddr,
        '--vss-session',
        opts.vssSession,
        '--recipients',
        opts.recipients.join(','),
        '--recipient-pks-hex',
        opts.recipientPksHex.join(','),
        '--recipient-indices',
        opts.recipientIndices.join(','),
        '--threshold',
        String(opts.threshold),
        '--poll-secs',
        String(poll),
        '--phase2-delay-secs',
        String(delay),
    ];
    console.log(`  $ ${WORKER_BINARY} vss-dealer run ...`);
    execSync(parts.join(' '), {
        env: { ...process.env, ACE_WORKER_V2_PRIVATE_KEY: `0x${privateKeyHex}`, RUST_LOG: 'info' },
        stdio: 'inherit',
    });
}

export type VssDealerSpawnOpts = {
    rpcUrl: string;
    contractAddr: string;
    vssSession: string;
    recipients: string[];
    recipientPksHex: string[];
    recipientIndices: number[];
    threshold: number;
    pollSecs?: number;
    phase2DelaySecs?: number;
};

/** Spawn `worker-rs vss-dealer run` (caller should `waitProcessExitZero` or race on timeout). */
export function spawnVssDealerRun(privateKey: Ed25519PrivateKey, opts: VssDealerSpawnOpts): ChildProcess {
    const privateKeyHex = Buffer.from(privateKey.toUint8Array()).toString('hex');
    const poll = opts.pollSecs ?? 10;
    const delay = opts.phase2DelaySecs ?? 10;
    console.log(`  $ ${WORKER_BINARY} vss-dealer run ... (spawn)`);
    return spawn(
        WORKER_BINARY,
        [
            'vss-dealer',
            'run',
            '--rpc-url',
            opts.rpcUrl,
            '--ace-contract',
            opts.contractAddr,
            '--vss-session',
            opts.vssSession,
            '--recipients',
            opts.recipients.join(','),
            '--recipient-pks-hex',
            opts.recipientPksHex.join(','),
            '--recipient-indices',
            opts.recipientIndices.join(','),
            '--threshold',
            String(opts.threshold),
            '--poll-secs',
            String(poll),
            '--phase2-delay-secs',
            String(delay),
        ],
        {
            env: { ...process.env, ACE_WORKER_V2_PRIVATE_KEY: `0x${privateKeyHex}`, RUST_LOG: 'info' },
            stdio: 'inherit',
        },
    );
}

export type VssRecipientSpawnOpts = {
    rpcUrl: string;
    contractAddr: string;
    vssSession: string;
    pollSecs?: number;
    maxWaitSecs?: number;
};

/** Spawn `worker-rs vss-recipient run` until share row exists, decrypted, and session `DONE`. */
export function spawnVssRecipientRun(privateKey: Ed25519PrivateKey, opts: VssRecipientSpawnOpts): ChildProcess {
    const privateKeyHex = Buffer.from(privateKey.toUint8Array()).toString('hex');
    const poll = opts.pollSecs ?? 2;
    const maxWait = opts.maxWaitSecs ?? 120;
    console.log(`  $ ${WORKER_BINARY} vss-recipient run ... (spawn)`);
    return spawn(
        WORKER_BINARY,
        [
            'vss-recipient',
            'run',
            '--rpc-url',
            opts.rpcUrl,
            '--ace-contract',
            opts.contractAddr,
            '--vss-session',
            opts.vssSession,
            '--poll-secs',
            String(poll),
            '--max-wait-secs',
            String(maxWait),
        ],
        {
            env: { ...process.env, ACE_WORKER_V2_PRIVATE_KEY: `0x${privateKeyHex}`, RUST_LOG: 'info' },
            stdio: 'inherit',
        },
    );
}

/** Resolves when `proc` exits with code 0; rejects on non-zero, spawn error, or missing exit. */
export function waitProcessExitZero(proc: ChildProcess, label: string): Promise<void> {
    return new Promise((resolve, reject) => {
        proc.once('error', reject);
        proc.once('exit', (code, signal) => {
            if (code === 0) {
                resolve();
            } else {
                reject(
                    new Error(
                        `${label} exited with code ${code}${signal ? ` (signal ${signal})` : ''}`,
                    ),
                );
            }
        });
    });
}

export function registerWorker(privateKey: Ed25519PrivateKey, endpoint: string, contractAddr: string): void {
    const privateKeyHex = Buffer.from(privateKey.toUint8Array()).toString('hex');
    execSync(
        `${WORKER_BINARY} register-node --endpoint ${endpoint} --rpc-url ${LOCALNET_URL} --ace-contract ${contractAddr}`,
        {
            env: { ...process.env, ACE_WORKER_V2_PRIVATE_KEY: `0x${privateKeyHex}`, RUST_LOG: 'info' },
            stdio: 'inherit',
        }
    );
}

/**
 * Spawn a worker process in `run` mode.
 * Public server on `port`; internal signer on `port + 100`.
 * The public URL (http://localhost:<port>) must be registered on-chain first
 * via registerWorker().
 */
export function spawnWorker(privateKey: Ed25519PrivateKey, port: number, contractAddr: string): ChildProcess {
    const privateKeyHex = Buffer.from(privateKey.toUint8Array()).toString('hex');
    const signerPort = port + 500; // +100 conflicts with localnet metrics:9101 and admin:9102
    const proc = spawn(WORKER_BINARY, [
        'run',
        '--port', String(port),
        '--signer-port', String(signerPort),
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
