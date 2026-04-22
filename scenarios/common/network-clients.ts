// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Account } from '@aptos-labs/ts-sdk';
import { execSync, spawn, type ChildProcess } from 'child_process';

import { NETWORK_NODE_BINARY, LOCALNET_URL, REPO_ROOT } from './config';
import { ed25519PrivateKeyHex } from './helpers';

function spawnExitZero(cmd: string, args: string[], cwd: string, label: string): Promise<void> {
    return new Promise((resolve, reject) => {
        const child = spawn(cmd, args, { cwd, stdio: 'inherit' });
        child.once('error', reject);
        child.once('close', (code, signal) => {
            if (code === 0) {
                resolve();
            } else {
                reject(new Error(`${label} exited with code ${code}${signal ? ` (signal ${signal})` : ''}`));
            }
        });
    });
}

/**
 * Kill any stale `network-node run` processes left over from previous test runs.
 * Stale workers hold their TCP ports open, causing bind failures on the next run.
 */
export function killStaleNetworkNodes(): void {
    try {
        execSync('pkill -KILL -f "network-node run" 2>/dev/null; sleep 0.3', { stdio: 'ignore' });
    } catch {
        // pkill exits non-zero when no processes match — that's fine.
    }
}

/** Build the repo-root Cargo workspace (all binaries including network-node). */
export async function buildRustWorkspace(): Promise<void> {
    if (process.env.ACE_SKIP_CARGO_BUILD) return;
    console.log(`  $ (cwd ${REPO_ROOT}) cargo build`);
    await spawnExitZero('cargo', ['build'], REPO_ROOT, 'cargo build');
}

export type NetworkNodeSpawnInput = {
    runAs: Account;
    /** PKE decryption key bytes as `0x` + hex (TS `decryptionKey.toBytes()`). */
    pkeDkHex: string;
    /** Published module address (`admin` / ace contract). */
    aceDeploymentAddr: string;
    aceDeploymentApi?: string;
    /** TCP port for the UserRequestHandler HTTP server. */
    port?: number;
};

/**
 * Spawn a `network-node run` process for one committee member.
 *
 * The network-node binary (not yet implemented) watches the chain for DKG and DKR
 * sessions it is part of, acting as:
 *   - dkg-worker  when listed in a DKG session's `workers`
 *   - dkr-src     when listed in a DKR session's `current_nodes`
 *   - dkr-dst     when listed in a DKR session's `new_nodes`
 *
 * Workers should be spawned BEFORE admin calls `start_initial_epoch` so they are
 * already watching when sessions appear on-chain.
 */
export function spawnNetworkNode(opts: NetworkNodeSpawnInput): ChildProcess {
    const pkHex = ed25519PrivateKeyHex(opts.runAs);
    const rpc = opts.aceDeploymentApi ?? LOCALNET_URL;
    const accountAddr = opts.runAs.accountAddress.toStringLong();
    const pkeDkHex = opts.pkeDkHex.startsWith('0x') ? opts.pkeDkHex : `0x${opts.pkeDkHex}`;
    const args = [
        'run',
        '--ace-deployment-api', rpc,
        '--ace-deployment-addr', opts.aceDeploymentAddr,
        '--account-addr', accountAddr,
        '--account-sk', `0x${pkHex}`,
        '--pke-dk', pkeDkHex,
    ];
    if (opts.port !== undefined) {
        args.push('--port', String(opts.port));
    }
    console.log(`  $ ${NETWORK_NODE_BINARY} ${args.join(' ')} (spawn)`);
    return spawn(NETWORK_NODE_BINARY, args, {
        env: { ...process.env, RUST_LOG: 'info' },
        stdio: 'inherit',
    });
}
