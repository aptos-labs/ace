// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import { spawn, type ChildProcess } from 'child_process';

import { DKG_WORKER_BINARY, LOCALNET_URL, REPO_ROOT } from './config';
import { ed25519PrivateKeyHex } from './helpers';

function spawnExitZero(cmd: string, args: string[], cwd: string, label: string): Promise<void> {
    return new Promise((resolve, reject) => {
        const child = spawn(cmd, args, { cwd, stdio: 'inherit' });
        child.once('error', reject);
        child.once('close', (code, signal) => {
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

/** Build the repo-root Cargo workspace (`dkg-worker`, `vss-dealer`, `vss-recipient`). */
export async function buildRustWorkspace(): Promise<void> {
    if (process.env.ACE_SKIP_CARGO_BUILD) return;
    console.log(`  $ (cwd ${REPO_ROOT}) cargo build`);
    await spawnExitZero('cargo', ['build'], REPO_ROOT, 'cargo build');
}

export type DKGWorkerSpawnInput = {
    runAs: Account;
    /** PKE decryption key bytes as `0x` + hex (TS `decryptionKey.toBytes()`). */
    pkeDkHex: string;
    dkgSessionAddr: AccountAddress | string;
    /** Published module address (`admin` / ace contract). */
    aceDeploymentAddr: string;
    aceDeploymentApi?: string;
};

/** Spawn `dkg-worker run` for one committee member. */
export function spawnDKGRun(opts: DKGWorkerSpawnInput): ChildProcess {
    const pkHex = ed25519PrivateKeyHex(opts.runAs);
    const rpc = opts.aceDeploymentApi ?? LOCALNET_URL;
    const session = typeof opts.dkgSessionAddr === 'string'
        ? opts.dkgSessionAddr
        : opts.dkgSessionAddr.toStringLong();
    const accountAddr = opts.runAs.accountAddress.toStringLong();
    const pkeDkHex = opts.pkeDkHex.startsWith('0x') ? opts.pkeDkHex : `0x${opts.pkeDkHex}`;
    const args = [
        'run',
        '--ace-deployment-api',
        rpc,
        '--ace-deployment-addr',
        opts.aceDeploymentAddr,
        '--dkg-session',
        session,
        '--pke-dk',
        pkeDkHex,
        '--account-addr',
        accountAddr,
        '--account-sk',
        `0x${pkHex}`,
    ];
    console.log(`  $ ${DKG_WORKER_BINARY} ${args.join(' ')} (spawn)`);
    return spawn(DKG_WORKER_BINARY, args, {
        env: { ...process.env, RUST_LOG: 'info' },
        stdio: 'inherit',
    });
}
