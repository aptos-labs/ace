// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import { spawn, type ChildProcess } from 'child_process';

import { DKR_SRC_BINARY, DKR_DST_BINARY, LOCALNET_URL, REPO_ROOT } from './config';
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

/** Build the repo-root Cargo workspace (all binaries including dkr-src, dkr-dst). */
export async function buildRustWorkspace(): Promise<void> {
    console.log(`  $ (cwd ${REPO_ROOT}) cargo build`);
    await spawnExitZero('cargo', ['build'], REPO_ROOT, 'cargo build');
}

export type DKRSrcSpawnInput = {
    runAs: Account;
    /** PKE decryption key bytes as `0x` + hex (TS `decryptionKey.toBytes()`). */
    pkeDkHex: string;
    dkrSessionAddr: AccountAddress | string;
    /** Published module address (`admin` / ace contract). */
    aceContract: string;
    rpcUrl?: string;
};

/** Spawn `dkr-src run` for one old-committee member. */
export function spawnDKRSrcRun(opts: DKRSrcSpawnInput): ChildProcess {
    const pkHex = ed25519PrivateKeyHex(opts.runAs);
    const rpc = opts.rpcUrl ?? LOCALNET_URL;
    const session = typeof opts.dkrSessionAddr === 'string'
        ? opts.dkrSessionAddr
        : opts.dkrSessionAddr.toStringLong();
    const accountAddr = opts.runAs.accountAddress.toStringLong();
    const pkeDkHex = opts.pkeDkHex.startsWith('0x') ? opts.pkeDkHex : `0x${opts.pkeDkHex}`;
    const args = [
        'run',
        '--rpc-url', rpc,
        '--ace-contract', opts.aceContract,
        '--dkr-session', session,
        '--pke-dk-hex', pkeDkHex,
        '--account-addr', accountAddr,
        '--account-sk', `0x${pkHex}`,
    ];
    console.log(`  $ ${DKR_SRC_BINARY} ${args.join(' ')} (spawn)`);
    return spawn(DKR_SRC_BINARY, args, {
        env: { ...process.env, RUST_LOG: 'info' },
        stdio: 'inherit',
    });
}

export type DKRDstSpawnInput = {
    runAs: Account;
    /** PKE decryption key bytes as `0x` + hex (TS `decryptionKey.toBytes()`). */
    pkeDkHex: string;
    dkrSessionAddr: AccountAddress | string;
    /** Published module address (`admin` / ace contract). */
    aceContract: string;
    rpcUrl?: string;
};

/** Spawn `dkr-dst run` for one new-committee member. */
export function spawnDKRDstRun(opts: DKRDstSpawnInput): ChildProcess {
    const pkHex = ed25519PrivateKeyHex(opts.runAs);
    const rpc = opts.rpcUrl ?? LOCALNET_URL;
    const session = typeof opts.dkrSessionAddr === 'string'
        ? opts.dkrSessionAddr
        : opts.dkrSessionAddr.toStringLong();
    const accountAddr = opts.runAs.accountAddress.toStringLong();
    const pkeDkHex = opts.pkeDkHex.startsWith('0x') ? opts.pkeDkHex : `0x${opts.pkeDkHex}`;
    const args = [
        'run',
        '--rpc-url', rpc,
        '--ace-contract', opts.aceContract,
        '--dkr-session', session,
        '--pke-dk-hex', pkeDkHex,
        '--account-addr', accountAddr,
        '--account-sk', `0x${pkHex}`,
    ];
    console.log(`  $ ${DKR_DST_BINARY} ${args.join(' ')} (spawn)`);
    return spawn(DKR_DST_BINARY, args, {
        env: { ...process.env, RUST_LOG: 'info' },
        stdio: 'inherit',
    });
}
