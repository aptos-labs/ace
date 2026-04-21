// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Result } from '@aptos-labs/ace-sdk';
import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import { spawn, type ChildProcess } from 'child_process';

import { LOCALNET_URL, REPO_ROOT, VSS_DEALER_BINARY, VSS_RECIPIENT_BINARY } from './config';
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

/** Build the repo-root Cargo workspace (`vss-dealer`, `vss-recipient`). */
export async function buildRustWorkspace(): Promise<void> {
    if (process.env.ACE_SKIP_CARGO_BUILD) return;
    console.log(`  $ (cwd ${REPO_ROOT}) cargo build`);
    await spawnExitZero('cargo', ['build'], REPO_ROOT, 'cargo build');
}

function sessionAddrString(addr: AccountAddress | string): string {
    return typeof addr === 'string' ? addr : addr.toStringLong();
}

export type VSSDealerSpawnInput = {
    runAs: Account;
    /** PKE decryption key bytes as `0x` + hex (TS `decryptionKey.toBytes()`). */
    pkeDkHex: string;
    sessionAddr: AccountAddress | string;
    /** Published module address (`admin` / ace contract). */
    aceContract: string;
    rpcUrl?: string;
};

/** Spawn `vss-dealer run` (skeleton binary). */
export function spawnVSSDealerRun(opts: VSSDealerSpawnInput): ChildProcess {
    const pkHex = ed25519PrivateKeyHex(opts.runAs);
    const rpc = opts.rpcUrl ?? LOCALNET_URL;
    const session = sessionAddrString(opts.sessionAddr);
    const accountAddr = opts.runAs.accountAddress.toStringLong();
    const pkeDkHex = opts.pkeDkHex.startsWith('0x') ? opts.pkeDkHex : `0x${opts.pkeDkHex}`;
    const args = [
        'run',
        '--rpc-url',
        rpc,
        '--ace-contract',
        opts.aceContract,
        '--vss-session',
        session,
        '--pke-dk-hex',
        pkeDkHex,
        '--account-addr',
        accountAddr,
        '--account-sk',
        `0x${pkHex}`,
    ];
    console.log(`  $ ${VSS_DEALER_BINARY} ${args.join(' ')} (spawn)`);
    return spawn(VSS_DEALER_BINARY, args, {
        env: { ...process.env, RUST_LOG: 'info' },
        stdio: 'inherit',
    });
}

export type VSSRecipientSpawnInput = {
    runAs: Account;
    /** PKE decryption key bytes as `0x` + hex (TS `decryptionKey.toBytes()`). */
    pkeDkHex: string;
    sessionAddr: AccountAddress | string;
    aceContract: string;
    rpcUrl?: string;
};

/** Spawn `vss-recipient run` (skeleton binary). */
export function spawnVSSRecipientRun(opts: VSSRecipientSpawnInput): ChildProcess {
    const pkHex = ed25519PrivateKeyHex(opts.runAs);
    const rpc = opts.rpcUrl ?? LOCALNET_URL;
    const session = sessionAddrString(opts.sessionAddr);
    const accountAddr = opts.runAs.accountAddress.toStringLong();
    const pkeDkHex = opts.pkeDkHex.startsWith('0x') ? opts.pkeDkHex : `0x${opts.pkeDkHex}`;
    const args = [
        'run',
        '--rpc-url',
        rpc,
        '--ace-contract',
        opts.aceContract,
        '--vss-session',
        session,
        '--pke-dk-hex',
        pkeDkHex,
        '--account-addr',
        accountAddr,
        '--account-sk',
        `0x${pkHex}`,
    ];
    console.log(`  $ ${VSS_RECIPIENT_BINARY} ${args.join(' ')} (spawn)`);
    return spawn(VSS_RECIPIENT_BINARY, args, {
        env: { ...process.env, RUST_LOG: 'info' },
        stdio: 'inherit',
    });
}
