// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Account } from '@aptos-labs/ts-sdk';
import { spawn, type ChildProcess } from 'child_process';

import { NETWORK_NODE_BINARY, LOCALNET_URL } from './config';
import { ed25519PrivateKeyHex } from './helpers';

export type NetworkNodeSpawnInput = {
    runAs: Account;
    /** PKE decryption key bytes as `0x` + hex (TS `decryptionKey.toBytes()`). */
    pkeDkHex: string;
    /** Published module address (`admin` / ace contract). */
    aceContract: string;
    rpcUrl?: string;
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
    const rpc = opts.rpcUrl ?? LOCALNET_URL;
    const accountAddr = opts.runAs.accountAddress.toStringLong();
    const pkeDkHex = opts.pkeDkHex.startsWith('0x') ? opts.pkeDkHex : `0x${opts.pkeDkHex}`;
    const args = [
        'run',
        '--rpc-url', rpc,
        '--ace-contract', opts.aceContract,
        '--account-addr', accountAddr,
        '--account-sk', `0x${pkHex}`,
        '--pke-dk-hex', pkeDkHex,
    ];
    console.log(`  $ ${NETWORK_NODE_BINARY} ${args.join(' ')} (spawn)`);
    return spawn(NETWORK_NODE_BINARY, args, {
        env: { ...process.env, RUST_LOG: 'info' },
        stdio: 'inherit',
    });
}
