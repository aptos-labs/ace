// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Admin bootstrap for manual ace-cli testing.
 *
 * Flow:
 *   1. Start localnet and deploy all contracts.
 *   2. Print the RPC URL and contract address so operators can fill them
 *      into `ace nodes` → Add new node.
 *   3. Wait while the user runs `ace nodes` for each committee member
 *      (that wizard registers PKE enc keys and endpoints on-chain).
 *   4. Prompt for the initial committee: space-separated addresses,
 *      threshold, and epoch duration.
 *   5. Call network::start_initial_epoch.
 *   6. Print a heartbeat (epoch, secrets, epoch-change status) every 30 s
 *      and block until Ctrl+C.
 *
 * Usage:
 *   pnpm cli-testbed
 */

import * as readline from 'readline';
import { Account, AccountAddress } from '@aptos-labs/ts-sdk';
import { type ChildProcess } from 'child_process';

import { LOCALNET_URL, FAUCET_URL } from './common/config';
import {
    startLocalnet,
    fundAccount,
    log,
    deployContracts,
    submitTxn,
    sleep,
    getNetworkState,
} from './common/helpers';

// ── readline helper ──────────────────────────────────────────────────────────

const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
const ask = (q: string): Promise<string> => new Promise(resolve => rl.question(q, resolve));

// ── main ─────────────────────────────────────────────────────────────────────

async function main() {
    let localnetProc: ChildProcess | undefined;

    process.on('SIGINT', () => {
        log('Caught SIGINT — shutting down.');
        rl.close();
        localnetProc?.kill();
        process.exit(0);
    });

    // ── 1. Start localnet ────────────────────────────────────────────────────
    log('Starting localnet...');
    localnetProc = await startLocalnet();

    // ── 2. Deploy contracts ──────────────────────────────────────────────────
    const adminAccount = Account.generate();
    await fundAccount(adminAccount.accountAddress);
    const aceContract = adminAccount.accountAddress.toStringLong();

    log('Deploying contracts...');
    await deployContracts(adminAccount, [
        'pke', 'worker_config', 'group', 'fiat-shamir-transform',
        'sigma-dlog-eq', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network',
    ]);

    // ── 3. Print connection info ─────────────────────────────────────────────
    log('');
    log('══════════════════════════════════════════════════════════');
    log('  Contracts deployed. Set these in `ace nodes` → Add new node:');
    log('');
    log(`  Deployment API URL : ${LOCALNET_URL}`);
    log(`  Contract address   : ${aceContract}`);
    log('');
    log('  Run `ace nodes` for each committee member to register their');
    log('  PKE enc key and endpoint on-chain, then return here.');
    log('══════════════════════════════════════════════════════════');
    log('');

    // ── 4. Collect initial epoch parameters from the user ────────────────────
    await ask('Press Enter when all nodes have been registered via `ace nodes`... ');

    const rawAddrs = await ask('Committee addresses (space-separated): ');
    const nodeAddresses = rawAddrs
        .trim()
        .split(/\s+/)
        .filter(Boolean)
        .map(s => AccountAddress.fromString(s));

    if (nodeAddresses.length === 0) {
        throw new Error('No addresses provided.');
    }

    const rawThreshold = await ask(`Threshold (2 ≤ t ≤ ${nodeAddresses.length}, 2t > ${nodeAddresses.length}): `);
    const threshold = parseInt(rawThreshold.trim(), 10);
    if (isNaN(threshold) || threshold < 2 || threshold > nodeAddresses.length || 2 * threshold <= nodeAddresses.length) {
        throw new Error(`Invalid threshold: ${rawThreshold}`);
    }

    const rawDuration = await ask('Epoch duration in seconds (min 30): ');
    const epochDuration = parseInt(rawDuration.trim(), 10);
    if (isNaN(epochDuration) || epochDuration < 30) {
        throw new Error(`Invalid epoch duration: ${rawDuration}`);
    }

    rl.close();

    // ── 5. start_initial_epoch ───────────────────────────────────────────────
    log(`Calling start_initial_epoch(nodes=${nodeAddresses.length}, threshold=${threshold}, duration=${epochDuration}s)...`);
    (await submitTxn({
        signer: adminAccount,
        entryFunction: `${aceContract}::network::start_initial_epoch`,
        args: [nodeAddresses, threshold, epochDuration],
    })).unwrapOrThrow('start_initial_epoch failed').asSuccessOrThrow();

    // ── 6. Ready ─────────────────────────────────────────────────────────────
    log('');
    log('══════════════════════════════════════════════════════════');
    log('  Network is live (epoch 0).');
    log('');
    log(`  ace network status --profile <any-committee-member>`);
    log(`  ace proposal       --profile <any-committee-member>`);
    log('');
    log('  Ctrl+C to stop.');
    log('══════════════════════════════════════════════════════════');
    log('');

    // ── Heartbeat + fund current-epoch nodes ─────────────────────────────────
    while (true) {
        await sleep(30_000);
        const maybe = await getNetworkState(adminAccount.accountAddress);
        if (maybe.isOk) {
            const s = maybe.okValue!;
            log(`epoch=${s.epoch}  secrets=${s.secrets.length}  epoch_change=${s.isEpochChanging() ? 'in_progress' : 'none'}  proposals=${s.activeProposals().length}`);

            // Fund every node in the current committee so touch() never runs dry.
            for (const node of s.curNodes) {
                try {
                    const addr = node.toStringLong();
                    const resp = await fetch(`${FAUCET_URL}/mint?amount=1000000000&address=${addr}`, { method: 'POST' });
                    if (resp.ok) log(`funded ${addr.slice(0, 10)}...`);
                } catch { /* non-fatal */ }
            }
        } else {
            log(`(could not read network state: ${maybe.errValue})`);
        }
    }
}

main().catch(err => {
    console.error('Fatal:', err);
    process.exit(1);
});
