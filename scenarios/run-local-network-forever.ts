// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Long-running local network for development / manual exploration.
 *
 * Scenario:
 *   Committee: [A, B, C]  threshold=2  epoch_duration_secs=120 (2 min)
 *   Secrets: 1 (scheme=0, BLS12-381 G1)
 *
 * Flow:
 *   1. Start localnet.
 *   2. Fund 1 admin + 3 worker accounts.
 *   3. Deploy pke, worker_config, group, vss, dkg, dkr, network.
 *   4. Register PKE enc keys for all 3 workers.
 *   5. Admin calls initialize(epoch_duration_secs=120) — enables auto-rotation.
 *   6. Build Rust workspace.
 *   7. Spawn one network-node per worker; each writes to its own tmp log file.
 *      Log paths are printed so you can `tail -f` them.
 *   8. Admin calls start_initial_epoch([A,B,C], threshold=2).
 *   9. Admin calls new_secret(0).
 *  10. Print heartbeat (epoch / secrets / dkgs) every 30 s — run until Ctrl+C.
 *
 * Usage:
 *   pnpm run-local-network-forever
 */

import { Account } from '@aptos-labs/ts-sdk';
import * as ace from '@aptos-labs/ace-sdk';
import { spawn, type ChildProcess } from 'child_process';
import { mkdtempSync, openSync, writeFileSync } from 'fs';
import * as os from 'os';
import * as path from 'path';

import { NETWORK_NODE_BINARY, LOCALNET_URL } from './common/config';
import {
    startLocalnet,
    fundAccount,
    log,
    deployContracts,
    submitTxn,
    sleep,
    getNetworkState,
    ed25519PrivateKeyHex,
} from './common/helpers';
import { buildRustWorkspace } from './common/network-clients';

async function main() {
    const nodeProcs: ChildProcess[] = [];
    let localnetProc: ChildProcess | undefined;

    // ── Graceful shutdown on Ctrl+C ─────────────────────────────────────────
    process.on('SIGINT', () => {
        log('Caught SIGINT — shutting down.');
        for (const proc of nodeProcs) proc.kill();
        localnetProc?.kill();
        process.exit(0);
    });

    // ── Start localnet ───────────────────────────────────────────────────────
    log('Starting localnet...');
    localnetProc = await startLocalnet();

    // ── Accounts ─────────────────────────────────────────────────────────────
    const numWorkers = 3;
    const accounts: Account[] = Array.from({ length: numWorkers + 1 }, () => Account.generate());
    const encKeypairs = Array.from({ length: numWorkers }, () => ace.pke.keygen());
    log(`Funding ${numWorkers + 1} accounts...`);
    for (const account of accounts) {
        await fundAccount(account.accountAddress);
    }

    const adminAccount = accounts[numWorkers]!;
    const workerAccounts = accounts.slice(0, numWorkers);
    const aceContract = adminAccount.accountAddress.toStringLong();
    const threshold = 2;

    // ── Deploy contracts ─────────────────────────────────────────────────────
    log('Deploying contracts...');
    await deployContracts(adminAccount, ['pke', 'worker_config', 'group', 'vss', 'dkg', 'dkr', 'network']);

    // ── Register PKE enc keys + HTTP endpoints ───────────────────────────────
    const WORKER_BASE_PORT = 9000;
    log('Registering PKE enc keys and HTTP endpoints for all workers...');
    for (let i = 0; i < numWorkers; i++) {
        (await submitTxn({
            signer: workerAccounts[i]!,
            entryFunction: `${aceContract}::worker_config::register_pke_enc_key`,
            args: [encKeypairs[i]!.encryptionKey.toBytes()],
        })).unwrapOrThrow('Failed to register PKE key.').asSuccessOrThrow();
        (await submitTxn({
            signer: workerAccounts[i]!,
            entryFunction: `${aceContract}::worker_config::register_endpoint`,
            args: [`http://127.0.0.1:${WORKER_BASE_PORT + i}`],
        })).unwrapOrThrow('Failed to register endpoint.').asSuccessOrThrow();
    }

    // ── Enable auto epoch rotation (2-minute epochs) ─────────────────────────
    log('Admin: initialize(epoch_duration_secs=120)...');
    (await submitTxn({
        signer: adminAccount,
        entryFunction: `${aceContract}::network::initialize`,
        args: [120],
    })).unwrapOrThrow('initialize failed').asSuccessOrThrow();

    // ── Build Rust workspace ─────────────────────────────────────────────────
    log('Building Rust workspace...');
    await buildRustWorkspace();

    // ── Spawn workers, redirect output to tmp log files ──────────────────────
    const logDir = mkdtempSync(path.join(os.tmpdir(), 'ace-network-'));
    log(`Worker log directory: ${logDir}`);

    for (let i = 0; i < numWorkers; i++) {
        const logPath = path.join(logDir, `worker-${i}.log`);
        const logFd = openSync(logPath, 'w');

        const pkHex = ed25519PrivateKeyHex(workerAccounts[i]!);
        const accountAddr = workerAccounts[i]!.accountAddress.toStringLong();
        const pkeDkHex = `0x${Buffer.from(encKeypairs[i]!.decryptionKey.toBytes()).toString('hex')}`;

        const args = [
            'run',
            '--rpc-url', LOCALNET_URL,
            '--ace-contract', aceContract,
            '--account-addr', accountAddr,
            '--account-sk', `0x${pkHex}`,
            '--pke-dk-hex', pkeDkHex,
            '--port', String(WORKER_BASE_PORT + i),
        ];

        const proc = spawn(NETWORK_NODE_BINARY, args, {
            env: { ...process.env, RUST_LOG: 'info' },
            stdio: ['ignore', logFd, logFd],
        });
        nodeProcs.push(proc);

        log(`Worker ${i} (${accountAddr.slice(0, 10)}...) log: tail -f ${logPath}`);
    }

    // ── Start initial epoch ──────────────────────────────────────────────────
    log('Admin: start_initial_epoch([A,B,C], threshold=2)...');
    (await submitTxn({
        signer: adminAccount,
        entryFunction: `${aceContract}::network::start_initial_epoch`,
        args: [
            workerAccounts.map(w => w.accountAddress),
            threshold,
        ],
    })).unwrapOrThrow('start_initial_epoch failed').asSuccessOrThrow();

    // ── Create 1 secret ──────────────────────────────────────────────────────
    log('Admin: new_secret(scheme=0)...');
    (await submitTxn({
        signer: adminAccount,
        entryFunction: `${aceContract}::network::new_secret`,
        args: [0],
    })).unwrapOrThrow('new_secret failed').asSuccessOrThrow();

    // ── Wait for DKG to complete ─────────────────────────────────────────────
    log('Waiting for DKG to complete (workers are running)...');
    const dkgDeadlineMs = Date.now() + 300_000; // 5-minute timeout
    let networkState: ace.network.State | undefined;
    while (Date.now() < dkgDeadlineMs) {
        const maybe = await getNetworkState(adminAccount.accountAddress);
        if (maybe.isOk) {
            networkState = maybe.okValue!;
            if (networkState.dkgsInProgress.length === 0 && networkState.secrets.length >= 1) break;
        }
        await sleep(5_000);
    }
    if (!networkState || networkState.secrets.length < 1) {
        throw 'DKG did not complete within 5 minutes.';
    }
    const keypairId = networkState.secrets[0]!;
    log(`DKG complete. keypairId=${keypairId.toStringLong()}`);

    // ── Write config for example scripts ────────────────────────────────────
    const CONFIG_PATH = '/tmp/ace-localnet-config.json';
    writeFileSync(CONFIG_PATH, JSON.stringify({
        aceContract,
        keypairId: keypairId.toStringLong(),
        rpcUrl: LOCALNET_URL,
    }, null, 2));

    log('');
    log('══════════════════════════════════════════════');
    log('  ACE local network is READY');
    log(`  Config: ${CONFIG_PATH}`);
    log('');
    log('  Run the Solana example:');
    log('    cd examples/shelby-access-control-solana');
    log('    anchor test --provider.cluster localnet');
    log('');
    log('  Run the Aptos example:');
    log('    cd examples/shelby-access-control-aptos/demo-cli-flow');
    log('    pnpm test:localnet');
    log('══════════════════════════════════════════════');
    log('');

    // ── Heartbeat loop (run forever) ─────────────────────────────────────────
    while (true) {
        await sleep(30_000);
        const maybeState = await getNetworkState(adminAccount.accountAddress);
        if (maybeState.isOk) {
            const s = maybeState.okValue!;
            log(`epoch=${s.epoch}  secrets=${s.secrets.length}  dkgs_in_progress=${s.dkgsInProgress.length}  epoch_change=${s.epochChangeState !== null ? 'in_progress' : 'none'}`);
        } else {
            log(`(could not read network state: ${maybeState.errValue})`);
        }
    }
}

main().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
});
