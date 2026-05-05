// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * CI scenario: stand up the ACE local network, then run `anchor test` against
 * the pay-to-download-solana example.
 *
 * Flow:
 *   1. Start Aptos localnet.
 *   2. Fund 1 admin + 3 worker accounts.
 *   3. Deploy ACE contracts.
 *   4. Register PKE enc keys + HTTP endpoints for all workers.
 *   5. Initialize network (epoch_duration_secs=3600 — no auto-rotation during test).
 *   6. Build Rust workspace.
 *   7. Spawn one network-node per worker.
 *   8. Start initial epoch and create 1 secret; wait for DKG.
 *   9. Write /tmp/ace-localnet-config.json for the Solana test to consume.
 *  10. Generate a throw-away Solana wallet if none exists.
 *  11. Run `anchor test --provider.cluster localnet` in the example directory.
 *  12. Exit with anchor's exit code.
 */

import { Account } from '@aptos-labs/ts-sdk';
import * as ace from '@aptos-labs/ace-sdk';
import { execSync, spawn, type ChildProcess } from 'child_process';
import { existsSync, writeFileSync } from 'fs';
import * as os from 'os';
import * as path from 'path';

import { LOCALNET_URL, REPO_ROOT, WORKER_BASE_PORT } from './common/config';
import {
    startLocalnet,
    fundAccount,
    log,
    deployContracts,
    submitTxn,
    sleep,
    getNetworkState,
    proposeAndApprove,
    serializeNewSecretProposal,
} from './common/helpers';
import { buildRustWorkspace, killStaleNetworkNodes, spawnNetworkNode } from './common/network-clients';

const SOLANA_EXAMPLE_DIR = path.join(REPO_ROOT, 'examples', 'pay-to-download-solana');
const NUM_WORKERS = 3;

async function main() {
    const nodeProcs: ChildProcess[] = [];
    let localnetProc: ChildProcess | undefined;

    const cleanup = () => {
        for (const proc of nodeProcs) proc.kill();
        localnetProc?.kill();
    };
    process.on('SIGINT', () => { cleanup(); process.exit(1); });
    process.on('SIGTERM', () => { cleanup(); process.exit(1); });

    try {
        // ── Start Aptos localnet ─────────────────────────────────────────────
        log('Starting Aptos localnet...');
        localnetProc = await startLocalnet();

        // ── Accounts ─────────────────────────────────────────────────────────
        const accounts: Account[] = Array.from({ length: NUM_WORKERS + 1 }, () => Account.generate());
        const encKeypairs = await Promise.all(Array.from({ length: NUM_WORKERS }, () => ace.pke.keygen()));
        log(`Funding ${NUM_WORKERS + 1} accounts...`);
        for (const account of accounts) {
            await fundAccount(account.accountAddress);
        }

        const adminAccount = accounts[NUM_WORKERS]!;
        const workerAccounts = accounts.slice(0, NUM_WORKERS);
        const aceContract = adminAccount.accountAddress.toStringLong();

        // ── Deploy contracts ─────────────────────────────────────────────────
        log('Deploying ACE contracts...');
        await deployContracts(adminAccount, ['pke', 'worker_config', 'group', 'fiat-shamir-transform', 'sigma-dlog-eq', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network']);

        // ── Register PKE enc keys + HTTP endpoints ───────────────────────────
        log('Registering PKE enc keys and HTTP endpoints...');
        for (let i = 0; i < NUM_WORKERS; i++) {
            (await submitTxn({
                signer: workerAccounts[i]!,
                entryFunction: `${aceContract}::worker_config::register_pke_enc_key`,
                args: [encKeypairs[i]!.encryptionKey.toBytes()],
            })).unwrapOrThrow('register_pke_enc_key failed').asSuccessOrThrow();
            (await submitTxn({
                signer: workerAccounts[i]!,
                entryFunction: `${aceContract}::worker_config::register_endpoint`,
                args: [`http://127.0.0.1:${WORKER_BASE_PORT + i}`],
            })).unwrapOrThrow('register_endpoint failed').asSuccessOrThrow();
        }

        // ── Build Rust workspace ─────────────────────────────────────────────
        log('Building Rust workspace...');
        await buildRustWorkspace();

        // ── Kill any stale worker processes from prior runs ──────────────────
        killStaleNetworkNodes();

        // ── Spawn workers ────────────────────────────────────────────────────
        for (let i = 0; i < NUM_WORKERS; i++) {
            const pkeDkHex = `0x${Buffer.from(encKeypairs[i]!.decryptionKey.toBytes()).toString('hex')}`;
            nodeProcs.push(spawnNetworkNode({
                runAs: workerAccounts[i]!,
                pkeDkHex,
                aceDeploymentAddr: aceContract,
                aceDeploymentApi: LOCALNET_URL,
                port: WORKER_BASE_PORT + i,
            }));
        }

        // ── Start initial epoch + propose new_secret ─────────────────────────
        // resharing_interval_secs=3600: no auto-rotation during test
        log('Admin: start_initial_epoch (resharing_interval_secs=3600)...');
        (await submitTxn({
            signer: adminAccount,
            entryFunction: `${aceContract}::network::start_initial_epoch`,
            args: [workerAccounts.map(w => w.accountAddress), 2, 3600],
        })).unwrapOrThrow('start_initial_epoch failed').asSuccessOrThrow();

        log('Admin: propose new_secret; workers 0,1 approve...');
        const newSecretApprovers = workerAccounts.slice(0, 2);
        await proposeAndApprove(
            newSecretApprovers[0]!,
            newSecretApprovers,
            aceContract,
            serializeNewSecretProposal(1),
        );

        log('Waiting for DKG epoch change to complete...');
        const deadline = Date.now() + 300_000;
        let networkState: ace.network.State | undefined;
        while (Date.now() < deadline) {
            const maybe = await getNetworkState(adminAccount.accountAddress);
            if (maybe.isOk) {
                networkState = maybe.okValue!;
                if (networkState.epochChangeInfo === null && networkState.secrets.length >= 1) break;
            }
            await sleep(5_000);
        }
        if (!networkState || networkState.secrets.length < 1) {
            throw 'DKG did not complete within 5 minutes.';
        }
        log(`DKG complete. keypairId=${networkState.secrets[0]!.keypairId.toStringLong()}`);

        // ── Write config for the Solana test ─────────────────────────────────
        const CONFIG_PATH = '/tmp/ace-localnet-config.json';
        writeFileSync(CONFIG_PATH, JSON.stringify({
            apiEndpoint: LOCALNET_URL,
            contractAddr: aceContract,
            keypairId: networkState.secrets[0]!.keypairId.toStringLong(),
        }, null, 2));
        log(`Config written to ${CONFIG_PATH}`);

        // ── Ensure a Solana wallet exists ─────────────────────────────────────
        const walletPath = path.join(os.homedir(), '.config', 'solana', 'id.json');
        if (!existsSync(walletPath)) {
            log('Generating throw-away Solana wallet...');
            execSync(`solana-keygen new --no-bip39-passphrase -o ${walletPath} --force`, { stdio: 'inherit' });
        }

        // ── Run anchor test ───────────────────────────────────────────────────
        log('Running: anchor test --provider.cluster localnet');
        const anchorProc = spawn('anchor', ['test', '--provider.cluster', 'localnet'], {
            cwd: SOLANA_EXAMPLE_DIR,
            stdio: 'inherit',
        });
        const exitCode = await new Promise<number>((resolve) => {
            anchorProc.on('close', resolve);
        });
        if (exitCode !== 0) throw `anchor test exited with code ${exitCode}`;

        log('Solana example tests passed.');
    } finally {
        cleanup();
    }
}

main().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
});
