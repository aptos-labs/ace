// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * CI scenario: stand up the ACE local network, then run `anchor test` against
 * scenarios/custom-flow-solana.
 *
 * Flow:
 *   1. Start Aptos localnet.
 *   2. Fund 1 admin + 3 worker accounts.
 *   3. Deploy ACE contracts.
 *   4. Register PKE enc keys + HTTP endpoints for all workers.
 *   5. Build Rust workspace.
 *   6. Spawn one network-node per worker.
 *   7. Start initial epoch + propose 2 new_secrets in one epoch change; wait
 *      for DKG. The 2nd keypair is used by the failures sub-test as the
 *      mismatching keypair_id (step A); the 1st is used by happy-path.
 *   8. Write /tmp/ace-localnet-config.json for the Solana test to consume.
 *   9. Generate a throw-away Solana wallet if none exists.
 *  10. Build the Anchor program (3-step: build → keys sync → build) so that
 *      the program ID is stable before testing.
 *  11. Run `anchor test --skip-build --provider.cluster localnet`.
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
    serializeNewSecretsProposal,
} from './common/helpers';
import { buildRustWorkspace, killStaleNetworkNodes, spawnNetworkNodeMaybeSplit } from './common/network-clients';

const SOLANA_EXAMPLE_DIR = path.join(REPO_ROOT, 'scenarios', 'custom-flow-solana');
const NUM_WORKERS = 3;
// Two DKG'd secrets in a single epoch change; happy-path uses keypair[0],
// failures step-A uses keypair[1] as the mismatching id.
const PRIMITIVES = [1, 1];

interface AceLocalnet {
    localnetProc: ChildProcess;
    nodeProcs: ChildProcess[];
    adminAccount: Account;
    workerAccounts: Account[];
    aceContract: string;
}

async function main() {
    let setup: AceLocalnet | undefined;
    const cleanup = () => {
        if (setup) for (const p of setup.nodeProcs) p.kill();
        setup?.localnetProc.kill();
    };
    process.on('SIGINT', () => { cleanup(); process.exit(1); });
    process.on('SIGTERM', () => { cleanup(); process.exit(1); });
    try {
        setup = await bringUpAceLocalnetWithWorkers(NUM_WORKERS);
        const networkState = await startInitialEpochAndDkgSecrets({
            admin: setup.adminAccount, workers: setup.workerAccounts,
            aceContract: setup.aceContract, threshold: 2,
            reshareIntervalSecs: 3600, primitives: PRIMITIVES, timeoutMs: 300_000,
        });
        const keypairIds = networkState.secrets.map(s => s.keypairId.toStringLong());
        log(`DKG complete. keypairIds=[${keypairIds.join(', ')}]`);
        writeSolanaTestConfig({
            apiEndpoint: LOCALNET_URL, contractAddr: setup.aceContract, keypairIds,
        });
        ensureSolanaWallet();
        buildAnchorProgramThreeStep(SOLANA_EXAMPLE_DIR);
        const exitCode = await runAnchorTest(SOLANA_EXAMPLE_DIR);
        if (exitCode !== 0) throw `anchor test exited with code ${exitCode}`;
        log('Solana custom-flow tests passed.');
    } finally {
        cleanup();
    }
}

/** Start Aptos localnet, fund admin + worker accounts, deploy ACE Move
 *  modules, register each worker's PKE enc key + HTTP endpoint, build the
 *  Rust workspace, and spawn one network-node per worker. */
async function bringUpAceLocalnetWithWorkers(numWorkers: number): Promise<AceLocalnet> {
    log('Starting Aptos localnet...');
    const localnetProc = await startLocalnet();
    const accounts: Account[] = Array.from({ length: numWorkers + 1 }, () => Account.generate());
    const encKeypairs = await Promise.all(Array.from({ length: numWorkers }, () => ace.pke.keygen()));
    log(`Funding ${numWorkers + 1} accounts...`);
    for (const account of accounts) await fundAccount(account.accountAddress);
    const adminAccount = accounts[numWorkers]!;
    const workerAccounts = accounts.slice(0, numWorkers);
    const aceContract = adminAccount.accountAddress.toStringLong();
    log('Deploying ACE contracts...');
    await deployContracts(adminAccount, [
        'pke', 'worker_config', 'group', 'secret-usage', 'fiat-shamir-transform',
        'sigma-dlog-linear', 'pedersen-polynomial-commitment', 'vss', 'dkg', 'dkr', 'epoch-change', 'voting', 'network',
    ]);
    await registerWorkersOnChain(workerAccounts, encKeypairs, aceContract);
    log('Building Rust workspace...');
    await buildRustWorkspace();
    killStaleNetworkNodes();
    const nodeProcs = spawnAceWorkers(workerAccounts, encKeypairs, aceContract);
    return { localnetProc, nodeProcs, adminAccount, workerAccounts, aceContract };
}

async function registerWorkersOnChain(
    workers: Account[],
    encKeypairs: { encryptionKey: ace.pke.EncryptionKey; decryptionKey: ace.pke.DecryptionKey }[],
    aceContract: string,
): Promise<void> {
    log('Registering PKE enc keys and HTTP endpoints...');
    for (let i = 0; i < workers.length; i++) {
        (await submitTxn({
            signer: workers[i]!,
            entryFunction: `${aceContract}::worker_config::register_pke_enc_key`,
            args: [encKeypairs[i]!.encryptionKey.toBytes()],
        })).unwrapOrThrow('register_pke_enc_key failed').asSuccessOrThrow();
        (await submitTxn({
            signer: workers[i]!,
            entryFunction: `${aceContract}::worker_config::register_endpoint`,
            args: [`http://127.0.0.1:${WORKER_BASE_PORT + i}`],
        })).unwrapOrThrow('register_endpoint failed').asSuccessOrThrow();
    }
}

function spawnAceWorkers(
    workers: Account[],
    encKeypairs: { encryptionKey: ace.pke.EncryptionKey; decryptionKey: ace.pke.DecryptionKey }[],
    aceContract: string,
): ChildProcess[] {
    const nodeProcs: ChildProcess[] = [];
    for (let i = 0; i < workers.length; i++) {
        const pkeDkHex = `0x${Buffer.from(encKeypairs[i]!.decryptionKey.toBytes()).toString('hex')}`;
        nodeProcs.push(...spawnNetworkNodeMaybeSplit({
            index: i, total: workers.length, runAs: workers[i]!, pkeDkHex,
            aceDeploymentAddr: aceContract, aceDeploymentApi: LOCALNET_URL,
            workerBasePort: WORKER_BASE_PORT,
        }));
    }
    return nodeProcs;
}

/** Drive the on-chain ACE state machine through `start_initial_epoch` →
 *  propose `primitives.length` new secrets in one epoch change → wait for the
 *  DKGs to complete. Returns the network-state snapshot at the moment all
 *  DKGs are done. */
async function startInitialEpochAndDkgSecrets(args: {
    admin: Account; workers: Account[]; aceContract: string;
    threshold: number; reshareIntervalSecs: number;
    primitives: number[]; timeoutMs: number;
}): Promise<ace.network.State> {
    log(`Admin: start_initial_epoch (resharing_interval_secs=${args.reshareIntervalSecs})...`);
    (await submitTxn({
        signer: args.admin,
        entryFunction: `${args.aceContract}::network::start_initial_epoch`,
        args: [args.workers.map(w => w.accountAddress), args.threshold, args.reshareIntervalSecs],
    })).unwrapOrThrow('start_initial_epoch failed').asSuccessOrThrow();
    log(`Admin: propose ${args.primitives.length} new_secret entries; workers 0,1 approve...`);
    await proposeAndApprove(
        args.workers[0]!, args.workers.slice(0, 2),
        args.aceContract, serializeNewSecretsProposal(args.primitives),
    );
    log(`Waiting for DKG (${args.primitives.length} secrets) to complete...`);
    const deadline = Date.now() + args.timeoutMs;
    let networkState: ace.network.State | undefined;
    while (Date.now() < deadline) {
        const maybe = await getNetworkState(args.admin.accountAddress);
        if (maybe.isOk) {
            networkState = maybe.okValue!;
            if (networkState.epochChangeInfo === null && networkState.secrets.length >= args.primitives.length) break;
        }
        await sleep(5_000);
    }
    if (!networkState || networkState.secrets.length < args.primitives.length) {
        throw `DKG did not complete within ${args.timeoutMs / 1000}s.`;
    }
    return networkState;
}

/** Write the per-test config (Aptos RPC endpoint, deployed contract
 *  address, DKG'd keypair_ids) to `/tmp/ace-localnet-config.json`. */
function writeSolanaTestConfig(args: {
    apiEndpoint: string; contractAddr: string; keypairIds: string[];
}): void {
    const CONFIG_PATH = '/tmp/ace-localnet-config.json';
    writeFileSync(CONFIG_PATH, JSON.stringify({
        apiEndpoint: args.apiEndpoint,
        contractAddr: args.contractAddr,
        keypairIds: args.keypairIds,
    }, null, 2));
    log(`Config written to ${CONFIG_PATH}`);
}

function ensureSolanaWallet(): void {
    const walletPath = path.join(os.homedir(), '.config', 'solana', 'id.json');
    if (!existsSync(walletPath)) {
        log('Generating throw-away Solana wallet...');
        execSync(`solana-keygen new --no-bip39-passphrase -o ${walletPath} --force`, { stdio: 'inherit' });
    }
}

/** Anchor's first build generates a fresh program keypair; `anchor keys
 *  sync` patches `declare_id!` + `Anchor.toml` to match; the second build
 *  compiles with the correct program ID baked in. Required only for fresh
 *  checkouts where the program-keypair file doesn't exist yet. */
function buildAnchorProgramThreeStep(cwd: string): void {
    log('Building Anchor program (step 1/3: initial build)...');
    execSync('anchor build', { cwd, stdio: 'inherit' });
    log('Building Anchor program (step 2/3: sync keys)...');
    execSync('anchor keys sync', { cwd, stdio: 'inherit' });
    log('Building Anchor program (step 3/3: rebuild with correct program ID)...');
    execSync('anchor build', { cwd, stdio: 'inherit' });
}

async function runAnchorTest(cwd: string): Promise<number> {
    log('Running: anchor test --skip-build --provider.cluster localnet');
    const proc = spawn(
        'anchor', ['test', '--skip-build', '--provider.cluster', 'localnet'],
        { cwd, stdio: 'inherit' },
    );
    return new Promise<number>((resolve) => proc.on('close', resolve));
}

main().catch(err => {
    console.error('Fatal error:', err);
    process.exit(1);
});
