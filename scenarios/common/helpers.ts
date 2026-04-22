// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import * as ace from '@aptos-labs/ace-sdk';
import { Result } from '@aptos-labs/ace-sdk';
import { Account, AccountAddress, Aptos, AptosConfig, Network } from '@aptos-labs/ts-sdk';
import { execFile, spawn, type ChildProcess } from 'child_process';
import * as readline from 'readline';
import {
    cpSync,
    existsSync,
    mkdtempSync,
    readFileSync,
    readdirSync,
    rmSync,
    writeFileSync,
} from 'fs';
import * as os from 'os';
import * as path from 'path';

import { ADMIN_PLACEHOLDER_FOR_MOVE_TOML, LOCALNET_URL, FAUCET_URL, REPO_ROOT } from './config';

export function log(msg: string): void { console.log(`[${new Date().toISOString()}] ${msg}`); }

export function assert(condition: boolean, msg: string) {
    if (!condition) throw new Error(`Assertion failed: ${msg}`);
}

export function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

export async function waitFor(
    label: string,
    checkFn: () => Promise<boolean>,
    timeoutMs = 30_000,
    intervalMs = 1_000,
): Promise<void> {
    const deadline = Date.now() + timeoutMs;
    while (Date.now() < deadline) {
        if (await checkFn()) return;
        await sleep(intervalMs);
    }
    throw new Error(`Timeout waiting for: ${label}`);
}

export function createAptos(): Aptos {
    return new Aptos(new AptosConfig({
        network: Network.CUSTOM,
        fullnode: LOCALNET_URL,
        faucet: FAUCET_URL,
    }));
}

function spawnExitZero(cmd: string, args: string[], label: string): Promise<void> {
    return new Promise((resolve, reject) => {
        const child = spawn(cmd, args, { stdio: 'inherit' });
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

export type ContractsPublishScratch = {
    /** Temp root; delete entire tree when done. */
    tmpRoot: string;
    /** Copy of `contractsRoot` with `Move.toml` admin placeholder patched to the real address. */
    contractsDir: string;
};

function patchMoveTomlAdminPlaceholders(contractsDir: string, adminAddressStr: string): void {
    const ph = ADMIN_PLACEHOLDER_FOR_MOVE_TOML;
    const walk = (dir: string): void => {
        for (const ent of readdirSync(dir, { withFileTypes: true })) {
            const full = path.join(dir, ent.name);
            if (ent.isDirectory()) {
                walk(full);
            } else if (ent.name === 'Move.toml') {
                const text = readFileSync(full, 'utf8');
                if (!text.includes(ph)) continue;
                writeFileSync(full, text.replaceAll(ph, adminAddressStr), 'utf8');
            }
        }
    };
    walk(contractsDir);
}

/**
 * Copy `contractsRoot` into a temp directory and replace {@link ADMIN_PLACEHOLDER_FOR_MOVE_TOML} in every `Move.toml`.
 */
export function prepareContractsPublishScratch(contractsRoot: string, adminAddressStr: string): ContractsPublishScratch {
    const tmpRoot = mkdtempSync(path.join(os.tmpdir(), 'ace-contracts-'));
    const contractsDir = path.join(tmpRoot, 'publish-root');
    cpSync(contractsRoot, contractsDir, { recursive: true });
    patchMoveTomlAdminPlaceholders(contractsDir, adminAddressStr);
    return { tmpRoot, contractsDir };
}

export function rmContractsPublishScratch(scratch: ContractsPublishScratch): void {
    rmSync(scratch.tmpRoot, { recursive: true, force: true });
}

export async function publishMovePackage(packageDir: string, privateKeyHex: string): Promise<void> {
    const args = [
        'move',
        'publish',
        '--package-dir',
        packageDir,
        '--private-key',
        `0x${privateKeyHex}`,
        '--url',
        LOCALNET_URL,
        '--assume-yes',
        '--skip-fetch-latest-git-deps',
    ];
    console.log(`  $ aptos ${args.join(' ')}`);
    await spawnExitZero('aptos', args, 'aptos move publish');
}

/** Hex (no `0x`) for an Ed25519-backed `Account` (e.g. `generate()` / `fromPrivateKey`). */
export function ed25519PrivateKeyHex(account: Account): string {
    if (!('privateKey' in account)) {
        throw new Error('deployContracts requires an Ed25519-backed Account (e.g. from generate() or fromPrivateKey())');
    }
    const pk = account.privateKey as { toUint8Array(): Uint8Array };
    return Buffer.from(pk.toUint8Array()).toString('hex');
}

/** Publish Move packages under `REPO_ROOT/contracts/<folder>` in order (one `aptos move publish` per folder). */
export async function deployContracts(adminAccount: Account, packageFolders: string[]): Promise<void> {
    const adminAddr = adminAccount.accountAddress.toStringLong();
    const adminKeyHex = ed25519PrivateKeyHex(adminAccount);
    const scratch = prepareContractsPublishScratch(path.join(REPO_ROOT, 'contracts'), adminAddr);
    try {
        for (const folder of packageFolders) {
            const packageDir = path.join(scratch.contractsDir, folder);
            if (!existsSync(path.join(packageDir, 'Move.toml'))) {
                throw new Error(`missing Move package at ${packageDir}`);
            }
            await publishMovePackage(packageDir, adminKeyHex);
        }
    } finally {
        rmContractsPublishScratch(scratch);
    }
}

export async function fundAccount(address: AccountAddress): Promise<void> {
    const aptos = createAptos();
    // Call the faucet directly so we can wait on the REST API (no indexer needed).
    const resp = await fetch(
        `${FAUCET_URL}/mint?amount=1000000000&address=${address.toStringLong()}`,
        { method: 'POST' },
    );
    if (!resp.ok) throw new Error(`Faucet error: ${resp.status} ${await resp.text()}`);
    const hashes = (await resp.json()) as string[];
    for (const hash of hashes) {
        await aptos.waitForTransaction({ transactionHash: hash });
    }
}

export async function callView(aptos: Aptos, contractAddr: string, mod: string, fn: string, extraArgs: any[]): Promise<any[]> {
    return aptos.view({
        payload: {
            function: `${contractAddr}::${mod}::${fn}` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [contractAddr, ...extraArgs],
        },
    });
}

export class CommittedTxnSuccess {
    readonly transactionHash: string;
    readonly events: any[];

    constructor(transactionHash: string, events: any[]) {
        this.transactionHash = transactionHash;
        this.events = events;
    }
}

export class CommittedTxnAbort {
    readonly transactionHash: string;
    readonly abortCode: number;
    readonly vmStatus: string;

    constructor(transactionHash: string, abortCode: number, vmStatus: string) {
        this.transactionHash = transactionHash;
        this.abortCode = abortCode;
        this.vmStatus = vmStatus;
    }
}

export class CommittedTxn {
    readonly succeeded: boolean;
    readonly inner: any;
    
    constructor(succeeded: boolean, inner: any) {
        this.succeeded = succeeded;
        this.inner = inner;
    }

    asSuccessOrThrow(): CommittedTxnSuccess {
        if (!this.succeeded) {
            throw new Error(`Committed transaction failed: ${this.inner}`);
        }
        return this.inner as CommittedTxnSuccess;
    }

    asAbortOrThrow(): CommittedTxnAbort {
        if (this.succeeded) {
            throw new Error(`Committed transaction succeeded: ${this.inner}`);
        }
        return this.inner as CommittedTxnAbort;
    }
}

/** Parse Move abort code from `vm_status` tail (`...: 0xN` or `...: N`). */
function parseMoveAbortCode(vmStatus: string): number | undefined {
    const m = vmStatus.match(/:\s*(0x[0-9a-fA-F]+|\d+)\s*$/);
    if (!m) return undefined;
    const s = m[1]!;
    return s.startsWith('0x') ? parseInt(s.slice(2), 16) : parseInt(s, 10);
}

/**
 * Submit an entry function against {@link createAptos} (localnet). Returns {@link Result} with
 * infrastructure errors, or Ok({@link CommittedTxn}) when the txn is committed (success or Move abort).
 */
export async function submitTxn(
    {
        signer,
        entryFunction,
        args,
    }: {
        signer: Account,
        entryFunction: `${string}::${string}::${string}`,
        args: any[],
    }
): Promise<Result<CommittedTxn>> {
    return Result.captureAsync({
        recordsExecutionTimeMs: false,
        task: async () => {
            const aptos = createAptos();
            const txn = await aptos.transaction.build.simple({
                sender: signer.accountAddress,
                data: {
                    function: entryFunction,
                    typeArguments: [],
                    functionArguments: args,
                },
            });
            const pending = await aptos.signAndSubmitTransaction({ signer, transaction: txn });
            const hash = pending.hash;
            let waited = await aptos.waitForTransaction({ transactionHash: hash }) as Record<string, unknown>;
            // On a fast localnet the node sometimes returns the committed transaction
            // before its events are fully written (race condition).  Re-fetch once to
            // let the node catch up.
            if (!((waited.events as unknown[])?.length)) {
                await new Promise(r => setTimeout(r, 200));
                waited = await aptos.getTransactionByHash({ transactionHash: hash }) as Record<string, unknown>;
            }
            const events = (waited.events as unknown[]) ?? [];
            const success = waited.success as boolean;
            const vmStatus = String(waited.vm_status ?? '');
            if (!success) {
                const parsed = parseMoveAbortCode(vmStatus);
                return new CommittedTxn(
                    false,
                    new CommittedTxnAbort(hash, parsed ?? 0, vmStatus),
                );
            }
            return new CommittedTxn(true, new CommittedTxnSuccess(hash, events));
        },
    });
}

/** Throws if the txn failed to commit, or committed with a Move abort. */
export function assertTxnSuccess(result: Result<CommittedTxn>, label: string): CommittedTxnSuccess {
    if (!result.isOk) {
        throw new Error(`${label}: ${result.errValue}`);
    }
    const v = result.okValue!;
    if (!v.succeeded) {
        const a = v.asAbortOrThrow();
        throw new Error(`${label}: Move abort code=${a.abortCode} vm_status=${a.vmStatus}`);
    }
    return v.asSuccessOrThrow();
}

function urlPort(urlStr: string): number {
    const u = new URL(urlStr);
    return u.port ? Number(u.port) : u.protocol === 'https:' ? 443 : 80;
}

/** True when REST and faucet both respond OK (same notion of "healthy" as wait in startLocalnet). */
async function localnetAndFaucetReachable(): Promise<boolean> {
    try {
        const [rpc, faucet] = await Promise.all([
            fetch(LOCALNET_URL, { signal: AbortSignal.timeout(1000) }),
            fetch(`${FAUCET_URL}/`, { signal: AbortSignal.timeout(1000) }),
        ]);
        return rpc.ok && faucet.ok;
    } catch {
        return false;
    }
}

/**
 * Prompts on a TTY: whether to kill the existing localnet. Resolves after one line of input or 10s with no complete line.
 */
function promptKillExistingLocalnet(): Promise<'yes' | 'no' | 'timeout'> {
    return new Promise(resolve => {
        const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
        const q =
            `A localnet appears to be running at ${LOCALNET_URL}.\n` +
            `Kill it and start a fresh one? [y/N] `;
        let settled = false;
        const finish = (v: 'yes' | 'no' | 'timeout') => {
            if (settled) return;
            settled = true;
            clearTimeout(timer);
            rl.close();
            resolve(v);
        };
        const timer = setTimeout(() => finish('timeout'), 10_000);
        rl.question(q, answer => {
            const a = answer.trim().toLowerCase();
            if (a === 'y' || a === 'yes') finish('yes');
            else finish('no');
        });
    });
}

function lsofListeningPids(port: number): Promise<number[]> {
    return new Promise(resolve => {
        execFile(
            'lsof',
            ['-nP', `-iTCP:${port}`, '-sTCP:LISTEN', '-t'],
            { encoding: 'utf8' },
            (err, stdout) => {
                if (err) {
                    resolve([]);
                    return;
                }
                const pids = stdout
                    .trim()
                    .split('\n')
                    .filter(Boolean)
                    .map(s => Number(s))
                    .filter(n => !Number.isNaN(n));
                resolve([...new Set(pids)]);
            },
        );
    });
}

async function killListenersOnPort(port: number): Promise<void> {
    const tryKill = async (signal: NodeJS.Signals) => {
        const pids = await lsofListeningPids(port);
        for (const pid of pids) {
            try {
                process.kill(pid, signal);
            } catch {
                // ESRCH or EPERM — ignore
            }
        }
    };
    await tryKill('SIGTERM');
    await sleep(500);
    await tryKill('SIGKILL');
}

async function killExistingLocalnetListeners(): Promise<void> {
    if (process.platform === 'win32') {
        throw new Error(
            'Cannot automatically free localnet ports on Windows. Stop the process using the REST/faucet ports, then retry.',
        );
    }
    const restPort = urlPort(LOCALNET_URL);
    const faucetPort = urlPort(FAUCET_URL);
    await killListenersOnPort(restPort);
    await killListenersOnPort(faucetPort);
}

export async function startLocalnet(): Promise<ChildProcess> {
    const localnetAlreadyUp = await (async () => {
        try {
            const r = await fetch(LOCALNET_URL, { signal: AbortSignal.timeout(1000) });
            return r.ok;
        } catch {
            return false;
        }
    })();
    if (localnetAlreadyUp) {
        if (!process.stdin.isTTY) {
            throw new Error(
                `A localnet is already running at ${LOCALNET_URL}.\n` +
                    `Please shut it down before running this test, or re-run in a terminal to be prompted to kill it.\n` +
                    `Interactive confirmation requires a TTY stdin.`,
            );
        }
        const choice = await promptKillExistingLocalnet();
        if (choice === 'timeout') {
            throw new Error(
                `No response within 10 seconds while a localnet is still running at ${LOCALNET_URL}.\n` +
                    `Please shut it down before running this test.`,
            );
        }
        if (choice === 'no') {
            throw new Error('Declined to shut down the existing localnet; aborting.');
        }
        await killExistingLocalnetListeners();
        await waitFor(
            'existing localnet stopped',
            async () => !(await localnetAndFaucetReachable()),
            30_000,
            500,
        );
    }

    const localnetProc = spawn(
        'aptos',
        ['node', 'run-local-testnet', '--with-faucet', '--force-restart', '--assume-yes'],
        { stdio: ['ignore', 'pipe', 'pipe'] },
    );
    localnetProc.stdout?.on('data', (d: Buffer) => process.stdout.write(`  [localnet] ${d}`));
    localnetProc.stderr?.on('data', (d: Buffer) => process.stderr.write(`  [localnet] ${d}`));

    await waitFor(
        'localnet healthy',
        async () => {
            try {
                const [rpc, faucet] = await Promise.all([
                    fetch(LOCALNET_URL, { signal: AbortSignal.timeout(1000) }),
                    fetch(`${FAUCET_URL}/`, { signal: AbortSignal.timeout(1000) }),
                ]);
                return rpc.ok && faucet.ok;
            } catch {
                return false;
            }
        },
        60_000,
        1_000,
    );

    return localnetProc;
}

export async function getVssSession(aceContractAddr: AccountAddress, sessionAddr: AccountAddress): Promise<Result<ace.vss.Session>> {
    return Result.captureAsync({
        recordsExecutionTimeMs: false,
        task: async () => {
            const aptos = createAptos();
            const [hexBytes] = await aptos.view({
                payload: {
                    function: `${aceContractAddr.toStringLong()}::vss::get_session_bcs` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [sessionAddr.toStringLong()],
                },
            });
            const bytes = new Uint8Array(Buffer.from((hexBytes as string).replace(/^0x/, ''), 'hex'));
            return ace.vss.Session.fromBytes(bytes).unwrapOrThrow('Failed to parse session.');
        },
    });
}

export async function getDKGSession(aceContractAddr: AccountAddress, sessionAddr: AccountAddress): Promise<Result<ace.dkg.Session>> {
    return Result.captureAsync({
        recordsExecutionTimeMs: false,
        task: async () => {
            const aptos = createAptos();
            const [hexBytes] = await aptos.view({
                payload: {
                    function: `${aceContractAddr.toStringLong()}::dkg::get_session_bcs` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [sessionAddr.toStringLong()],
                },
            });
            const bytes = new Uint8Array(Buffer.from((hexBytes as string).replace(/^0x/, ''), 'hex'));
            return ace.dkg.Session.fromBytes(bytes).unwrapOrThrow('Failed to parse DKG session.');
        },
    });
}

export async function getNetworkState(aceContractAddr: AccountAddress): Promise<Result<ace.network.State>> {
    return Result.captureAsync({
        recordsExecutionTimeMs: false,
        task: async () => {
            const aptos = createAptos();
            const [hexBytes] = await aptos.view({
                payload: {
                    function: `${aceContractAddr.toStringLong()}::network::state_bcs` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [],
                },
            });
            const bytes = new Uint8Array(Buffer.from((hexBytes as string).replace(/^0x/, ''), 'hex'));
            return ace.network.State.fromBytes(bytes).unwrapOrThrow('Failed to parse network State.');
        },
    });
}

export async function getDKRSession(aceContractAddr: AccountAddress, sessionAddr: AccountAddress): Promise<Result<ace.dkr.Session>> {
    return Result.captureAsync({
        recordsExecutionTimeMs: false,
        task: async () => {
            const aptos = createAptos();
            const [hexBytes] = await aptos.view({
                payload: {
                    function: `${aceContractAddr.toStringLong()}::dkr::get_session_bcs` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [sessionAddr.toStringLong()],
                },
            });
            const bytes = new Uint8Array(Buffer.from((hexBytes as string).replace(/^0x/, ''), 'hex'));
            return ace.dkr.Session.fromBytes(bytes).unwrapOrThrow('Failed to parse DKR session.');
        },
    });
}