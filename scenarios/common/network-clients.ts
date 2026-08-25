// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Account } from '@aptos-labs/ts-sdk';
import { execSync, spawn, type ChildProcess } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

import { NETWORK_NODE_BINARY, LOCALNET_URL, REPO_ROOT } from './config';
import { ed25519PrivateKeyHex } from './helpers';

const _nodeLogPaths: string[] = [];
process.on('exit', () => {
    if (_nodeLogPaths.length === 0) return;
    console.log('\nNode log files:');
    for (const p of _nodeLogPaths) console.log(`  ${p}`);
});

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

/**
 * Spawn the discovery server and wait until `/healthz` is green. Runs the SHIPPED bundle
 * (`discovery-server/dist/index.js`, built by the scenario's npm script), NOT the TS source — so
 * bundling/runtime bugs in the real artifact (e.g. an ESM "Dynamic require of http2" crash) fail
 * the scenario instead of only surfacing in production. Caller kills the returned process.
 */
export async function spawnDiscoveryServer(opts: {
    contractAddr: string;
    port: number;
    fullnode?: string;
}): Promise<ChildProcess> {
    const dist = path.join(REPO_ROOT, 'discovery-server', 'dist', 'index.js');
    if (!fs.existsSync(dist)) {
        throw new Error(
            `discovery-server bundle not found at ${dist} — ` +
            `run \`pnpm --filter @aptos-labs/ace-discovery-server build\` before this scenario.`,
        );
    }
    const logPath = path.join(os.tmpdir(), 'ace-discovery.log');
    const logFd = fs.openSync(logPath, 'w');
    _nodeLogPaths.push(logPath);
    console.log(`  $ node ${dist} (spawn discovery-server on :${opts.port})`);
    const child = spawn('node', [dist], {
        env: {
            ...process.env,
            ACE_DISCOVERY_FULLNODE: opts.fullnode ?? LOCALNET_URL,
            ACE_DISCOVERY_CONTRACT_ADDR: opts.contractAddr,
            ACE_DISCOVERY_PORT: String(opts.port),
        },
        stdio: ['ignore', logFd, logFd],
    });
    fs.closeSync(logFd);

    const base = `http://localhost:${opts.port}`;
    const deadline = Date.now() + 30_000;
    while (Date.now() < deadline) {
        if (child.exitCode !== null) {
            throw new Error(`discovery-server exited early (code ${child.exitCode}); see ${logPath}`);
        }
        try {
            const res = await fetch(`${base}/healthz`);
            if (res.ok) return child;
        } catch {
            // not listening yet
        }
        await new Promise((r) => setTimeout(r, 300));
    }
    child.kill('SIGKILL');
    throw new Error(`discovery-server did not become healthy on :${opts.port} within 30s; see ${logPath}`);
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
    /** Optional disaster-recovery reconstructor public key (hex of BCS `sig::PublicKey`).
     *  When set, the node is launched with `--reconstructor-pk`. */
    reconstructorPk?: string;
};

/**
 * Spawn a `network-node run` process for one committee member.
 *
 * The network-node binary watches the chain for DKG and DKR sessions it is
 * part of, then handles user decryption requests on `--port`.
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
    if (opts.reconstructorPk) {
        args.push('--reconstructor-pk', opts.reconstructorPk);
    }
    if (opts.port !== undefined) {
        args.push('--port', String(opts.port));
    }
    return spawnWithLog(NETWORK_NODE_BINARY, args, `ace-node-${accountAddr}`);
}

export type NetworkNodeSplitSpawnInput = NetworkNodeSpawnInput & {
    /** TCP port for the maintainer's `GET /secrets` endpoint. Required. */
    maintainerPort: number;
};

/**
 * Spawn a maintainer + handler pair for one committee member.
 *
 * The maintainer keeps the chain-touching responsibilities (URH share
 * reconstruction, `network::touch`, epoch-change-cur/nxt) and serves
 * `GET /secrets` on `--port=maintainerPort`. The handler owns the public
 * `--port` (= `opts.port`) and serves user decryption requests, pulling
 * secrets from the maintainer's `/secrets` endpoint with a 1-second
 * singleflight cache.
 *
 * No application-level auth on `/secrets`: maintainer + handler are assumed
 * to live in the same private network (Cloud Run `ingress=internal` + IAM
 * `run.invoker`, or a VPC-scoped service). On-chain registration is
 * unchanged — `account_addr` + PKE pubkey identify the worker; the endpoint
 * URL registered on-chain should point at the handler.
 */
export function spawnNetworkNodeSplit(opts: NetworkNodeSplitSpawnInput): {
    maintainer: ChildProcess;
    handler: ChildProcess;
} {
    const pkHex = ed25519PrivateKeyHex(opts.runAs);
    const rpc = opts.aceDeploymentApi ?? LOCALNET_URL;
    const accountAddr = opts.runAs.accountAddress.toStringLong();
    const pkeDkHex = opts.pkeDkHex.startsWith('0x') ? opts.pkeDkHex : `0x${opts.pkeDkHex}`;
    if (opts.port === undefined) {
        throw new Error('spawnNetworkNodeSplit: opts.port (handler port) is required');
    }

    const maintainer = spawnWithLog(
        NETWORK_NODE_BINARY,
        [
            'run',
            '--mode', 'maintainer',
            '--ace-deployment-api', rpc,
            '--ace-deployment-addr', opts.aceDeploymentAddr,
            '--account-addr', accountAddr,
            '--account-sk', `0x${pkHex}`,
            '--pke-dk', pkeDkHex,
            '--port', String(opts.maintainerPort),
        ],
        `ace-node-maintainer-${accountAddr}`,
    );

    const handler = spawnWithLog(
        NETWORK_NODE_BINARY,
        [
            'run',
            '--mode', 'handler',
            '--maintainer-url', `http://127.0.0.1:${opts.maintainerPort}/secrets`,
            '--pke-dk', pkeDkHex,
            // Handler serves reconstruction; give it the pk + ace addr + ACE
            // fullnode URL (to fetch chain id) for the domain check.
            ...(opts.reconstructorPk
                ? ['--reconstructor-pk', opts.reconstructorPk,
                   '--ace-deployment-addr', opts.aceDeploymentAddr,
                   '--ace-deployment-api', rpc]
                : []),
            '--port', String(opts.port),
        ],
        `ace-node-handler-${accountAddr}`,
    );

    return { maintainer, handler };
}

export type WorkerSpawnInput = Omit<NetworkNodeSpawnInput, 'port'> & {
    /** Position in the committee (0-based). Used to assign ports + pick mode. */
    index: number;
    /** Total number of workers being spawned in this committee. */
    total: number;
    /** Base port; handler/monolith uses `workerBasePort + index`. */
    workerBasePort: number;
    /** Offset for the maintainer's `/secrets` port in split mode (default 100). */
    maintainerPortOffset?: number;
};

/**
 * Spawn one committee member in either monolith or split mode, chosen by index:
 * the front `ceil(total/2)` indices run as split (maintainer + handler) and the
 * rest run as monoliths. Returns the list of processes spawned (length 1 for
 * monolith, 2 for split). Callers register
 * `http://localhost:${workerBasePort + index}` as the on-chain endpoint
 * regardless of mode.
 *
 * Exercising both modes in every end-to-end scenario keeps the split-mode
 * codepaths under continuous CI coverage.
 */
export function spawnNetworkNodeMaybeSplit(opts: WorkerSpawnInput): ChildProcess[] {
    const offset = opts.maintainerPortOffset ?? 100;
    const handlerPort = opts.workerBasePort + opts.index;
    const isSplit = opts.index < Math.ceil(opts.total / 2);
    if (isSplit) {
        const { maintainer, handler } = spawnNetworkNodeSplit({
            runAs: opts.runAs,
            pkeDkHex: opts.pkeDkHex,
            aceDeploymentAddr: opts.aceDeploymentAddr,
            aceDeploymentApi: opts.aceDeploymentApi,
            port: handlerPort,
            maintainerPort: opts.workerBasePort + offset + opts.index,
            reconstructorPk: opts.reconstructorPk,
        });
        return [maintainer, handler];
    }
    return [spawnNetworkNode({
        runAs: opts.runAs,
        pkeDkHex: opts.pkeDkHex,
        aceDeploymentAddr: opts.aceDeploymentAddr,
        aceDeploymentApi: opts.aceDeploymentApi,
        port: handlerPort,
        reconstructorPk: opts.reconstructorPk,
    })];
}

function spawnWithLog(bin: string, args: string[], label: string): ChildProcess {
    const logPath = path.join(os.tmpdir(), `${label}.log`);
    const logFd = fs.openSync(logPath, 'w');
    _nodeLogPaths.push(logPath);
    console.log(`  $ ${bin} ${args.join(' ')} (spawn)`);
    const child = spawn(bin, args, {
        env: { ...process.env, RUST_LOG: 'info' },
        stdio: ['ignore', logFd, logFd],
    });
    fs.closeSync(logFd);
    return child;
}
