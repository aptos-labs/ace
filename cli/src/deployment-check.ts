// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { exec } from 'child_process';
import { promisify } from 'util';
import type { ChainRpcOverrides, TrackedNode } from './config.js';
import {
    DEFAULT_CONTAINER_CONCURRENCY,
    DEFAULT_VPC_EGRESS,
    DEFAULT_VPC_NETWORK,
    DEFAULT_VPC_SUBNET,
    GCP_CONFIG_ENV,
    GCP_SECRET_ENV,
    gcpConfigSecretId,
    gcpSecretId,
    rpcUrlsNeedVpcEgress,
} from './onboarding.js';

const execAsync = promisify(exec);

export interface DiffRow {
    field: string;
    profile: string;
    running: string;
    secret: boolean;
    match: boolean;
    /** For microservices: which Cloud Run service this row's "Running" was read from. Unset for monolith. */
    service?: 'maintainer' | 'handler';
}

/** Discriminated container for whatever shape of services this deployment has. */
export type FetchedDeployment =
    | { kind: 'mono'; args: ParsedArgs }
    | { kind: 'microservices'; maintainer: ParsedArgs; handler: ParsedArgs };

interface ParsedArgs {
    api?: string;
    addr?: string;
    apikey?: string;
    gaskey?: string;
    accountAddr?: string;
    accountSk?: string;
    pkeDk?: string;
    port?: string;
    image?: string;
    chainRpc: ChainRpcOverrides;
    // Cloud Run only. `vpcNetwork`/`vpcSubnet` come from the network-interfaces
    // annotation; `vpcEgress` from vpc-access-egress annotation. All undefined
    // for docker/local, and undefined on gcp when egress is the default (public-only).
    vpcNetwork?: string;
    vpcSubnet?: string;
    vpcEgress?: string;
    /** Cloud Run only. `spec.template.spec.containerConcurrency`. */
    containerConcurrency?: number;
    /** Cloud Run only. Env var name -> Secret Manager secret ref, e.g. `secret-name:latest`. */
    secretEnv: Record<string, string>;
}

// CLI flag → TrackedNode.chainRpc key. Matches `chainRpcArgs()` in onboarding.ts
// and the `--*-api/--*-apikey/--*-rpc` flag set declared in worker-components/network-node/src/main.rs.
const CHAIN_RPC_FLAGS: Record<string, keyof ChainRpcOverrides> = {
    'aptos-mainnet-api':       'aptosMainnetApi',
    'aptos-mainnet-apikey':    'aptosMainnetApikey',
    'aptos-testnet-api':       'aptosTestnetApi',
    'aptos-testnet-apikey':    'aptosTestnetApikey',
    'aptos-localnet-api':      'aptosLocalnetApi',
    'aptos-localnet-apikey':   'aptosLocalnetApikey',
    'solana-mainnet-beta-rpc': 'solanaMainnetBetaRpc',
    'solana-testnet-rpc':      'solanaTestnetRpc',
    'solana-devnet-rpc':       'solanaDevnetRpc',
};

const CHAIN_RPC_SECRET: Partial<Record<keyof ChainRpcOverrides, boolean>> = {
    aptosMainnetApikey:  true,
    aptosTestnetApikey:  true,
    aptosLocalnetApikey: true,
};

const CHAIN_RPC_SECRET_ENVS: Partial<Record<keyof ChainRpcOverrides, string>> = {
    aptosMainnetApikey:  GCP_SECRET_ENV.aptosMainnetApiKey,
    aptosTestnetApikey:  GCP_SECRET_ENV.aptosTestnetApiKey,
    aptosLocalnetApikey: GCP_SECRET_ENV.aptosLocalnetApiKey,
};

function parseNodeArgs(args: string[]): ParsedArgs {
    const p: ParsedArgs = { chainRpc: {}, secretEnv: {} };
    for (const arg of args) {
        const m = arg.match(/^--([^=]+)=([\s\S]*)$/);
        if (!m) continue;
        const [, k, v] = m;
        if      (k === 'ace-deployment-api')    p.api = v;
        else if (k === 'ace-deployment-addr')   p.addr = v;
        else if (k === 'ace-deployment-apikey') p.apikey = v;
        else if (k === 'ace-deployment-gaskey') p.gaskey = v;
        else if (k === 'account-addr')          p.accountAddr = v;
        else if (k === 'account-sk')            p.accountSk = v;
        else if (k === 'pke-dk')                p.pkeDk = v;
        else if (k === 'port')                  p.port = v;
        else if (k in CHAIN_RPC_FLAGS)          p.chainRpc[CHAIN_RPC_FLAGS[k]!] = v;
    }
    return p;
}

async function fetchDockerDeployment(containerName: string): Promise<ParsedArgs> {
    let argsOut: string, imgOut: string;
    try {
        ([{ stdout: argsOut }, { stdout: imgOut }] = await Promise.all([
            execAsync(`docker inspect ${containerName} --format '{{json .Args}}'`),
            execAsync(`docker inspect ${containerName} --format '{{.Config.Image}}'`),
        ]));
    } catch (e) {
        if (String(e).toLowerCase().includes('no such object')) {
            throw new Error(`Container "${containerName}" not running — start it with the docker command above`);
        }
        throw e;
    }
    const parsed = parseNodeArgs(JSON.parse(argsOut.trim()) as string[]);
    parsed.image = imgOut.trim().replace(/^docker\.io\//, '');
    return parsed;
}

async function fetchGcpDeployment(serviceName: string, project: string, region: string): Promise<ParsedArgs> {
    const { stdout } = await execAsync(
        `gcloud run services describe ${serviceName} --project ${project} --region ${region} --format=json`,
    );
    const svc = JSON.parse(stdout) as any;
    const container = svc?.spec?.template?.spec?.containers?.[0];
    if (!container) throw new Error('No container in service spec');
    const parsed = parseNodeArgs((container.args as string[]) ?? []);
    parsed.image = ((container.image as string) ?? '').replace(/^docker\.io\//, '');
    for (const env of (container.env ?? []) as any[]) {
        const name = env?.name;
        const secretKeyRef = env?.valueFrom?.secretKeyRef;
        if (typeof name === 'string' && typeof secretKeyRef?.name === 'string') {
            const key = typeof secretKeyRef.key === 'string' ? secretKeyRef.key : undefined;
            parsed.secretEnv[name] = key ? `${secretKeyRef.name}:${key}` : secretKeyRef.name;
        }
    }
    // VPC config: stored in template annotations on the running revision.
    // `network-interfaces` is a JSON array (Direct VPC egress); `vpc-access-connector`
    // is the legacy connector path. We only emit Direct VPC egress in gcpDeployCmd,
    // but we read both to surface drift in either direction.
    const ann = (svc?.spec?.template?.metadata?.annotations ?? {}) as Record<string, string>;
    const niRaw = ann['run.googleapis.com/network-interfaces'];
    if (niRaw) {
        try {
            const arr = JSON.parse(niRaw) as { network?: string; subnetwork?: string }[];
            if (arr.length > 0) {
                parsed.vpcNetwork = arr[0]!.network;
                parsed.vpcSubnet = arr[0]!.subnetwork;
            }
        } catch { /* malformed annotation — ignore */ }
    }
    parsed.vpcEgress = ann['run.googleapis.com/vpc-access-egress'];
    const cc = svc?.spec?.template?.spec?.containerConcurrency;
    if (typeof cc === 'number') parsed.containerConcurrency = cc;
    return parsed;
}

export async function fetchDeployment(node: TrackedNode): Promise<FetchedDeployment | Error | null> {
    try {
        if (node.platform === 'docker' && node.docker) {
            const args = await fetchDockerDeployment(node.docker.containerName);
            return { kind: 'mono', args };
        }
        if (node.platform === 'gcp' && node.gcp) {
            const { project, region, serviceName, maintainerServiceName, handlerServiceName } = node.gcp;
            if (serviceName) {
                const args = await fetchGcpDeployment(serviceName, project, region);
                return { kind: 'mono', args };
            }
            if (maintainerServiceName && handlerServiceName) {
                const [maintainer, handler] = await Promise.all([
                    fetchGcpDeployment(maintainerServiceName, project, region),
                    fetchGcpDeployment(handlerServiceName, project, region),
                ]);
                return { kind: 'microservices', maintainer, handler };
            }
            return new Error('No Cloud Run service name on this profile');
        }
        if (node.platform === 'local')
            return null; // local processes aren't introspectable; skip diff
        return new Error('No deployment platform configured');
    } catch (e) {
        return e instanceof Error ? e : new Error(String(e));
    }
}

type Adder = (field: string, profile: string | undefined, run: string | undefined, secret?: boolean) => void;

function makeAdder(rows: DiffRow[], service?: 'maintainer' | 'handler'): Adder {
    return (field, profile, run, secret = false) => {
        const p = profile ?? '', r = run ?? '';
        rows.push({ field, profile: p, running: r, secret, match: p === r, service });
    };
}

/** Per-chain-RPC override rows. Always read from `running` since only worker code (mono or handler) has them. */
function addChainRpcRows(
    add: Adder,
    profileRpc: ChainRpcOverrides,
    running: ParsedArgs,
    gcpSecretPrefix?: string,
): void {
    for (const [flag, key] of Object.entries(CHAIN_RPC_FLAGS)) {
        const p = profileRpc[key];
        const envName = CHAIN_RPC_SECRET_ENVS[key];
        if (envName && gcpSecretPrefix) {
            addGcpSecretRow(add, flag, gcpSecretPrefix, envName, p, running, running.chainRpc[key]);
            continue;
        }
        const r = running.chainRpc[key];
        if (p || r) add(flag, p, r, CHAIN_RPC_SECRET[key] ?? false);
    }
}

function secretRefName(ref?: string): string | undefined {
    return ref?.replace(/:.*$/, '');
}

function addGcpSecretRow(
    add: Adder,
    field: string,
    secretPrefix: string | undefined,
    envName: string,
    profileValue: string | undefined,
    running: ParsedArgs,
    runningArgValue?: string,
): void {
    const configActual = secretRefName(running.secretEnv[GCP_CONFIG_ENV]);
    if (configActual && profileValue) {
        const expected = secretPrefix ? gcpConfigSecretId(secretPrefix) : undefined;
        add(field, expected, configActual, true);
        return;
    }

    const legacyActual = secretRefName(running.secretEnv[envName]);
    if (legacyActual) {
        const expected = secretPrefix && profileValue ? gcpSecretId(secretPrefix, envName) : undefined;
        add(field, expected, legacyActual, true);
    } else if (profileValue || runningArgValue) {
        // Backward compatibility for Cloud Run services deployed before secrets
        // moved from --args into Secret Manager.
        add(field, profileValue, runningArgValue, true);
    }
}

function addSecretRow(
    add: Adder,
    field: string,
    profileValue: string | undefined,
    runningArgValue: string | undefined,
    running: ParsedArgs,
    gcpSecretPrefix: string | undefined,
    envName: string,
): void {
    if (gcpSecretPrefix) {
        addGcpSecretRow(add, field, gcpSecretPrefix, envName, profileValue, running, runningArgValue);
    } else if (profileValue || runningArgValue) {
        add(field, profileValue, runningArgValue, true);
    }
}

/** Compare a single Cloud Run service's VPC config against the expected config. */
function addVpcRows(
    add: Adder,
    running: ParsedArgs,
    expected: { network?: string; subnet?: string; egress?: string },
): void {
    // Cloud Run records `network` / `subnetwork` as resource paths; trim to the trailing name.
    const lastPathPart = (v: string | undefined) => v?.replace(/^.*\//, '');
    const runningNetwork = lastPathPart(running.vpcNetwork);
    const runningSubnet  = lastPathPart(running.vpcSubnet);
    if (expected.network || runningNetwork)   add('vpc-network', expected.network, runningNetwork);
    if (expected.subnet  || runningSubnet)    add('vpc-subnet',  expected.subnet,  runningSubnet);
    if (expected.egress  || running.vpcEgress) add('vpc-egress', expected.egress,  running.vpcEgress);
    const cc = running.containerConcurrency;
    if (typeof cc === 'number' && cc !== DEFAULT_CONTAINER_CONCURRENCY) {
        add('concurrency', String(DEFAULT_CONTAINER_CONCURRENCY), String(cc));
    }
}

function computeDiffMono(node: TrackedNode, running: ParsedArgs): DiffRow[] {
    const rows: DiffRow[] = [];
    const add = makeAdder(rows);
    const gcpSecretPrefix = node.platform === 'gcp' ? node.gcp?.serviceName : undefined;
    add('api',          node.nodeRpcUrl ?? node.rpcUrl, running.api);
    add('addr',         node.aceAddr,                   running.addr);
    addSecretRow(add, 'apikey', node.rpcApiKey, running.apikey, running, gcpSecretPrefix, GCP_SECRET_ENV.deploymentApiKey);
    addSecretRow(add, 'gaskey', node.gasStationKey, running.gaskey, running, gcpSecretPrefix, GCP_SECRET_ENV.deploymentGasKey);
    add('account-addr', node.accountAddr, running.accountAddr);
    addSecretRow(add, 'account-sk', node.accountSk, running.accountSk, running, gcpSecretPrefix, GCP_SECRET_ENV.accountSk);
    addSecretRow(add, 'pke-dk', node.pkeDk, running.pkeDk, running, gcpSecretPrefix, GCP_SECRET_ENV.pkeDk);
    if (node.image     || running.image)         add('image',     node.image,         running.image);

    addChainRpcRows(add, node.chainRpc ?? {}, running, gcpSecretPrefix);

    if (node.platform === 'gcp') {
        const expectedVpc = rpcUrlsNeedVpcEgress(node.chainRpc);
        addVpcRows(add, running, {
            network: expectedVpc ? DEFAULT_VPC_NETWORK : undefined,
            subnet:  expectedVpc ? DEFAULT_VPC_SUBNET  : undefined,
            egress:  expectedVpc ? DEFAULT_VPC_EGRESS  : undefined,
        });
    }
    return rows;
}

/**
 * Microservices diff: the worker config is split across two Cloud Run services.
 *   - Maintainer carries the chain/admin secrets (api/addr/apikey/gaskey/account-addr/account-sk).
 *   - Handler carries pke-dk + per-chain RPC overrides + the always-on `--maintainer-url`.
 *   - Both share the image and pke-dk; we diff both copies so drift on either side surfaces.
 *   - VPC: maintainer follows the same chainRpc rule as monolith; handler is hard-wired
 *     to network=default, subnet=default, egress=all-traffic (see gcpDeployCmdMicroservices).
 */
function computeDiffMicroservices(
    node: TrackedNode, maintainer: ParsedArgs, handler: ParsedArgs,
): DiffRow[] {
    const rows: DiffRow[] = [];
    const addM = makeAdder(rows, 'maintainer');
    const addH = makeAdder(rows, 'handler');
    const gcpSecretPrefix = node.platform === 'gcp' ? node.gcp?.maintainerServiceName : undefined;

    addM('api',  node.nodeRpcUrl ?? node.rpcUrl, maintainer.api);
    addM('addr', node.aceAddr,                   maintainer.addr);
    addSecretRow(addM, 'apikey', node.rpcApiKey, maintainer.apikey, maintainer, gcpSecretPrefix, GCP_SECRET_ENV.deploymentApiKey);
    addSecretRow(addM, 'gaskey', node.gasStationKey, maintainer.gaskey, maintainer, gcpSecretPrefix, GCP_SECRET_ENV.deploymentGasKey);
    addM('account-addr', node.accountAddr, maintainer.accountAddr);
    addSecretRow(addM, 'account-sk', node.accountSk, maintainer.accountSk, maintainer, gcpSecretPrefix, GCP_SECRET_ENV.accountSk);
    addSecretRow(addM, 'pke-dk', node.pkeDk, maintainer.pkeDk, maintainer, gcpSecretPrefix, GCP_SECRET_ENV.pkeDk);
    if (node.image     || maintainer.image)         addM('image',     node.image,         maintainer.image);

    addSecretRow(addH, 'pke-dk', node.pkeDk, handler.pkeDk, handler, gcpSecretPrefix, GCP_SECRET_ENV.pkeDk);
    if (node.image || handler.image)                addH('image',     node.image,         handler.image);
    addChainRpcRows(addH, node.chainRpc ?? {}, handler, gcpSecretPrefix);

    const expectedMaintVpc = rpcUrlsNeedVpcEgress(node.chainRpc);
    addVpcRows(addM, maintainer, {
        network: expectedMaintVpc ? DEFAULT_VPC_NETWORK : undefined,
        subnet:  expectedMaintVpc ? DEFAULT_VPC_SUBNET  : undefined,
        egress:  expectedMaintVpc ? DEFAULT_VPC_EGRESS  : undefined,
    });
    addVpcRows(addH, handler, {
        network: DEFAULT_VPC_NETWORK,
        subnet:  DEFAULT_VPC_SUBNET,
        egress:  'all-traffic',
    });
    return rows;
}

export function computeDiff(node: TrackedNode, fetched: FetchedDeployment): DiffRow[] {
    if (fetched.kind === 'mono') return computeDiffMono(node, fetched.args);
    return computeDiffMicroservices(node, fetched.maintainer, fetched.handler);
}

export function hasOutdated(rows: DiffRow[]): boolean {
    return rows.some(r => !r.match);
}
