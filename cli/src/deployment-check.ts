// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { exec } from 'child_process';
import { promisify } from 'util';
import type { ChainRpcOverrides, TrackedNode } from './config.js';
import { DEFAULT_CONTAINER_CONCURRENCY, DEFAULT_VPC_EGRESS, DEFAULT_VPC_NETWORK, DEFAULT_VPC_SUBNET, rpcUrlsNeedVpcEgress } from './onboarding.js';

const execAsync = promisify(exec);

export interface DiffRow {
    field: string;
    profile: string;
    running: string;
    secret: boolean;
    match: boolean;
}

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

function parseNodeArgs(args: string[]): ParsedArgs {
    const p: ParsedArgs = { chainRpc: {} };
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

export async function fetchDeployment(node: TrackedNode): Promise<ParsedArgs | Error | null> {
    try {
        if (node.platform === 'docker' && node.docker)
            return await fetchDockerDeployment(node.docker.containerName);
        if (node.platform === 'gcp' && node.gcp)
            return await fetchGcpDeployment(node.gcp.serviceName, node.gcp.project, node.gcp.region);
        if (node.platform === 'local')
            return null; // local processes aren't introspectable; skip diff
        return new Error('No deployment platform configured');
    } catch (e) {
        return e instanceof Error ? e : new Error(String(e));
    }
}

export function computeDiff(node: TrackedNode, running: ParsedArgs): DiffRow[] {
    const rows: DiffRow[] = [];
    const add = (field: string, profile: string | undefined, run: string | undefined, secret = false) => {
        const p = profile ?? '', r = run ?? '';
        rows.push({ field, profile: p, running: r, secret, match: p === r });
    };
    add('api', node.nodeRpcUrl ?? node.rpcUrl, running.api);
    add('addr',         node.aceAddr,       running.addr);
    if (node.rpcApiKey     || running.apikey)  add('apikey',    node.rpcApiKey,     running.apikey,    true);
    if (node.gasStationKey || running.gaskey)  add('gaskey',    node.gasStationKey, running.gaskey,    true);
    add('account-addr', node.accountAddr,   running.accountAddr);
    if (node.accountSk || running.accountSk)   add('account-sk', node.accountSk,   running.accountSk, true);
    if (node.pkeDk     || running.pkeDk)       add('pke-dk',    node.pkeDk,         running.pkeDk,     true);
    if (node.image     || running.image)       add('image',     node.image,         running.image);

    // Per-chain RPC overrides. Only emit a row when either side has a value, so
    // the common "neither override the binary default" case doesn't add noise.
    const profileRpc = node.chainRpc ?? {};
    for (const [flag, key] of Object.entries(CHAIN_RPC_FLAGS)) {
        const p = profileRpc[key];
        const r = running.chainRpc[key];
        if (p || r) add(flag, p, r, CHAIN_RPC_SECRET[key] ?? false);
    }

    // VPC egress (Cloud Run only). gcpDeployCmd auto-emits the standard config
    // when a chainRpc URL is private. Show rows only when the profile's
    // derivation OR the running service has any value, so unrelated docker/local
    // nodes don't get noisy.
    if (node.platform === 'gcp') {
        const expectedVpc = rpcUrlsNeedVpcEgress(node.chainRpc);
        const profileNetwork = expectedVpc ? DEFAULT_VPC_NETWORK : undefined;
        const profileSubnet  = expectedVpc ? DEFAULT_VPC_SUBNET  : undefined;
        const profileEgress  = expectedVpc ? DEFAULT_VPC_EGRESS  : undefined;
        // Cloud Run records `network` and `subnetwork` as resource paths
        // (`projects/<num>/regions/<r>/subnetworks/<name>`) — normalize to the trailing name for comparison.
        const lastPathPart = (v: string | undefined) => v?.replace(/^.*\//, '');
        const runningNetwork = lastPathPart(running.vpcNetwork);
        const runningSubnet  = lastPathPart(running.vpcSubnet);
        if (profileNetwork || runningNetwork) add('vpc-network', profileNetwork, runningNetwork);
        if (profileSubnet  || runningSubnet)  add('vpc-subnet',  profileSubnet,  runningSubnet);
        if (profileEgress  || running.vpcEgress) add('vpc-egress', profileEgress, running.vpcEgress);

        // Concurrency: gcpDeployCmd always emits --concurrency=DEFAULT_CONTAINER_CONCURRENCY;
        // surface drift if the running service has a different value (e.g., legacy 80 default).
        const runningCC = running.containerConcurrency;
        if (typeof runningCC === 'number' && runningCC !== DEFAULT_CONTAINER_CONCURRENCY) {
            add('concurrency', String(DEFAULT_CONTAINER_CONCURRENCY), String(runningCC));
        }
    }
    return rows;
}

export function hasOutdated(rows: DiffRow[]): boolean {
    return rows.some(r => !r.match);
}
