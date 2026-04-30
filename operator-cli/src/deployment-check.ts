// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { exec } from 'child_process';
import { promisify } from 'util';
import type { TrackedNode } from './config.js';

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
}

function parseNodeArgs(args: string[]): ParsedArgs {
    const p: ParsedArgs = {};
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
    return rows;
}

export function hasOutdated(rows: DiffRow[]): boolean {
    return rows.some(r => !r.match);
}
