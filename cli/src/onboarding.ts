// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { input } from '@inquirer/prompts';
import { execSync } from 'child_process';
import { writeFileSync, mkdirSync } from 'fs';
import { homedir } from 'os';
import * as path from 'path';
import { generateProfile } from './new-profile.js';
import { registerOnChain } from './register.js';
import { fetchTagsRaw } from './docker-hub.js';
import {
    loadConfig, makeNodeKey,
    type TrackedNode, type ChainRpcOverrides, type LocalConfig, type Mode,
} from './config.js';
import { resolveDeployment } from './resolve-profile.js';
import { logFilePath, spawnLocalNode } from './local-process.js';
import { buildFromEditor } from './editor.js';
import {
    pickScheme, modeOf, platformOf, generateTemplate, parseTemplate, defaultsFor,
    type Scheme, type TemplateInputs, type ParsedNodeForm,
} from './node-schemes.js';
import { gcloudReady, dockerReady, maybeAutoRun, runDeployScript, captureCloudRunUrl } from './auto-deploy.js';

const LOGROTATE_DIR   = path.join(homedir(), '.ace', 'logrotate');
const LOGROTATE_STATE = path.join(LOGROTATE_DIR, 'logrotate.state');

export function writeLogrotateConf(logFile: string, maxMb: number): string {
    mkdirSync(LOGROTATE_DIR, { recursive: true });
    const confFile = path.join(LOGROTATE_DIR, path.basename(logFile) + '.conf');
    const conf = [
        `${logFile} {`,
        `    size ${maxMb}M`,
        `    rotate 1`,
        `    copytruncate`,
        `    nocompress`,
        `    missingok`,
        `    notifempty`,
        `}`,
    ].join('\n') + '\n';
    writeFileSync(confFile, conf);
    return confFile;
}

export function runLogrotate(confFile: string): void {
    try {
        execSync(`logrotate --state ${LOGROTATE_STATE} ${confFile}`, { stdio: 'ignore' });
    } catch { /* rotation errors are non-fatal */ }
}

const CHAIN_DEFAULTS = {
    aptosMainnet:      'https://api.mainnet.aptoslabs.com/v1',
    aptosTestnet:      'https://api.testnet.aptoslabs.com/v1',
    aptosLocalnet:     'http://127.0.0.1:8080/v1',
    aptosShelbynet:    'https://api.shelbynet.shelby.xyz/v1',
    aptosShelbyPrivateBeta: '',
    solanaMainnetBeta: 'https://api.mainnet-beta.solana.com',
    solanaTestnet:     'https://api.testnet.solana.com',
    solanaDevnet:      'https://api.devnet.solana.com',
} as const;

const CHAIN_RPC_KEYS = [
    'aptosMainnetApi',
    'aptosMainnetApikey',
    'aptosTestnetApi',
    'aptosTestnetApikey',
    'aptosLocalnetApi',
    'aptosLocalnetApikey',
    'aptosShelbynetApi',
    'aptosShelbynetApikey',
    'aptosShelbyPrivateBetaApi',
    'aptosShelbyPrivateBetaApikey',
    'solanaMainnetBetaRpc',
    'solanaTestnetRpc',
    'solanaDevnetRpc',
] as const satisfies readonly (keyof ChainRpcOverrides)[];

export interface NodeNewOptions {
    nonInteractive?: boolean;
    yes?: boolean;
    json?: boolean;
    deployment?: string;
    deploymentBlob?: string;
    rpcUrl?: string;
    aceAddr?: string;
    rpcApiKey?: string;
    gasStationKey?: string;
    platform?: string;
    mode?: string;
    alias?: string;
    image?: string;
    project?: string;
    region?: string;
    serviceName?: string;
    maintainerServiceName?: string;
    handlerServiceName?: string;
    handlerMaxInstances?: string;
    endpoint?: string;
    chainRpcJson?: string;
}

export function isNonInteractiveNodeNew(opts: NodeNewOptions): boolean {
    return !!(
        opts.nonInteractive ||
        opts.deployment ||
        opts.deploymentBlob ||
        opts.rpcUrl ||
        opts.aceAddr ||
        opts.platform ||
        opts.mode ||
        opts.alias ||
        opts.image ||
        opts.project ||
        opts.region ||
        opts.serviceName ||
        opts.maintainerServiceName ||
        opts.handlerServiceName ||
        opts.handlerMaxInstances ||
        opts.endpoint ||
        opts.chainRpcJson
    );
}

function defaultGcpProject(): string | undefined {
    try {
        const out = execSync('gcloud config get-value project 2>/dev/null', { encoding: 'utf8' }).trim();
        return out || undefined;
    } catch {
        return undefined;
    }
}

export function dockerRpcUrl(rpcUrl: string): string {
    return rpcUrl.replace(/localhost/g, 'host.docker.internal')
                 .replace(/127\.0\.0\.1/g, 'host.docker.internal');
}

/**
 * Cloud Run defaults to public-internet egress only. If any chainRpc URL points
 * at a private IP (RFC1918) or a `*.internal` hostname, the Cloud Run service
 * needs Direct VPC egress configured to reach it. Detecting this lets us emit
 * the right --network/--subnet/--vpc-egress flags without making the operator
 * remember them.
 */
export function rpcUrlsNeedVpcEgress(chainRpc?: ChainRpcOverrides): boolean {
    if (!chainRpc) return false;
    const urls = [
        chainRpc.aptosMainnetApi, chainRpc.aptosTestnetApi, chainRpc.aptosLocalnetApi,
        chainRpc.aptosShelbynetApi, chainRpc.aptosShelbyPrivateBetaApi,
        chainRpc.solanaMainnetBetaRpc, chainRpc.solanaTestnetRpc, chainRpc.solanaDevnetRpc,
    ].filter((u): u is string => typeof u === 'string' && u.length > 0);
    return urls.some(isPrivateRpcUrl);
}

function isPrivateRpcUrl(url: string): boolean {
    let host: string;
    try { host = new URL(url).hostname; } catch { return false; }
    if (host.endsWith('.internal')) return true;
    // RFC1918: 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
    const m = /^(\d{1,3})\.(\d{1,3})\.\d{1,3}\.\d{1,3}$/.exec(host);
    if (!m) return false;
    const a = Number(m[1]), b = Number(m[2]);
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    return false;
}

/** Default VPC egress config used when private RPC URLs are detected. */
export const DEFAULT_VPC_NETWORK = 'default';
export const DEFAULT_VPC_SUBNET = 'default';
export const DEFAULT_VPC_EGRESS = 'private-ranges-only';

/**
 * Cloud Run's max concurrent in-flight requests per container. Cloud Run's
 * legacy default of 80 caps a single instance at modest throughput (e.g.,
 * 80 / 50 ms = 1600 QPS theoretical); 1000 is the documented max and gives
 * one well-resourced instance plenty of headroom. Operators can override at
 * deploy time by editing the printed gcloud command.
 */
export const DEFAULT_CONTAINER_CONCURRENCY = 1000;

export const GCP_SECRET_ENV = {
    accountSk:            'ACE_ACCOUNT_SK',
    pkeDk:                'ACE_PKE_DK',
    deploymentApiKey:     'ACE_DEPLOYMENT_APIKEY',
    deploymentGasKey:     'ACE_DEPLOYMENT_GASKEY',
    aptosMainnetApiKey:   'ACE_APTOS_MAINNET_APIKEY',
    aptosTestnetApiKey:   'ACE_APTOS_TESTNET_APIKEY',
    aptosLocalnetApiKey:  'ACE_APTOS_LOCALNET_APIKEY',
    aptosShelbynetApiKey: 'ACE_APTOS_SHELBYNET_APIKEY',
    aptosShelbyPrivateBetaApiKey: 'ACE_APTOS_SHELBY_PRIVATE_BETA_APIKEY',
} as const;

export const GCP_CONFIG_ENV = 'ACE_CONFIG_JSON';

export interface GcpDeployScript {
    /** Script printed to the terminal. It references secret env vars but never contains secret values. */
    display: string;
    /** Script passed to `bash -c` for auto-run. Same text as display; values arrive via `env`. */
    run: string;
    /** Secret values supplied to auto-run only. */
    env: Record<string, string>;
}

interface SecretBinding {
    envName: string;
    secretName: string;
    value: string;
}

function shellQuote(v: string): string {
    return `'${v.replace(/'/g, `'\\''`)}'`;
}

export function gcpConfigSecretId(prefix: string): string {
    return `${prefix}-config`;
}

export function gcpSecretId(prefix: string, envName: string): string {
    const suffix = envName
        .toLowerCase()
        .replace(/^ace_/, '')
        .replace(/_/g, '-');
    return `${prefix}-${suffix}`;
}

function runtimeConfigJson(
    node: { accountSk: string; pkeDk: string },
    rpcApiKey?: string,
    gasStationKey?: string,
    chainRpc?: ChainRpcOverrides,
): string {
    const cfg = {
        accountSk:            node.accountSk,
        pkeDk:                node.pkeDk,
        ...(rpcApiKey                  ? { deploymentApiKey:    rpcApiKey }                  : {}),
        ...(gasStationKey              ? { deploymentGasKey:    gasStationKey }              : {}),
        ...(chainRpc?.aptosMainnetApikey  ? { aptosMainnetApiKey:  chainRpc.aptosMainnetApikey }  : {}),
        ...(chainRpc?.aptosTestnetApikey  ? { aptosTestnetApiKey:  chainRpc.aptosTestnetApikey }  : {}),
        ...(chainRpc?.aptosLocalnetApikey ? { aptosLocalnetApiKey: chainRpc.aptosLocalnetApikey } : {}),
        ...(chainRpc?.aptosShelbynetApikey ? { aptosShelbynetApiKey: chainRpc.aptosShelbynetApikey } : {}),
        ...(chainRpc?.aptosShelbyPrivateBetaApikey ? { aptosShelbyPrivateBetaApiKey: chainRpc.aptosShelbyPrivateBetaApikey } : {}),
    };
    return JSON.stringify(cfg);
}

function configBinding(
    prefix: string,
    node: { accountSk: string; pkeDk: string },
    rpcApiKey?: string,
    gasStationKey?: string,
    chainRpc?: ChainRpcOverrides,
): SecretBinding {
    return {
        envName:    GCP_CONFIG_ENV,
        secretName: gcpConfigSecretId(prefix),
        value:      runtimeConfigJson(node, rpcApiKey, gasStationKey, chainRpc),
    };
}

function cloudRunSecretSetup(project: string, bindings: SecretBinding[]): string[] {
    if (bindings.length === 0) return [];
    return [
        `# Store runtime config in Secret Manager. Auto-run supplies this env var`,
        `# from the local ACE profile without printing its value. For manual runs,`,
        `# export ${GCP_CONFIG_ENV} first.`,
        `RUN_SA="$(gcloud projects describe ${shellQuote(project)} --format='value(projectNumber)')-compute@developer.gserviceaccount.com"`,
        `ensure_secret_version() {`,
        `  local secret_name="$1"`,
        `  local env_name="$2"`,
        `  if [ -z "\${!env_name:-}" ]; then`,
        `    echo "Missing $env_name; export it before running this script." >&2`,
        `    exit 1`,
        `  fi`,
        `  gcloud secrets describe "$secret_name" --project ${shellQuote(project)} >/dev/null 2>&1 || \\`,
        `    gcloud secrets create "$secret_name" --project ${shellQuote(project)} --replication-policy=automatic >/dev/null`,
        `  gcloud secrets add-iam-policy-binding "$secret_name" --project ${shellQuote(project)} \\`,
        `    --member "serviceAccount:$RUN_SA" --role roles/secretmanager.secretAccessor --quiet >/dev/null`,
        `  printf '%s' "\${!env_name}" | \\`,
        `    gcloud secrets versions add "$secret_name" --project ${shellQuote(project)} --data-file=- >/dev/null`,
        `}`,
        ...bindings.map(b => `ensure_secret_version ${shellQuote(b.secretName)} ${shellQuote(b.envName)}`),
        ``,
    ];
}

function cloudRunSecretFlags(bindings: SecretBinding[]): string[] {
    if (bindings.length === 0) return [];
    return [
        `  --service-account=\${RUN_SA}`,
        `  --set-secrets=${bindings.map(b => `${b.envName}=${b.secretName}:latest`).join(',')}`,
    ];
}

function secretEnv(bindings: SecretBinding[]): Record<string, string> {
    return Object.fromEntries(bindings.map(b => [b.envName, b.value]));
}

export function gcpDeployCmd(
    serviceName: string, image: string, project: string, region: string,
    node: { accountAddr: string; accountSk: string; pkeDk: string },
    rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string,
    chainRpc?: ChainRpcOverrides,
): GcpDeployScript {
    const secretBindings = [configBinding(serviceName, node, rpcApiKey, gasStationKey, chainRpc)];
    const args = nodeRunArgs(node, rpcUrl, aceAddr, undefined, undefined, chainRpc, { includeSecrets: false });
    const vpcLines = rpcUrlsNeedVpcEgress(chainRpc) ? [
        `  --network=${DEFAULT_VPC_NETWORK}`,
        `  --subnet=${DEFAULT_VPC_SUBNET}`,
        `  --vpc-egress=${DEFAULT_VPC_EGRESS}`,
    ] : [];
    const deploy = [
        `gcloud run deploy ${serviceName}`,
        `  --image docker.io/${image}`,
        `  --project ${project}`,
        `  --region ${region}`,
        `  --allow-unauthenticated`,
        `  --min-instances 1`,
        `  --no-cpu-throttling`,
        `  --concurrency=${DEFAULT_CONTAINER_CONCURRENCY}`,
        ...cloudRunSecretFlags(secretBindings),
        ...vpcLines,
        `  --args "${args.join(',')}"`,
    ].join(' \\\n');
    const script = [
        `set -e`,
        ``,
        ...cloudRunSecretSetup(project, secretBindings),
        deploy,
    ].join('\n');
    return { display: script, run: script, env: secretEnv(secretBindings) };
}

/**
 * Emit the microservices-mode deploy script.
 *
 * The script is **ordered**: the Handler's `--maintainer-url` flag needs the
 * Maintainer's auto-assigned Cloud Run URL, which is NOT derivable from
 * `<service>-<project_number>` ahead of time (Cloud Run mixes that with a
 * legacy `<service>-<hash>-<region>.a.run.app` form for some services /
 * projects). Capturing it post-deploy via `gcloud run services describe`
 * is the only correct path. The emitted shell script does that with a
 * `MAINT_URL=$(gcloud …)` substitution, then deploys the Handler.
 *
 * Auth model: the Maintainer is reachable only via VPC (`--ingress=internal`),
 * but invocation itself is unauthenticated. The Handler is given Direct VPC
 * egress so its outbound to the Maintainer's `*.run.app` URL is recognized as
 * same-project internal and passes the ingress filter. No OIDC tokens are
 * needed — the worker code does plain HTTP GETs.
 *
 * Step order:
 *   1. Deploy the Maintainer (internal-only, min=max=1, no auth required).
 *   2. Capture the Maintainer URL.
 *   3. Deploy the Handler with VPC egress + `--maintainer-url=$MAINT_URL/secrets`.
 */
export function gcpDeployCmdMicroservices(
    cfg: {
        project: string;
        region: string;
        maintainerServiceName: string;
        handlerServiceName: string;
        handlerMaxInstances: number;
    },
    image: string,
    node: { accountAddr: string; accountSk: string; pkeDk: string },
    rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string,
    chainRpc?: ChainRpcOverrides,
): GcpDeployScript {
    // Maintainer's VPC needs follow the chain-RPC rule (it only talks to the
    // chain). Handler ALWAYS needs VPC egress so it can reach the Maintainer's
    // internal-only *.run.app URL.
    const maintainerVpcLines = rpcUrlsNeedVpcEgress(chainRpc) ? [
        `  --network=${DEFAULT_VPC_NETWORK}`,
        `  --subnet=${DEFAULT_VPC_SUBNET}`,
        `  --vpc-egress=${DEFAULT_VPC_EGRESS}`,
    ] : [];
    const handlerVpcLines = [
        `  --network=${DEFAULT_VPC_NETWORK}`,
        `  --subnet=${DEFAULT_VPC_SUBNET}`,
        `  --vpc-egress=all-traffic`,
    ];

    const configSecret = configBinding(
        cfg.maintainerServiceName,
        node,
        rpcApiKey,
        gasStationKey,
        chainRpc,
    );
    const secretBindings = [configSecret];

    const maintainerArgs = [
        'run',
        '--mode=maintainer',
        `--ace-deployment-api=${rpcUrl}`,
        `--ace-deployment-addr=${aceAddr}`,
        `--account-addr=${node.accountAddr}`,
        `--port=8080`,
    ];
    // Handler args use a shell variable for --maintainer-url; the deploy line
    // below interpolates $MAINT_URL after capture.
    const handlerArgsBeforeUrl = ['run', '--mode=handler'];
    const handlerArgsAfterUrl = [
        `--port=8080`,
        ...chainRpcArgs(chainRpc, { includeSecrets: false }),
    ];

    const maintainerDeploy = [
        `gcloud run deploy ${cfg.maintainerServiceName}`,
        `  --image docker.io/${image}`,
        `  --project ${cfg.project}`,
        `  --region ${cfg.region}`,
        `  --ingress=internal`,
        `  --allow-unauthenticated`,
        `  --min-instances 1`,
        `  --max-instances 1`,
        `  --no-cpu-throttling`,
        `  --concurrency=${DEFAULT_CONTAINER_CONCURRENCY}`,
        ...cloudRunSecretFlags(secretBindings),
        ...maintainerVpcLines,
        `  --args "${maintainerArgs.join(',')}"`,
    ].join(' \\\n');

    const handlerDeploy = [
        `gcloud run deploy ${cfg.handlerServiceName}`,
        `  --image docker.io/${image}`,
        `  --project ${cfg.project}`,
        `  --region ${cfg.region}`,
        `  --allow-unauthenticated`,
        `  --min-instances 1`,
        `  --max-instances ${cfg.handlerMaxInstances}`,
        `  --no-cpu-throttling`,
        `  --concurrency=${DEFAULT_CONTAINER_CONCURRENCY}`,
        ...cloudRunSecretFlags(secretBindings),
        ...handlerVpcLines,
        `  --args "${handlerArgsBeforeUrl.join(',')},--maintainer-url=\${MAINT_URL}/secrets,${handlerArgsAfterUrl.join(',')}"`,
    ].join(' \\\n');

    const script = [
        `set -e`,
        ``,
        ...cloudRunSecretSetup(cfg.project, secretBindings),
        `# 1. Deploy the Maintainer (internal-only, pinned at min=max=1).`,
        `#    Reachable only via VPC; unauthenticated within the VPC.`,
        maintainerDeploy,
        ``,
        `# 2. Capture the Maintainer's auto-assigned URL (Cloud Run picks the format,`,
        `#    we can't derive it ahead of time).`,
        `MAINT_URL=$(gcloud run services describe ${cfg.maintainerServiceName} \\`,
        `  --project=${cfg.project} --region=${cfg.region} --format='value(status.url)')`,
        `echo "Maintainer URL: $MAINT_URL"`,
        ``,
        `# 3. Deploy the Handler (public, scales 1..${cfg.handlerMaxInstances}).`,
        `#    Direct VPC egress (all-traffic) is required so the Handler's outbound`,
        `#    to the Maintainer is recognized as same-project internal traffic.`,
        handlerDeploy,
    ].join('\n');
    return { display: script, run: script, env: secretEnv(secretBindings) };
}

export function dockerRunCmd(
    containerName: string, image: string, port: string,
    node: { accountAddr: string; accountSk: string; pkeDk: string },
    rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string,
    chainRpc?: ChainRpcOverrides,
): string {
    return [
        `docker run -d --platform linux/amd64 --restart unless-stopped`,
        `  --name ${containerName}`,
        `  -p ${port}:${port}`,
        `  ${image}`,
        `  run`,
        `  --ace-deployment-api=${rpcUrl}`,
        `  --ace-deployment-addr=${aceAddr}`,
        ...(rpcApiKey     ? [`  --ace-deployment-apikey=${rpcApiKey}`]     : []),
        ...(gasStationKey ? [`  --ace-deployment-gaskey=${gasStationKey}`] : []),
        `  --account-addr=${node.accountAddr}`,
        `  --account-sk=${node.accountSk}`,
        `  --pke-dk=${node.pkeDk}`,
        `  --port=${port}`,
        ...chainRpcArgs(chainRpc),
    ].join(' \\\n');
}

export function localBuildCmd(repoPath: string): string {
    return `cargo build --release -p network-node --manifest-path ${repoPath}/Cargo.toml`;
}

export function localRunCmd(
    repoPath: string, port: string,
    node: { accountAddr: string; accountSk: string; pkeDk: string },
    rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string,
    chainRpc?: ChainRpcOverrides,
): string {
    return [
        `${repoPath}/target/release/network-node run`,
        `  --ace-deployment-api=${rpcUrl}`,
        `  --ace-deployment-addr=${aceAddr}`,
        ...(rpcApiKey     ? [`  --ace-deployment-apikey=${rpcApiKey}`]     : []),
        ...(gasStationKey ? [`  --ace-deployment-gaskey=${gasStationKey}`] : []),
        `  --account-addr=${node.accountAddr}`,
        `  --account-sk=${node.accountSk}`,
        `  --pke-dk=${node.pkeDk}`,
        `  --port=${port}`,
        ...chainRpcArgs(chainRpc).map(a => `  ${a}`),
    ].join(' \\\n');
}

export function localRunArgs(
    port: string,
    node: { accountAddr: string; accountSk: string; pkeDk: string },
    rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string,
    chainRpc?: ChainRpcOverrides,
): string[] {
    return [
        'run',
        `--ace-deployment-api=${rpcUrl}`,
        `--ace-deployment-addr=${aceAddr}`,
        ...(rpcApiKey     ? [`--ace-deployment-apikey=${rpcApiKey}`]     : []),
        ...(gasStationKey ? [`--ace-deployment-gaskey=${gasStationKey}`] : []),
        `--account-addr=${node.accountAddr}`,
        `--account-sk=${node.accountSk}`,
        `--pke-dk=${node.pkeDk}`,
        `--port=${port}`,
        ...chainRpcArgs(chainRpc),
    ];
}

function defaultRepoPath(): string | undefined {
    try {
        const out = execSync('git rev-parse --show-toplevel 2>/dev/null', { encoding: 'utf8' }).trim();
        if (out && out.includes('ace')) return out;
    } catch { /* ignore */ }
    return undefined;
}

function nodeRunArgs(
    node: { accountAddr: string; accountSk: string; pkeDk: string },
    rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string,
    chainRpc?: ChainRpcOverrides,
    opts: { includeSecrets?: boolean } = {},
): string[] {
    const includeSecrets = opts.includeSecrets ?? true;
    return [
        'run',
        `--ace-deployment-api=${rpcUrl}`,
        `--ace-deployment-addr=${aceAddr}`,
        ...(includeSecrets && rpcApiKey     ? [`--ace-deployment-apikey=${rpcApiKey}`]     : []),
        ...(includeSecrets && gasStationKey ? [`--ace-deployment-gaskey=${gasStationKey}`] : []),
        `--account-addr=${node.accountAddr}`,
        ...(includeSecrets ? [`--account-sk=${node.accountSk}`, `--pke-dk=${node.pkeDk}`] : []),
        '--port=8080',
        ...chainRpcArgs(chainRpc, { includeSecrets }),
    ];
}

function chainRpcArgs(r?: ChainRpcOverrides, opts: { includeSecrets?: boolean } = {}): string[] {
    if (!r) return [];
    const includeSecrets = opts.includeSecrets ?? true;
    const f = (flag: string, val?: string) => val ? [`${flag}${val}`] : [];
    return [
        ...f('--aptos-mainnet-api=',       r.aptosMainnetApi),
        ...(includeSecrets ? f('--aptos-mainnet-apikey=',    r.aptosMainnetApikey) : []),
        ...f('--aptos-testnet-api=',       r.aptosTestnetApi),
        ...(includeSecrets ? f('--aptos-testnet-apikey=',    r.aptosTestnetApikey) : []),
        ...f('--aptos-localnet-api=',      r.aptosLocalnetApi),
        ...(includeSecrets ? f('--aptos-localnet-apikey=',   r.aptosLocalnetApikey) : []),
        ...f('--aptos-shelbynet-api=',     r.aptosShelbynetApi),
        ...(includeSecrets ? f('--aptos-shelbynet-apikey=',  r.aptosShelbynetApikey) : []),
        ...f('--aptos-shelby-private-beta-api=',    r.aptosShelbyPrivateBetaApi),
        ...(includeSecrets ? f('--aptos-shelby-private-beta-apikey=', r.aptosShelbyPrivateBetaApikey) : []),
        ...f('--solana-mainnet-beta-rpc=', r.solanaMainnetBetaRpc),
        ...f('--solana-testnet-rpc=',      r.solanaTestnetRpc),
        ...f('--solana-devnet-rpc=',       r.solanaDevnetRpc),
    ];
}

export async function promptChainRpcOverrides(
    current?: ChainRpcOverrides,
    transformDefault: (url: string) => string = u => u,
): Promise<ChainRpcOverrides> {
    console.log('\nPer-chain RPC endpoints  (Enter to use default)\n');

    const askUrl = async (msg: string, pubDefault: string, cur?: string): Promise<string | undefined> => {
        const effectiveDefault = cur ?? transformDefault(pubDefault);
        const val = (await input({ message: msg, default: effectiveDefault })).trim();
        return val === pubDefault ? undefined : val || undefined;
    };

    const askKey = async (msg: string, cur?: string): Promise<string | undefined> => {
        const hint = cur ? ' (Enter to keep, "none" to clear)' : ' (Enter to skip)';
        const val = (await input({ message: msg + hint, default: '' })).trim();
        if (val === 'none') return undefined;
        return val || cur;
    };

    const r: ChainRpcOverrides = {
        aptosMainnetApi:      await askUrl('Aptos mainnet API URL',        CHAIN_DEFAULTS.aptosMainnet,      current?.aptosMainnetApi),
        aptosMainnetApikey:   await askKey('Aptos mainnet API key',        current?.aptosMainnetApikey),
        aptosTestnetApi:      await askUrl('Aptos testnet API URL',        CHAIN_DEFAULTS.aptosTestnet,      current?.aptosTestnetApi),
        aptosTestnetApikey:   await askKey('Aptos testnet API key',        current?.aptosTestnetApikey),
        aptosLocalnetApi:     await askUrl('Aptos localnet API URL',       CHAIN_DEFAULTS.aptosLocalnet,     current?.aptosLocalnetApi),
        aptosLocalnetApikey:  await askKey('Aptos localnet API key',       current?.aptosLocalnetApikey),
        aptosShelbynetApi:    await askUrl('Aptos shelbynet API URL',      CHAIN_DEFAULTS.aptosShelbynet,    current?.aptosShelbynetApi),
        aptosShelbynetApikey: await askKey('Aptos shelbynet API key',      current?.aptosShelbynetApikey),
        aptosShelbyPrivateBetaApi:    await askUrl('Aptos shelby-private-beta API URL', CHAIN_DEFAULTS.aptosShelbyPrivateBeta, current?.aptosShelbyPrivateBetaApi),
        aptosShelbyPrivateBetaApikey: await askKey('Aptos shelby-private-beta API key', current?.aptosShelbyPrivateBetaApikey),
        solanaMainnetBetaRpc: await askUrl('Solana mainnet-beta RPC URL',  CHAIN_DEFAULTS.solanaMainnetBeta, current?.solanaMainnetBetaRpc),
        solanaTestnetRpc:     await askUrl('Solana testnet RPC URL',       CHAIN_DEFAULTS.solanaTestnet,     current?.solanaTestnetRpc),
        solanaDevnetRpc:      await askUrl('Solana devnet RPC URL',        CHAIN_DEFAULTS.solanaDevnet,      current?.solanaDevnetRpc),
    };

    console.log();
    return Object.fromEntries(Object.entries(r).filter(([, v]) => v !== undefined)) as ChainRpcOverrides;
}

interface NetworkDetails {
    rpcUrl:     string;
    aceAddr:    string;
    rpcApiKey?: string;
    gasStationKey?: string;
}

function nonEmpty(v: string | undefined): string | undefined {
    const s = v?.trim();
    return s ? s : undefined;
}

function parseDeploymentBlob(raw: string): NetworkDetails {
    let parsed: Record<string, unknown>;
    try {
        parsed = JSON.parse(raw) as Record<string, unknown>;
    } catch (e) {
        throw new Error(`--deployment-blob is not valid JSON: ${(e as Error).message}`);
    }
    if (typeof parsed.rpcUrl !== 'string' || typeof parsed.aceAddr !== 'string') {
        throw new Error('--deployment-blob must include string fields "rpcUrl" and "aceAddr".');
    }
    return {
        rpcUrl:        parsed.rpcUrl,
        aceAddr:       parsed.aceAddr,
        rpcApiKey:     typeof parsed.rpcApiKey === 'string' ? parsed.rpcApiKey : undefined,
        gasStationKey: typeof parsed.gasStationKey === 'string' ? parsed.gasStationKey : undefined,
    };
}

function networkDetailsFromOptions(opts: NodeNewOptions): NetworkDetails {
    let base: Partial<NetworkDetails> = {};
    if (opts.deploymentBlob) {
        base = parseDeploymentBlob(opts.deploymentBlob);
    } else if (opts.deployment || (!opts.rpcUrl || !opts.aceAddr)) {
        const { deployment } = resolveDeployment(opts.deployment);
        base = {
            rpcUrl:        deployment.rpcUrl,
            aceAddr:       deployment.aceAddr,
            rpcApiKey:     deployment.sharedNodeApiKey,
            gasStationKey: deployment.gasStationApiKey,
        };
    }

    const rpcUrl = nonEmpty(opts.rpcUrl) ?? base.rpcUrl;
    const aceAddr = nonEmpty(opts.aceAddr) ?? base.aceAddr;
    if (!rpcUrl) throw new Error('Missing deployment RPC URL. Pass --deployment, --deployment-blob, or --rpc-url.');
    if (!aceAddr) throw new Error('Missing ACE contract address. Pass --deployment, --deployment-blob, or --ace-addr.');
    return {
        rpcUrl,
        aceAddr,
        rpcApiKey:     nonEmpty(opts.rpcApiKey) ?? base.rpcApiKey,
        gasStationKey: nonEmpty(opts.gasStationKey) ?? base.gasStationKey,
    };
}

function parseChainRpcJson(raw: string | undefined): ChainRpcOverrides | undefined {
    if (!raw) return undefined;
    let parsed: unknown;
    try {
        parsed = JSON.parse(raw);
    } catch (e) {
        throw new Error(`--chain-rpc-json is not valid JSON: ${(e as Error).message}`);
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
        throw new Error('--chain-rpc-json must be a JSON object.');
    }
    const out: ChainRpcOverrides = {};
    const doc = parsed as Record<string, unknown>;
    for (const [k, v] of Object.entries(doc)) {
        if (!CHAIN_RPC_KEYS.includes(k as keyof ChainRpcOverrides)) {
            throw new Error(`Unknown --chain-rpc-json key "${k}". Allowed: ${CHAIN_RPC_KEYS.join(', ')}.`);
        }
        if (typeof v !== 'string') {
            throw new Error(`--chain-rpc-json key "${k}" must be a string.`);
        }
        if (v) (out as Record<string, string>)[k] = v;
    }
    return Object.keys(out).length > 0 ? out : undefined;
}

function parsePositiveInt(v: string | undefined, label: string, fallback: number): number {
    if (v === undefined || v === '') return fallback;
    const n = Number(v);
    if (!Number.isInteger(n) || n <= 0) {
        throw new Error(`${label} must be a positive integer.`);
    }
    return n;
}

function requireParsedString(v: string | undefined, label: string): string {
    if (!v) throw new Error(`Missing ${label}.`);
    return v;
}

function schemeFromOptions(opts: NodeNewOptions, isLocalnet: boolean): Scheme {
    if (opts.mode === 'metadata-management-only') {
        return 'metadata-management-only';
    }

    const platform = opts.platform ?? 'gcp';
    if (platform !== 'gcp') {
        throw new Error('Non-interactive node new currently supports only --platform gcp or --mode metadata-management-only.');
    }
    if (isLocalnet) {
        throw new Error('GCP Cloud Run is unavailable for localnet deployments.');
    }
    const mode = opts.mode ?? 'microservices';
    if (mode === 'microservices') return 'gcp-cloudrun-microservices';
    if (mode === 'monolith') return 'gcp-cloudrun-monolith';
    throw new Error('--mode must be "microservices", "monolith", or "metadata-management-only".');
}

function parsedFormFromOptions(
    opts: NodeNewOptions,
    scheme: Scheme,
    defaults: ReturnType<typeof defaultsFor>,
    net: NetworkDetails,
): ParsedNodeForm {
    const metadataCommon = {
        alias:         nonEmpty(opts.alias),
        rpcApiKey:     nonEmpty(opts.rpcApiKey) ?? net.rpcApiKey,
        gasStationKey: nonEmpty(opts.gasStationKey) ?? net.gasStationKey,
        chainRpc:      parseChainRpcJson(opts.chainRpcJson),
    };
    if (scheme === 'metadata-management-only') {
        return { ...metadataCommon, endpoint: nonEmpty(opts.endpoint) };
    }

    const common = {
        ...metadataCommon,
        image: nonEmpty(opts.image) ?? defaults.image,
    };
    if (scheme === 'gcp-cloudrun-monolith') {
        return {
            ...common,
            project:     nonEmpty(opts.project) ?? defaults.project,
            region:      nonEmpty(opts.region) ?? defaults.region,
            serviceName: nonEmpty(opts.serviceName) ?? defaults.serviceName,
        };
    }
    return {
        ...common,
        project:                nonEmpty(opts.project) ?? defaults.project,
        region:                 nonEmpty(opts.region) ?? defaults.region,
        maintainerServiceName:  nonEmpty(opts.maintainerServiceName) ?? defaults.maintainerServiceName,
        handlerServiceName:     nonEmpty(opts.handlerServiceName) ?? defaults.handlerServiceName,
        handlerMaxInstances:    parsePositiveInt(
            opts.handlerMaxInstances,
            '--handler-max-instances',
            defaults.handlerMaxInstances ?? 10,
        ),
    };
}

async function probeEndpoint(url: string): Promise<boolean> {
    try {
        await fetch(url, { method: 'GET', signal: AbortSignal.timeout(3000) });
        return true;
    } catch {
        return false;
    }
}


async function promptEndpoint(message: string, defaultValue?: string): Promise<string> {
    let last = defaultValue;
    while (true) {
        const url = (await input({ message, default: last })).trim();
        if (!url) continue;
        last = url;

        process.stdout.write('  Checking node reachability...');
        if (await probeEndpoint(url)) {
            process.stdout.write(' ✓\n\n');
            return url;
        }
        process.stdout.write(' ✗  (not reachable)\n\n');
    }
}

async function endpointFromOptions(
    opts: NodeNewOptions,
    label: string,
    capturedEndpoint?: string,
): Promise<string> {
    const endpoint = nonEmpty(opts.endpoint) ?? capturedEndpoint;
    if (!endpoint) {
        throw new Error(`Could not determine ${label} endpoint. Pass --endpoint or run with --yes so the CLI can deploy and discover it.`);
    }
    process.stderr.write(`  Checking ${label} endpoint reachability...`);
    if (await probeEndpoint(endpoint)) {
        process.stderr.write(' ✓\n');
        return endpoint;
    }
    process.stderr.write(' ✗\n');
    throw new Error(`${label} endpoint is not reachable: ${endpoint}`);
}

function endpointValueFromOptions(
    opts: NodeNewOptions,
    label: string,
    capturedEndpoint?: string,
): string {
    const endpoint = nonEmpty(opts.endpoint) ?? capturedEndpoint;
    if (!endpoint) {
        throw new Error(`Missing ${label} endpoint. Pass --endpoint.`);
    }
    return endpoint;
}

async function promptEndpointValue(message: string, defaultValue?: string): Promise<string> {
    let last = defaultValue;
    while (true) {
        const url = (await input({ message, default: last })).trim();
        if (!url) continue;
        return url;
    }
}

/** Best-effort lookup of the latest aptoslabs/ace-node tag from Docker Hub. */
async function latestImageTag(): Promise<string> {
    try {
        const tags = await fetchTagsRaw(1);
        if (tags.length > 0) return `aptoslabs/ace-node:${tags[0]!.name}`;
    } catch { /* fall through */ }
    return 'aptoslabs/ace-node:latest';
}

function suggestPort(existing: Record<string, TrackedNode>): string {
    const used = new Set<string>();
    for (const n of Object.values(existing)) {
        if (n.docker?.port) used.add(n.docker.port);
        if (n.local?.port)  used.add(n.local.port);
    }
    let p = 19000;
    while (used.has(String(p))) p++;
    return String(p);
}

/** Full guided wizard for adding a new node you control. */
export async function runOnboarding(options: NodeNewOptions = {}): Promise<{ nodeKey: string; node: TrackedNode }> {
    const existingConfig = loadConfig();
    const nonInteractive = isNonInteractiveNodeNew(options);
    console.log('\n  ACE Node Setup\n');

    console.log('Generating node keys...\n');
    const profile = await generateProfile();
    console.log(`  Account address : ${profile.accountAddr}`);
    console.log(`  PKE enc key     : ${profile.pkeEk}\n`);

    const net: NetworkDetails = nonInteractive
        ? networkDetailsFromOptions(options)
        : await promptNetworkDetails();

    const isLocalnet = /localhost|127\.0\.0\.1/.test(net.rpcUrl);
    const scheme = nonInteractive
        ? schemeFromOptions(options, isLocalnet)
        : await pickScheme({ isLocalnet });
    if (!scheme) {
        throw new Error('Cancelled (no scheme picked).');
    }
    const mode: Mode = modeOf(scheme);
    const platform = platformOf(scheme);

    const fallbackImage = scheme === 'metadata-management-only'
        ? ''
        : options.image ?? await latestImageTag();

    const t: TemplateInputs = {
        identity: { accountAddr: profile.accountAddr, pkeEk: profile.pkeEk! },
        blob: {
            rpcUrl:        net.rpcUrl,
            aceAddr:       net.aceAddr,
            rpcApiKey:     net.rpcApiKey,
            gasStationKey: net.gasStationKey,
            nodeRpcUrl:    platform === 'docker' ? dockerRpcUrl(net.rpcUrl) : undefined,
        },
        defaults: defaultsFor(scheme, net, profile, fallbackImage, {
            defaultGcpProject: defaultGcpProject(),
            defaultRepoPath:   defaultRepoPath(),
            defaultPort:       suggestPort(existingConfig.nodes),
        }),
    };

    const parsed = nonInteractive
        ? parsedFormFromOptions(options, scheme, t.defaults, net)
        : await buildFromEditor(
            generateTemplate(scheme, t),
            c => parseTemplate(scheme, c),
            { fileTag: 'node-new', acceptUnmodified: true },
        );
    if (!parsed) {
        throw new Error('Cancelled (no changes saved).');
    }

    // Effective values used for deploy emission / spawn.
    const image          = parsed.image;
    const rpcApiKey      = parsed.rpcApiKey ?? net.rpcApiKey;
    const gasStationKey  = parsed.gasStationKey ?? net.gasStationKey;
    const chainRpc       = parsed.chainRpc ?? {};
    const nodeRpcUrl     = t.blob.nodeRpcUrl;
    const deployRunOpts  = { stdout: options.json ? 'stderr' : 'inherit' } as const;
    const network        = detectAptosNetwork(net.rpcUrl);

    if (nonInteractive && !gasStationKey && (network === 'testnet' || network === 'mainnet' || network === 'shelbynet' || network === 'shelby-private-beta')) {
        throw new Error(
            'Non-interactive node new requires a gas station key for testnet/mainnet/shelbynet/shelby-private-beta because it generates a fresh account. ' +
            'Pass --gas-station-key or use a deployment profile with gasStationApiKey.',
        );
    }

    let endpoint:  string;
    let gcpCfg:    TrackedNode['gcp'];
    let dockerCfg: TrackedNode['docker'];
    let localCfg:  LocalConfig | undefined;

    if (scheme === 'metadata-management-only') {
        console.log('\nMetadata-management-only profile: no deploy command will be emitted.');
        console.log('Use the external deployment system for image/resources/replicas/routing changes.\n');
        endpoint = nonInteractive
            ? endpointValueFromOptions(options, 'externally managed node', parsed.endpoint)
            : await promptEndpointValue("Your externally managed node's public URL", parsed.endpoint);
    } else if (scheme === 'gcp-cloudrun-monolith') {
        const project = requireParsedString(parsed.project, 'GCP project');
        const region = requireParsedString(parsed.region, 'Cloud Run region');
        const serviceName = requireParsedString(parsed.serviceName, 'Cloud Run service name');
        gcpCfg = { project, region, serviceName };
        const cmd = gcpDeployCmd(serviceName, image!, project, region,
            profile, net.rpcUrl, net.aceAddr, rpcApiKey, gasStationKey, chainRpc);
        console.log('\nDeploy command:\n');
        console.log(cmd.display);
        console.log();
        const ran = nonInteractive
            ? (options.yes ? runDeployScript(cmd.run, gcloudReady(), cmd.env, deployRunOpts) : false)
            : await maybeAutoRun(cmd.run, gcloudReady(), 'Run this now?', cmd.env, { yes: options.yes });
        const defaultEndpoint = ran
            ? captureCloudRunUrl(serviceName, project, region)
            : undefined;
        endpoint = nonInteractive
            ? await endpointFromOptions(options, 'Cloud Run service', defaultEndpoint)
            : await promptEndpoint('Cloud Run service URL', defaultEndpoint);
    } else if (scheme === 'gcp-cloudrun-microservices') {
        const project = requireParsedString(parsed.project, 'GCP project');
        const region = requireParsedString(parsed.region, 'Cloud Run region');
        const maintainerServiceName = requireParsedString(parsed.maintainerServiceName, 'Maintainer service name');
        const handlerServiceName = requireParsedString(parsed.handlerServiceName, 'Handler service name');
        const handlerMaxInstances = parsed.handlerMaxInstances ?? 10;
        gcpCfg = {
            project,
            region,
            maintainerServiceName,
            handlerServiceName,
            handlerMaxInstances,
        };
        const cmd = gcpDeployCmdMicroservices(
            {
                project,
                region,
                maintainerServiceName,
                handlerServiceName,
                handlerMaxInstances,
            },
            image!, profile, net.rpcUrl, net.aceAddr, rpcApiKey, gasStationKey, chainRpc,
        );
        console.log('\nDeploy script:\n');
        console.log(cmd.display);
        console.log();
        const ran = nonInteractive
            ? (options.yes ? runDeployScript(cmd.run, gcloudReady(), cmd.env, deployRunOpts) : false)
            : await maybeAutoRun(cmd.run, gcloudReady(), 'Run this script now?', cmd.env, { yes: options.yes });
        const defaultEndpoint = ran
            ? captureCloudRunUrl(handlerServiceName, project, region)
            : undefined;
        endpoint = nonInteractive
            ? await endpointFromOptions(options, 'Handler service', defaultEndpoint)
            : await promptEndpoint('Handler service URL', defaultEndpoint);
    } else if (scheme === 'docker-monolith') {
        dockerCfg = { containerName: parsed.containerName!, port: parsed.port! };
        const cmd = dockerRunCmd(parsed.containerName!, image!, parsed.port!,
            profile, nodeRpcUrl!, net.aceAddr, rpcApiKey, gasStationKey, chainRpc);
        console.log('\nStart command:\n');
        console.log(cmd);
        console.log();
        await maybeAutoRun(cmd, dockerReady(), 'Run this now?', undefined, { yes: options.yes });
        const defaultEndpoint = isLocalnet ? `http://localhost:${parsed.port}` : undefined;
        endpoint = await promptEndpoint("Your node's public URL", defaultEndpoint);
    } else {
        // local-build-monolith
        const repoPath = parsed.repoPath!;
        const port     = parsed.port!;
        const logMaxMb = parsed.logMaxMb!;
        console.log('\nBuilding node binary (this may take a minute)...\n');
        execSync(localBuildCmd(repoPath), { stdio: 'inherit' });

        const nodeKey = makeNodeKey(net.rpcUrl, net.aceAddr, profile.accountAddr);
        const logFile = logFilePath(nodeKey);
        const binaryPath = path.join(repoPath, 'target', 'release', 'network-node');
        const runArgs = localRunArgs(port, profile, net.rpcUrl, net.aceAddr, rpcApiKey, gasStationKey, chainRpc);
        const pid = spawnLocalNode(binaryPath, runArgs, logFile);
        console.log(`\nNode started in background  pid=${pid}  log=${logFile}\n`);

        const logrotateConf = writeLogrotateConf(logFile, logMaxMb);
        runLogrotate(logrotateConf);

        localCfg = { repoPath, port, pid, logFile, logMaxMb };
        endpoint = await promptEndpoint("Your node's public URL", `http://localhost:${port}`);
    }

    await ensureAccountFunded(net.rpcUrl, profile.accountAddr, rpcApiKey, gasStationKey);

    console.log('\nRegistering on-chain...\n');
    await registerOnChain(
        { ...profile, rpcUrl: net.rpcUrl, aceAddr: net.aceAddr, rpcApiKey, gasStationKey },
        endpoint,
    );

    const node: TrackedNode = {
        rpcUrl:      net.rpcUrl,
        nodeRpcUrl:  nodeRpcUrl && nodeRpcUrl !== net.rpcUrl ? nodeRpcUrl : undefined,
        aceAddr:     net.aceAddr,
        rpcApiKey:   rpcApiKey,
        accountAddr: profile.accountAddr,
        accountSk:   profile.accountSk,
        pkeDk:       profile.pkeDk,
        pkeEk:       profile.pkeEk,
        alias:       parsed.alias,
        endpoint,
        image,
        platform,
        mode,
        gcp:          gcpCfg,
        docker:       dockerCfg,
        local:        localCfg,
        gasStationKey,
        chainRpc:     Object.keys(chainRpc).length > 0 ? chainRpc : undefined,
    };

    const nodeKey = makeNodeKey(net.rpcUrl, net.aceAddr, profile.accountAddr);

    console.log('\nShare your account address with the ACE deployer to be added to the committee:\n');
    console.log(`  ${profile.accountAddr}\n`);

    return { nodeKey, node };
}

const OCTAS_PER_APT = 100_000_000n;

function detectAptosNetwork(rpcUrl: string): 'localnet' | 'devnet' | 'testnet' | 'mainnet' | 'shelbynet' | 'shelby-private-beta' | 'other' {
    if (/localhost|127\.0\.0\.1/.test(rpcUrl)) return 'localnet';
    if (/shelbynet/.test(rpcUrl)) return 'shelbynet';
    if (/shelby-private-beta/.test(rpcUrl)) return 'shelby-private-beta';
    if (/devnet\.aptoslabs\.com/.test(rpcUrl))  return 'devnet';
    if (/testnet\.aptoslabs\.com/.test(rpcUrl)) return 'testnet';
    if (/mainnet\.aptoslabs\.com/.test(rpcUrl)) return 'mainnet';
    return 'other';
}

function aptFaucetUrl(rpcUrl: string): string | undefined {
    if (/localhost/.test(rpcUrl))    return rpcUrl.replace(/:\d+\/.*$/, ':8081');
    if (/127\.0\.0\.1/.test(rpcUrl)) return rpcUrl.replace(/:\d+\/.*$/, ':8081');
    if (/devnet\.aptoslabs\.com/.test(rpcUrl))  return 'https://faucet.devnet.aptoslabs.com';
    if (/testnet\.aptoslabs\.com/.test(rpcUrl)) return 'https://faucet.testnet.aptoslabs.com';
    return undefined;
}

async function getAptBalance(rpcUrl: string, addr: string, apiKey?: string): Promise<bigint> {
    // Use the unified `0x1::coin::balance` view function rather than reading the
    // legacy `0x1::coin::CoinStore<AptosCoin>` resource directly. Modern testnet
    // and mainnet faucets credit APT via the fungible-asset accounting model,
    // which lives in a separate object — the legacy CoinStore resource may never
    // be created. The view function transparently sums both models.
    try {
        const headers: HeadersInit = {
            'Content-Type': 'application/json',
            ...(apiKey ? { Authorization: `Bearer ${apiKey}` } : {}),
        };
        const res = await fetch(`${rpcUrl}/view`, {
            method: 'POST',
            headers,
            body: JSON.stringify({
                function: '0x1::coin::balance',
                type_arguments: ['0x1::aptos_coin::AptosCoin'],
                arguments: [addr],
            }),
            signal: AbortSignal.timeout(5000),
        });
        if (!res.ok) return 0n;
        const data = await res.json() as [string];
        return BigInt(data[0]);
    } catch {
        return 0n;
    }
}

export async function ensureAccountFunded(
    rpcUrl: string, accountAddr: string, apiKey?: string, gasStationKey?: string,
): Promise<void> {
    if (gasStationKey) return;

    const network = detectAptosNetwork(rpcUrl);
    const faucet  = aptFaucetUrl(rpcUrl);

    if (network === 'localnet' || network === 'devnet') {
        if (faucet) {
            process.stdout.write('\nFunding account with 10 APT via faucet...');
            try {
                const res = await fetch(
                    `${faucet}/mint?address=${accountAddr}&amount=${10n * OCTAS_PER_APT}`,
                    { method: 'POST', signal: AbortSignal.timeout(5000) },
                );
                if (res.ok) { process.stdout.write(' ✓\n'); return; }
            } catch { /* fall through */ }
            process.stdout.write(' ✗  (faucet unreachable — fund manually before registering)\n');
        }
        return;
    }

    if (network !== 'testnet' && network !== 'mainnet' && network !== 'shelbynet' && network !== 'shelby-private-beta') return;

    console.log();
    if (network === 'testnet' && faucet) {
        console.log('Fund your account using the testnet faucet:');
        console.log(`  curl -X POST '${faucet}/mint?address=${accountAddr}&amount=1000000000'\n`);
    } else {
        console.log(`Fund your account (${accountAddr}) with APT to cover transaction fees.\n`);
    }

    process.stdout.write('Waiting for account to receive APT...');
    while (true) {
        const bal = await getAptBalance(rpcUrl, accountAddr, apiKey);
        if (bal > 0n) {
            const apt = (Number(bal) / Number(OCTAS_PER_APT)).toFixed(4);
            process.stdout.write(` ✓  (${apt} APT)\n`);
            return;
        }
        await new Promise(r => setTimeout(r, 2000));
        process.stdout.write('.');
    }
}

async function promptNetworkDetails(): Promise<NetworkDetails> {
    console.log('\nACE deployment details\n');
    const blob = (await input({ message: 'Paste deployment blob from admin (or Enter to fill manually)' })).trim();
    if (blob) {
        try {
            const p = JSON.parse(blob) as Record<string, string>;
            if (typeof p.rpcUrl === 'string' && typeof p.aceAddr === 'string') {
                console.log(`  ✓ Parsed — contract ${p.aceAddr.slice(0, 10)}...\n`);
                return {
                    rpcUrl:        p.rpcUrl,
                    aceAddr:       p.aceAddr,
                    rpcApiKey:     p.rpcApiKey     || undefined,
                    gasStationKey: p.gasStationKey || undefined,
                };
            }
        } catch {
            // fall through
        }
        console.log('  Could not parse blob — please fill in manually.\n');
    }

    const rpcUrl        = await input({ message: 'Deployment API URL' });
    const aceAddr       = await input({ message: 'Contract address' });
    const rpcApiKey     = (await input({ message: 'API key         (Enter to skip)' })) || undefined;
    const gasStationKey = (await input({ message: 'Gas station key (Enter to skip)' })) || undefined;
    console.log();
    return { rpcUrl, aceAddr, rpcApiKey, gasStationKey };
}
