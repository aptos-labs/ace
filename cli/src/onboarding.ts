// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { input } from '@inquirer/prompts';
import { execSync } from 'child_process';
import { randomBytes } from 'crypto';
import { writeFileSync, mkdirSync } from 'fs';
import { homedir } from 'os';
import * as path from 'path';
import { generateProfile } from './new-profile.js';
import { registerOnChain } from './register.js';
import { fetchTagsRaw } from './docker-hub.js';
import {
    loadConfig, makeNodeKey,
    type TrackedNode, type ChainRpcOverrides, type LocalConfig, type Mode, type GceConfig,
    type GcpCloudSqlConfig,
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
    aptosShelbyPrivateBeta: '',
} as const;

const CHAIN_RPC_KEYS = [
    'aptosMainnetApi',
    'aptosMainnetApikey',
    'aptosTestnetApi',
    'aptosTestnetApikey',
    'aptosLocalnetApi',
    'aptosLocalnetApikey',
    'aptosShelbyPrivateBetaApi',
    'aptosShelbyPrivateBetaApikey',
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
    zone?: string;
    instanceName?: string;
    machineType?: string;
    diskSizeGb?: string;
    port?: string;
    containerName?: string;
    network?: string;
    subnet?: string;
    cloudSqlInstanceName?: string;
    cloudSqlDatabase?: string;
    cloudSqlUser?: string;
    cloudSqlPrivateRangeName?: string;
    endpoint?: string;
    nodeMsgEndpoint?: string;
    vssStoreUrl?: string;
    nodeMsgListen?: string;
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
        opts.zone ||
        opts.instanceName ||
        opts.machineType ||
        opts.diskSizeGb ||
        opts.port ||
        opts.containerName ||
        opts.network ||
        opts.subnet ||
        opts.cloudSqlInstanceName ||
        opts.cloudSqlDatabase ||
        opts.cloudSqlUser ||
        opts.cloudSqlPrivateRangeName ||
        opts.endpoint ||
        opts.nodeMsgEndpoint ||
        opts.vssStoreUrl ||
        opts.nodeMsgListen ||
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
        chainRpc.aptosShelbyPrivateBetaApi,
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
    sigSk:                'ACE_SIG_SK',
    vssStoreUrl:          'ACE_VSS_STORE_URL',
    nodeMsgListen:        'ACE_NODE_MSG_LISTEN',
    deploymentApiKey:     'ACE_DEPLOYMENT_APIKEY',
    deploymentGasKey:     'ACE_DEPLOYMENT_GASKEY',
    aptosMainnetApiKey:   'ACE_APTOS_MAINNET_APIKEY',
    aptosTestnetApiKey:   'ACE_APTOS_TESTNET_APIKEY',
    aptosLocalnetApiKey:  'ACE_APTOS_LOCALNET_APIKEY',
    aptosShelbyPrivateBetaApiKey: 'ACE_APTOS_SHELBY_PRIVATE_BETA_APIKEY',
} as const;

export const GCP_CONFIG_ENV = 'ACE_CONFIG_JSON';
export const GCP_CLOUD_SQL_PASSWORD_ENV = 'ACE_CLOUD_SQL_PASSWORD';

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
    node: { accountSk: string; pkeDk: string; sigSk: string; vssStoreUrl: string; nodeMsgListen: string },
    rpcApiKey?: string,
    gasStationKey?: string,
    chainRpc?: ChainRpcOverrides,
): string {
    const cfg = {
        accountSk:            node.accountSk,
        pkeDk:                node.pkeDk,
        sigSk:                node.sigSk,
        vssStoreUrl:          node.vssStoreUrl,
        nodeMsgListen:        node.nodeMsgListen,
        ...(rpcApiKey                  ? { deploymentApiKey:    rpcApiKey }                  : {}),
        ...(gasStationKey              ? { deploymentGasKey:    gasStationKey }              : {}),
        ...(chainRpc?.aptosMainnetApikey  ? { aptosMainnetApiKey:  chainRpc.aptosMainnetApikey }  : {}),
        ...(chainRpc?.aptosTestnetApikey  ? { aptosTestnetApiKey:  chainRpc.aptosTestnetApikey }  : {}),
        ...(chainRpc?.aptosLocalnetApikey ? { aptosLocalnetApiKey: chainRpc.aptosLocalnetApikey } : {}),
        ...(chainRpc?.aptosShelbyPrivateBetaApikey ? { aptosShelbyPrivateBetaApiKey: chainRpc.aptosShelbyPrivateBetaApikey } : {}),
    };
    return JSON.stringify(cfg);
}

function configBinding(
    prefix: string,
    node: { accountSk: string; pkeDk: string; sigSk: string; vssStoreUrl: string; nodeMsgListen: string },
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

interface CloudSqlDeployConfig extends GcpCloudSqlConfig {
    project: string;
    region: string;
    network: string;
    subnet: string;
    password: string;
}

function generatedCloudSqlPassword(): string {
    return randomBytes(24).toString('base64url');
}

export function cloudSqlVssStoreUrl(
    cfg: Pick<CloudSqlDeployConfig, 'databaseName' | 'user'>,
    privateIp: string,
    password: string,
): string {
    return `postgres://${encodeURIComponent(cfg.user)}:${encodeURIComponent(password)}@${privateIp}:5432/${encodeURIComponent(cfg.databaseName)}`;
}

export function captureCloudSqlPrivateIp(instanceName: string, project: string): string | undefined {
    try {
        const out = execSync(
            `gcloud sql instances describe ${shellQuote(instanceName)} --project ${shellQuote(project)} --format='value(ipAddresses[0].ipAddress)'`,
            { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
        ).trim();
        return out || undefined;
    } catch {
        return undefined;
    }
}

function cloudSqlSetupLines(cfg: CloudSqlDeployConfig): string[] {
    return [
        `# Provision/reuse Cloud SQL Postgres for the shared VSS store.`,
        `PROJECT=${shellQuote(cfg.project)}`,
        `SQL_REGION=${shellQuote(cfg.region)}`,
        `SQL_INSTANCE=${shellQuote(cfg.instanceName)}`,
        `SQL_DATABASE=${shellQuote(cfg.databaseName)}`,
        `SQL_USER=${shellQuote(cfg.user)}`,
        `SQL_NETWORK=${shellQuote(cfg.network)}`,
        `SQL_PRIVATE_RANGE=${shellQuote(cfg.privateRangeName)}`,
        `if [ -z "\${${GCP_CLOUD_SQL_PASSWORD_ENV}:-}" ]; then`,
        `  echo "Missing ${GCP_CLOUD_SQL_PASSWORD_ENV}; export it before running this script." >&2`,
        `  exit 1`,
        `fi`,
        `if [ -z "\${${GCP_CONFIG_ENV}:-}" ]; then`,
        `  echo "Missing ${GCP_CONFIG_ENV}; export it before running this script." >&2`,
        `  exit 1`,
        `fi`,
        `gcloud services enable run.googleapis.com secretmanager.googleapis.com sqladmin.googleapis.com servicenetworking.googleapis.com --project "$PROJECT"`,
        `if ! gcloud services vpc-peerings list --network="$SQL_NETWORK" --service=servicenetworking.googleapis.com --project "$PROJECT" --format='value(network)' | grep -q .; then`,
        `  gcloud compute addresses describe "$SQL_PRIVATE_RANGE" --global --project "$PROJECT" >/dev/null 2>&1 || \\`,
        `    gcloud compute addresses create "$SQL_PRIVATE_RANGE" --global --purpose=VPC_PEERING --prefix-length=16 --network="$SQL_NETWORK" --project "$PROJECT"`,
        `  gcloud services vpc-peerings connect --network="$SQL_NETWORK" --ranges="$SQL_PRIVATE_RANGE" --service=servicenetworking.googleapis.com --project "$PROJECT" --quiet`,
        `fi`,
        `if ! gcloud sql instances describe "$SQL_INSTANCE" --project "$PROJECT" >/dev/null 2>&1; then`,
        `  gcloud sql instances create "$SQL_INSTANCE" \\`,
        `    --project "$PROJECT" \\`,
        `    --region "$SQL_REGION" \\`,
        `    --database-version=POSTGRES_16 \\`,
        `    --edition=enterprise \\`,
        `    --cpu=1 \\`,
        `    --memory=4GiB \\`,
        `    --storage-size=10 \\`,
        `    --availability-type=zonal \\`,
        `    --network="projects/$PROJECT/global/networks/$SQL_NETWORK" \\`,
        `    --no-assign-ip \\`,
        `    --no-deletion-protection \\`,
        `    --root-password="$${GCP_CLOUD_SQL_PASSWORD_ENV}" \\`,
        `    --quiet`,
        `fi`,
        `gcloud sql databases describe "$SQL_DATABASE" --instance "$SQL_INSTANCE" --project "$PROJECT" >/dev/null 2>&1 || \\`,
        `  gcloud sql databases create "$SQL_DATABASE" --instance "$SQL_INSTANCE" --project "$PROJECT"`,
        `if gcloud sql users describe "$SQL_USER" --instance "$SQL_INSTANCE" --project "$PROJECT" >/dev/null 2>&1; then`,
        `  gcloud sql users set-password "$SQL_USER" --instance "$SQL_INSTANCE" --project "$PROJECT" --password="$${GCP_CLOUD_SQL_PASSWORD_ENV}"`,
        `else`,
        `  gcloud sql users create "$SQL_USER" --instance "$SQL_INSTANCE" --project "$PROJECT" --password="$${GCP_CLOUD_SQL_PASSWORD_ENV}"`,
        `fi`,
        `SQL_PRIVATE_IP=$(gcloud sql instances describe "$SQL_INSTANCE" --project "$PROJECT" --format='value(ipAddresses[0].ipAddress)')`,
        `if [ -z "$SQL_PRIVATE_IP" ]; then`,
        `  echo "Cloud SQL instance $SQL_INSTANCE has no private IP." >&2`,
        `  exit 1`,
        `fi`,
        `VSS_STORE_URL="postgres://$SQL_USER:$${GCP_CLOUD_SQL_PASSWORD_ENV}@$SQL_PRIVATE_IP:5432/$SQL_DATABASE"`,
        `${GCP_CONFIG_ENV}="$(${GCP_SECRET_ENV.vssStoreUrl}="$VSS_STORE_URL" node <<'ACE_CONFIG_JSON_NODE'`,
        `const cfg = JSON.parse(process.env.${GCP_CONFIG_ENV} || '{}');`,
        `cfg.vssStoreUrl = process.env.${GCP_SECRET_ENV.vssStoreUrl};`,
        `process.stdout.write(JSON.stringify(cfg));`,
        `ACE_CONFIG_JSON_NODE`,
        `)"`,
        `export ${GCP_CONFIG_ENV}`,
        ``,
    ];
}

export function gcpDeployCmd(
    serviceName: string, image: string, project: string, region: string,
    node: { accountAddr: string; accountSk: string; pkeDk: string; sigSk: string; vssStoreUrl: string; nodeMsgListen: string },
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
        `  --use-http2`,
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
 * The script is **ordered**: the Maintainer's auto-assigned Cloud Run URL is
 * the node-message endpoint registered on chain, and is NOT derivable from
 * `<service>-<project_number>` ahead of time (Cloud Run mixes that with a
 * legacy `<service>-<hash>-<region>.a.run.app` form for some services /
 * projects). Capturing it post-deploy via `gcloud run services describe`
 * is the only correct path.
 *
 * Auth model: the Handler is the public request endpoint. The Maintainer is
 * also the node-message ingress for offchain VSS, so it must be externally
 * reachable at its registered node-message URL.
 *
 * Step order:
 *   1. Optionally provision the Cloud SQL VSS store.
 *   2. Deploy the public Maintainer/node-message endpoint (min=max=1).
 *   3. Capture the Maintainer URL.
 *   4. Deploy the Handler.
 */
export function gcpDeployCmdMicroservices(
    cfg: {
        project: string;
        region: string;
        maintainerServiceName: string;
        handlerServiceName: string;
        handlerMaxInstances: number;
        vpcNetwork?: string;
        vpcSubnet?: string;
        forceMaintainerVpc?: boolean;
        cloudSql?: Omit<CloudSqlDeployConfig, 'project' | 'region' | 'network' | 'subnet'>;
    },
    image: string,
    node: { accountAddr: string; accountSk: string; pkeDk: string; sigSk: string; vssStoreUrl: string; nodeMsgListen: string },
    rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string,
    chainRpc?: ChainRpcOverrides,
): GcpDeployScript {
    const vpcNetwork = cfg.vpcNetwork ?? DEFAULT_VPC_NETWORK;
    const vpcSubnet = cfg.vpcSubnet ?? DEFAULT_VPC_SUBNET;
    // Maintainer needs VPC egress when it talks to private chain RPCs or to
    // the auto-provisioned Cloud SQL private IP. Handler needs VPC egress for
    // the same private Cloud SQL store when the CLI provisions it.
    const maintainerVpcLines = (cfg.forceMaintainerVpc || cfg.cloudSql || rpcUrlsNeedVpcEgress(chainRpc)) ? [
        `  --network=${vpcNetwork}`,
        `  --subnet=${vpcSubnet}`,
        `  --vpc-egress=${DEFAULT_VPC_EGRESS}`,
    ] : [];
    const handlerVpcLines = [
        `  --network=${vpcNetwork}`,
        `  --subnet=${vpcSubnet}`,
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
    const handlerArgs = [
        'run',
        '--mode=handler',
        `--ace-deployment-api=${rpcUrl}`,
        `--ace-deployment-addr=${aceAddr}`,
        `--account-addr=${node.accountAddr}`,
        `--port=8080`,
        ...chainRpcArgs(chainRpc, { includeSecrets: false }),
    ];

    const maintainerDeploy = [
        `gcloud run deploy ${cfg.maintainerServiceName}`,
        `  --image docker.io/${image}`,
        `  --project ${cfg.project}`,
        `  --region ${cfg.region}`,
        `  --ingress=all`,
        `  --allow-unauthenticated`,
        `  --min-instances 1`,
        `  --max-instances 1`,
        `  --no-cpu-throttling`,
        `  --concurrency=${DEFAULT_CONTAINER_CONCURRENCY}`,
        `  --use-http2`,
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
        `  --use-http2`,
        ...cloudRunSecretFlags(secretBindings),
        ...handlerVpcLines,
        `  --args "${handlerArgs.join(',')}"`,
    ].join(' \\\n');

    const script = [
        `set -e`,
        ``,
        ...(cfg.cloudSql ? cloudSqlSetupLines({
            ...cfg.cloudSql,
            project: cfg.project,
            region: cfg.region,
            network: vpcNetwork,
            subnet: vpcSubnet,
        }) : []),
        ...cloudRunSecretSetup(cfg.project, secretBindings),
        `# Deploy the Maintainer/node-message endpoint (public, pinned at min=max=1).`,
        maintainerDeploy,
        ``,
        `# Capture the Maintainer's auto-assigned URL (Cloud Run picks the format,`,
        `#    we can't derive it ahead of time).`,
        `MAINT_URL=$(gcloud run services describe ${cfg.maintainerServiceName} \\`,
        `  --project=${cfg.project} --region=${cfg.region} --format='value(status.url)')`,
        `echo "Maintainer URL: $MAINT_URL"`,
        ``,
        `# Deploy the Handler (public, scales 1..${cfg.handlerMaxInstances}).`,
        `#    Direct VPC egress is required for Cloud SQL private IP access.`,
        handlerDeploy,
    ].join('\n');
    return {
        display: script,
        run: script,
        env: {
            ...secretEnv(secretBindings),
            ...(cfg.cloudSql ? { [GCP_CLOUD_SQL_PASSWORD_ENV]: cfg.cloudSql.password } : {}),
        },
    };
}

export function gceResourceNames(instanceName: string): Required<Pick<
    GceConfig,
    'staticIpName' | 'firewallRuleName' | 'diskName' | 'networkTag'
>> {
    return {
        staticIpName:     `${instanceName}-ip`,
        firewallRuleName: `${instanceName}-allow-ace`,
        diskName:         `${instanceName}-vss`,
        networkTag:       `${instanceName}-ace`,
    };
}

function normalizeGceConfig(cfg: GceConfig): GceConfig {
    return {
        ...cfg,
        network: cfg.network ?? 'default',
        ...gceResourceNames(cfg.instanceName),
    };
}

export function captureGceExternalIp(
    instanceName: string, project: string, zone: string,
): string | undefined {
    try {
        const out = execSync(
            `gcloud compute instances describe ${shellQuote(instanceName)} --project ${shellQuote(project)} --zone ${shellQuote(zone)} --format='value(networkInterfaces[0].accessConfigs[0].natIP)'`,
            { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
        ).trim();
        return out || undefined;
    } catch {
        return undefined;
    }
}

export function gceDeployCmd(
    rawCfg: GceConfig,
    image: string,
    node: { accountAddr: string; accountSk: string; pkeDk: string; sigSk: string; vssStoreUrl: string; nodeMsgListen: string },
    rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string,
    chainRpc?: ChainRpcOverrides,
): GcpDeployScript {
    const cfg = normalizeGceConfig(rawCfg);
    const runtimeConfig = runtimeConfigJson(node, rpcApiKey, gasStationKey, chainRpc);
    const publicArgs = [
        'run',
        `--ace-deployment-api=${rpcUrl}`,
        `--ace-deployment-addr=${aceAddr}`,
        `--account-addr=${node.accountAddr}`,
        `--port=${cfg.port}`,
        ...chainRpcArgs(chainRpc, { includeSecrets: false }),
    ];
    const dockerArgs = publicArgs.map(shellQuote).join(' \\\n  ');
    const imageRef = `docker.io/${image}`;
    const startupHead = [
        `cat > "$STARTUP_SCRIPT" <<'ACE_VM_STARTUP_HEAD'`,
        `#!/usr/bin/env bash`,
        `set -euo pipefail`,
        `export DEBIAN_FRONTEND=noninteractive`,
        ``,
        `mkdir -p /etc/ace /ace-vss`,
        `DEVICE="/dev/disk/by-id/google-ace-vss"`,
        `if [ -e "$DEVICE" ]; then`,
        `  if ! blkid "$DEVICE" >/dev/null 2>&1; then`,
        `    mkfs.ext4 -F "$DEVICE"`,
        `  fi`,
        `  if ! grep -q ' /ace-vss ' /etc/fstab; then`,
        `    echo "$DEVICE /ace-vss ext4 defaults,nofail 0 2" >> /etc/fstab`,
        `  fi`,
        `  mount /ace-vss || mount -a || true`,
        `fi`,
        ``,
        `if ! command -v docker >/dev/null 2>&1; then`,
        `  apt-get update`,
        `  apt-get install -y docker.io`,
        `fi`,
        `systemctl enable --now docker`,
        ``,
        `cat >/etc/ace/config.json <<'ACE_CONFIG_EOF'`,
        `ACE_VM_STARTUP_HEAD`,
        `printf '%s\\n' "$ACE_CONFIG_JSON" >> "$STARTUP_SCRIPT"`,
    ];
    const startupTail = [
        `cat >> "$STARTUP_SCRIPT" <<'ACE_VM_STARTUP_TAIL'`,
        `ACE_CONFIG_EOF`,
        ``,
        `docker rm -f ${shellQuote(cfg.containerName)} >/dev/null 2>&1 || true`,
        `docker pull ${shellQuote(imageRef)}`,
        `docker run -d --platform linux/amd64 --restart unless-stopped \\`,
        `  --name ${shellQuote(cfg.containerName)} \\`,
        `  -p ${shellQuote(`${cfg.port}:${cfg.port}`)} \\`,
        `  -v /ace-vss:/ace-vss \\`,
        `  -e ACE_CONFIG_JSON="$(cat /etc/ace/config.json)" \\`,
        `  ${shellQuote(imageRef)} \\`,
        `  ${dockerArgs}`,
        `ACE_VM_STARTUP_TAIL`,
    ];
    const script = [
        `set -e`,
        ``,
        `PROJECT=${shellQuote(cfg.project)}`,
        `ZONE=${shellQuote(cfg.zone)}`,
        `REGION="\${ZONE%-*}"`,
        `INSTANCE=${shellQuote(cfg.instanceName)}`,
        `MACHINE_TYPE=${shellQuote(cfg.machineType)}`,
        `DISK_SIZE_GB=${shellQuote(String(cfg.diskSizeGb))}`,
        `PORT=${shellQuote(cfg.port)}`,
        `NETWORK=${shellQuote(cfg.network ?? 'default')}`,
        `STATIC_IP_NAME=${shellQuote(cfg.staticIpName!)}`,
        `FIREWALL_RULE=${shellQuote(cfg.firewallRuleName!)}`,
        `DISK_NAME=${shellQuote(cfg.diskName!)}`,
        `NETWORK_TAG=${shellQuote(cfg.networkTag!)}`,
        ``,
        `if [ -z "\${ACE_CONFIG_JSON:-}" ]; then`,
        `  echo "Missing ACE_CONFIG_JSON; export it before running this script." >&2`,
        `  exit 1`,
        `fi`,
        ``,
        `STARTUP_SCRIPT="$(mktemp)"`,
        `trap 'rm -f "$STARTUP_SCRIPT"' EXIT`,
        ...startupHead,
        ...startupTail,
        ``,
        `gcloud compute addresses describe "$STATIC_IP_NAME" --project "$PROJECT" --region "$REGION" >/dev/null 2>&1 || \\`,
        `  gcloud compute addresses create "$STATIC_IP_NAME" --project "$PROJECT" --region "$REGION" >/dev/null`,
        `STATIC_IP="$(gcloud compute addresses describe "$STATIC_IP_NAME" --project "$PROJECT" --region "$REGION" --format='value(address)')"`,
        ``,
        `if gcloud compute firewall-rules describe "$FIREWALL_RULE" --project "$PROJECT" >/dev/null 2>&1; then`,
        `  gcloud compute firewall-rules update "$FIREWALL_RULE" --project "$PROJECT" \\`,
        `    --allow "tcp:$PORT" --target-tags "$NETWORK_TAG" --source-ranges 0.0.0.0/0 >/dev/null`,
        `else`,
        `  gcloud compute firewall-rules create "$FIREWALL_RULE" --project "$PROJECT" \\`,
        `    --network "$NETWORK" --allow "tcp:$PORT" --target-tags "$NETWORK_TAG" --source-ranges 0.0.0.0/0 >/dev/null`,
        `fi`,
        ``,
        `if gcloud compute disks describe "$DISK_NAME" --project "$PROJECT" --zone "$ZONE" >/dev/null 2>&1; then`,
        `  DISK_FLAG=("--disk=name=$DISK_NAME,device-name=ace-vss,mode=rw,boot=no,auto-delete=no")`,
        `else`,
        `  DISK_FLAG=("--create-disk=name=$DISK_NAME,device-name=ace-vss,mode=rw,boot=no,auto-delete=no,size=${'${DISK_SIZE_GB}'}GB,type=pd-balanced")`,
        `fi`,
        ``,
        `if gcloud compute instances describe "$INSTANCE" --project "$PROJECT" --zone "$ZONE" >/dev/null 2>&1; then`,
        `  gcloud compute instances add-metadata "$INSTANCE" --project "$PROJECT" --zone "$ZONE" --metadata-from-file=startup-script="$STARTUP_SCRIPT" >/dev/null`,
        `  gcloud compute instances reset "$INSTANCE" --project "$PROJECT" --zone "$ZONE" --quiet >/dev/null`,
        `else`,
        `  gcloud compute instances create "$INSTANCE" \\`,
        `    --project "$PROJECT" --zone "$ZONE" --machine-type "$MACHINE_TYPE" \\`,
        `    --network "$NETWORK" --tags "$NETWORK_TAG" --address "$STATIC_IP" \\`,
        `    --image-family debian-12 --image-project debian-cloud \\`,
        `    --metadata-from-file=startup-script="$STARTUP_SCRIPT" \\`,
        `    "\${DISK_FLAG[@]}" >/dev/null`,
        `fi`,
        ``,
        `echo "VM external IP: $STATIC_IP"`,
        `echo "Node URL: http://$STATIC_IP:$PORT"`,
    ].join('\n');
    return { display: script, run: script, env: { ACE_CONFIG_JSON: runtimeConfig } };
}

export function dockerRunCmd(
    containerName: string, image: string, port: string,
    node: { accountAddr: string; accountSk: string; pkeDk: string; sigSk: string; vssStoreUrl: string; nodeMsgListen: string },
    rpcUrl: string, aceAddr: string, rpcApiKey?: string, gasStationKey?: string,
    chainRpc?: ChainRpcOverrides,
): string {
    const hostVssDir = path.join(homedir(), '.ace', 'vss', containerName);
    return [
        `mkdir -p ${shellQuote(hostVssDir)} &&`,
        `docker run -d --platform linux/amd64 --restart unless-stopped`,
        `  --name ${containerName}`,
        `  -p ${port}:${port}`,
        `  -v ${shellQuote(hostVssDir)}:/ace-vss`,
        `  ${image}`,
        `  run`,
        `  --ace-deployment-api=${rpcUrl}`,
        `  --ace-deployment-addr=${aceAddr}`,
        ...(rpcApiKey     ? [`  --ace-deployment-apikey=${rpcApiKey}`]     : []),
        ...(gasStationKey ? [`  --ace-deployment-gaskey=${gasStationKey}`] : []),
        `  --account-addr=${node.accountAddr}`,
        `  --account-sk=${node.accountSk}`,
        `  --pke-dk=${node.pkeDk}`,
        `  --sig-sk=${node.sigSk}`,
        `  --vss-store-url=${node.vssStoreUrl}`,
        `  --port=${port}`,
        ...chainRpcArgs(chainRpc),
    ].join(' \\\n');
}

export function localBuildCmd(repoPath: string): string {
    return `cargo build --release -p network-node --manifest-path ${repoPath}/Cargo.toml`;
}

export function localRunCmd(
    repoPath: string, port: string,
    node: { accountAddr: string; accountSk: string; pkeDk: string; sigSk: string; vssStoreUrl: string; nodeMsgListen: string },
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
        `  --sig-sk=${node.sigSk}`,
        `  --vss-store-url=${node.vssStoreUrl}`,
        `  --port=${port}`,
        ...chainRpcArgs(chainRpc).map(a => `  ${a}`),
    ].join(' \\\n');
}

export function localRunArgs(
    port: string,
    node: { accountAddr: string; accountSk: string; pkeDk: string; sigSk: string; vssStoreUrl: string; nodeMsgListen: string },
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
        `--sig-sk=${node.sigSk}`,
        `--vss-store-url=${node.vssStoreUrl}`,
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
    node: { accountAddr: string; accountSk: string; pkeDk: string; sigSk: string; vssStoreUrl: string; nodeMsgListen: string },
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
        ...(includeSecrets ? [
            `--account-sk=${node.accountSk}`,
            `--pke-dk=${node.pkeDk}`,
            `--sig-sk=${node.sigSk}`,
            `--vss-store-url=${node.vssStoreUrl}`,
        ] : []),
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
        ...f('--aptos-shelby-private-beta-api=',    r.aptosShelbyPrivateBetaApi),
        ...(includeSecrets ? f('--aptos-shelby-private-beta-apikey=', r.aptosShelbyPrivateBetaApikey) : []),
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
        aptosShelbyPrivateBetaApi:    await askUrl('Aptos shelby-private-beta API URL', CHAIN_DEFAULTS.aptosShelbyPrivateBeta, current?.aptosShelbyPrivateBetaApi),
        aptosShelbyPrivateBetaApikey: await askKey('Aptos shelby-private-beta API key', current?.aptosShelbyPrivateBetaApikey),
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
    if (isLocalnet) {
        throw new Error('GCP runtimes are unavailable for localnet deployments.');
    }
    if (platform === 'gcp-vm' || platform === 'gce') {
        const mode = opts.mode ?? 'monolith';
        if (mode === 'monolith') return 'gcp-vm-monolith';
        throw new Error('--platform gcp-vm supports only --mode monolith.');
    }
    if (platform !== 'gcp') {
        throw new Error('Non-interactive node new currently supports --platform gcp, --platform gcp-vm, or --mode metadata-management-only.');
    }
    const mode = opts.mode ?? 'microservices';
    if (mode === 'microservices') return 'gcp-cloudrun-microservices';
    if (mode === 'monolith') return 'gcp-vm-monolith';
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
        vssStoreUrl: nonEmpty(opts.vssStoreUrl) ?? defaults.vssStoreUrl,
        nodeMsgListen: nonEmpty(opts.nodeMsgListen) ?? defaults.nodeMsgListen,
    };
    if (scheme === 'gcp-vm-monolith') {
        return {
            ...common,
            project:       nonEmpty(opts.project) ?? defaults.project,
            zone:          nonEmpty(opts.zone) ?? defaults.zone,
            instanceName:  nonEmpty(opts.instanceName) ?? defaults.instanceName,
            machineType:   nonEmpty(opts.machineType) ?? defaults.machineType,
            diskSizeGb:    parsePositiveInt(opts.diskSizeGb, '--disk-size-gb', defaults.diskSizeGb ?? 50),
            network:       nonEmpty(opts.network) ?? defaults.network,
            port:          nonEmpty(opts.port) ?? defaults.port,
            containerName: nonEmpty(opts.containerName) ?? defaults.containerName,
        };
    }
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
        vpcNetwork:             nonEmpty(opts.network) ?? defaults.vpcNetwork,
        vpcSubnet:              nonEmpty(opts.subnet) ?? defaults.vpcSubnet,
        cloudSqlInstanceName:   nonEmpty(opts.cloudSqlInstanceName) ?? defaults.cloudSqlInstanceName,
        cloudSqlDatabase:       nonEmpty(opts.cloudSqlDatabase) ?? defaults.cloudSqlDatabase,
        cloudSqlUser:           nonEmpty(opts.cloudSqlUser) ?? defaults.cloudSqlUser,
        cloudSqlPrivateRangeName: nonEmpty(opts.cloudSqlPrivateRangeName) ?? defaults.cloudSqlPrivateRangeName,
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
    waitMs = 0,
): Promise<string> {
    const endpoint = nonEmpty(opts.endpoint) ?? capturedEndpoint;
    if (!endpoint) {
        throw new Error(`Could not determine ${label} endpoint. Pass --endpoint or run with --yes so the CLI can deploy and discover it.`);
    }
    const deadline = Date.now() + waitMs;
    while (true) {
        process.stderr.write(`  Checking ${label} endpoint reachability...`);
        if (await probeEndpoint(endpoint)) {
            process.stderr.write(' ✓\n');
            return endpoint;
        }
        if (Date.now() >= deadline) break;
        process.stderr.write(' not ready; retrying\n');
        await new Promise(r => setTimeout(r, 5000));
    }
    process.stderr.write(' ✗\n');
    throw new Error(`${label} endpoint is not reachable: ${endpoint}`);
}

async function promptEndpointValue(message: string, defaultValue?: string): Promise<string> {
    let last = defaultValue;
    while (true) {
        const url = (await input({ message, default: last })).trim();
        if (!url) continue;
        return url.replace(/\/$/, '');
    }
}

function metadataEndpointValueFromOptions(
    opts: NodeNewOptions,
    label: string,
    capturedEndpoint?: string,
): string {
    const endpoint = nonEmpty(opts.endpoint) ?? capturedEndpoint;
    if (!endpoint) {
        throw new Error(`Missing ${label} endpoint. Pass --endpoint.`);
    }
    return endpoint.replace(/\/$/, '');
}

function nodeMsgEndpointValueFromOptions(
    opts: NodeNewOptions,
    label: string,
    capturedEndpoint?: string,
): string {
    const endpoint = nonEmpty(opts.nodeMsgEndpoint) ?? capturedEndpoint;
    if (!endpoint) {
        throw new Error(`Could not determine ${label}. Pass --node-msg-endpoint or run with --yes so the CLI can discover it.`);
    }
    return endpoint.replace(/\/$/, '');
}

function listenPort(listen: string): string {
    const m = /:(\d+)$/.exec(listen.trim());
    if (!m) throw new Error(`Invalid listen address "${listen}" — expected host:port`);
    return m[1]!;
}

function nodeMsgEndpointDefault(listen: string, host = 'localhost'): string {
    return `http://${host}:${listenPort(listen)}`;
}

function ensureSqliteStoreParent(url: string): void {
    if (!url.startsWith('sqlite://')) return;
    const filePath = url.slice('sqlite://'.length);
    if (!filePath || filePath.startsWith('/ace-vss/')) return;
    mkdirSync(path.dirname(filePath), { recursive: true });
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
        if (n.gce?.port)    used.add(n.gce.port);
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
        identity: { accountAddr: profile.accountAddr, pkeEk: profile.pkeEk!, sigPk: profile.sigPk },
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
    let vssStoreUrl = scheme === 'metadata-management-only'
        ? undefined
        : parsed.vssStoreUrl;
    if (scheme !== 'metadata-management-only' && scheme !== 'gcp-cloudrun-microservices') {
        vssStoreUrl = requireParsedString(parsed.vssStoreUrl, 'VSS store URL');
    }
    const nodeMsgListen = scheme === 'metadata-management-only'
        ? undefined
        : requireParsedString(parsed.nodeMsgListen, 'node message listen address');
    const chainRpc       = parsed.chainRpc ?? {};
    const nodeRpcUrl     = t.blob.nodeRpcUrl;
    const deployRunOpts  = { stdout: options.json ? 'stderr' : 'inherit' } as const;
    const network        = detectAptosNetwork(net.rpcUrl);

    if (nonInteractive && !gasStationKey && (network === 'testnet' || network === 'mainnet' || network === 'shelby-private-beta')) {
        throw new Error(
            'Non-interactive node new requires a gas station key for testnet/mainnet/shelby-private-beta because it generates a fresh account. ' +
            'Pass --gas-station-key or use a deployment profile with gasStationApiKey.',
        );
    }

    let endpoint:  string;
    let nodeMsgEndpoint: string;
    let gcpCfg:    TrackedNode['gcp'];
    let gceCfg:    TrackedNode['gce'];
    let dockerCfg: TrackedNode['docker'];
    let localCfg:  LocalConfig | undefined;

    if (scheme === 'metadata-management-only') {
        console.log('\nMetadata-management-only profile: no deploy command will be emitted.');
        console.log('Use the external deployment system for image/resources/replicas/routing changes.\n');
        endpoint = nonInteractive
            ? metadataEndpointValueFromOptions(options, 'externally managed node', parsed.endpoint)
            : await promptEndpointValue("Your externally managed node's public URL", parsed.endpoint);
        nodeMsgEndpoint = nonInteractive
            ? nodeMsgEndpointValueFromOptions(options, 'externally managed node-message endpoint')
            : await promptEndpointValue('Your externally managed node-message public URL', nonEmpty(options.nodeMsgEndpoint));
    } else if (scheme === 'gcp-vm-monolith') {
        const project = requireParsedString(parsed.project, 'GCP project');
        const zone = requireParsedString(parsed.zone, 'Compute Engine zone');
        const instanceName = requireParsedString(parsed.instanceName, 'Compute Engine instance name');
        const machineType = requireParsedString(parsed.machineType, 'Compute Engine machine type');
        const diskSizeGb = parsed.diskSizeGb ?? 50;
        const networkName = requireParsedString(parsed.network, 'Compute Engine network');
        const port = requireParsedString(parsed.port, 'VM port');
        const containerName = requireParsedString(parsed.containerName, 'Docker container name');
        gceCfg = normalizeGceConfig({
            project,
            zone,
            instanceName,
            machineType,
            diskSizeGb,
            network: networkName,
            port,
            containerName,
        });
        const cmd = gceDeployCmd(gceCfg, image!,
            { ...profile, vssStoreUrl: vssStoreUrl!, nodeMsgListen: nodeMsgListen! },
            net.rpcUrl, net.aceAddr, rpcApiKey, gasStationKey, chainRpc);
        console.log('\nDeploy script:\n');
        console.log(cmd.display);
        console.log();
        const ran = nonInteractive
            ? (options.yes ? runDeployScript(cmd.run, gcloudReady(), cmd.env, deployRunOpts) : false)
            : await maybeAutoRun(cmd.run, gcloudReady(), 'Run this script now?', cmd.env, { yes: options.yes });
        const ip = ran ? captureGceExternalIp(instanceName, project, zone) : undefined;
        const defaultEndpoint = ip ? `http://${ip}:${port}` : undefined;
        endpoint = nonInteractive
            ? await endpointFromOptions(options, 'GCE VM node', defaultEndpoint, ran ? 10 * 60_000 : 0)
            : await promptEndpoint('GCE VM node URL', defaultEndpoint);
        nodeMsgEndpoint = nonInteractive
            ? nodeMsgEndpointValueFromOptions(options, 'GCE VM node-message endpoint', nonEmpty(options.endpoint) ?? defaultEndpoint)
            : await promptEndpointValue('GCE VM node-message URL', nonEmpty(options.nodeMsgEndpoint) ?? defaultEndpoint);
    } else if (scheme === 'gcp-cloudrun-monolith') {
        const project = requireParsedString(parsed.project, 'GCP project');
        const region = requireParsedString(parsed.region, 'Cloud Run region');
        const serviceName = requireParsedString(parsed.serviceName, 'Cloud Run service name');
        gcpCfg = { project, region, serviceName };
        const cmd = gcpDeployCmd(serviceName, image!, project, region,
            { ...profile, vssStoreUrl: vssStoreUrl!, nodeMsgListen: nodeMsgListen! },
            net.rpcUrl, net.aceAddr, rpcApiKey, gasStationKey, chainRpc);
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
        nodeMsgEndpoint = nonInteractive
            ? nodeMsgEndpointValueFromOptions(options, 'Cloud Run node-message service', defaultEndpoint)
            : await promptEndpointValue('Cloud Run node-message service URL', nonEmpty(options.nodeMsgEndpoint) ?? defaultEndpoint);
    } else if (scheme === 'gcp-cloudrun-microservices') {
        const project = requireParsedString(parsed.project, 'GCP project');
        const region = requireParsedString(parsed.region, 'Cloud Run region');
        const maintainerServiceName = requireParsedString(parsed.maintainerServiceName, 'Maintainer service name');
        const handlerServiceName = requireParsedString(parsed.handlerServiceName, 'Handler service name');
        const handlerMaxInstances = parsed.handlerMaxInstances ?? 10;
        const vpcNetwork = requireParsedString(parsed.vpcNetwork, 'Cloud Run VPC network');
        const vpcSubnet = requireParsedString(parsed.vpcSubnet, 'Cloud Run VPC subnet');
        const cloudSqlInstanceName = requireParsedString(parsed.cloudSqlInstanceName, 'Cloud SQL instance name');
        const cloudSqlDatabase = requireParsedString(parsed.cloudSqlDatabase, 'Cloud SQL database');
        const cloudSqlUser = requireParsedString(parsed.cloudSqlUser, 'Cloud SQL user');
        const cloudSqlPrivateRangeName = requireParsedString(parsed.cloudSqlPrivateRangeName, 'Cloud SQL private range name');
        const cloudSqlPassword = vssStoreUrl ? undefined : generatedCloudSqlPassword();
        const cloudSqlProfile: GcpCloudSqlConfig | undefined = vssStoreUrl
            ? undefined
            : {
                instanceName: cloudSqlInstanceName,
                databaseName: cloudSqlDatabase,
                user: cloudSqlUser,
                privateRangeName: cloudSqlPrivateRangeName,
            };
        const scriptVssStoreUrl = vssStoreUrl ?? cloudSqlVssStoreUrl(
            { databaseName: cloudSqlDatabase, user: cloudSqlUser },
            '<cloud-sql-private-ip>',
            cloudSqlPassword!,
        );
        gcpCfg = {
            project,
            region,
            maintainerServiceName,
            handlerServiceName,
            handlerMaxInstances,
            vpcNetwork,
            vpcSubnet,
            cloudSql: cloudSqlProfile,
        };
        const cmd = gcpDeployCmdMicroservices(
            {
                project,
                region,
                maintainerServiceName,
                handlerServiceName,
                handlerMaxInstances,
                vpcNetwork,
                vpcSubnet,
                cloudSql: cloudSqlPassword ? {
                    instanceName: cloudSqlInstanceName,
                    databaseName: cloudSqlDatabase,
                    user: cloudSqlUser,
                    privateRangeName: cloudSqlPrivateRangeName,
                    password: cloudSqlPassword,
                } : undefined,
            },
            image!, { ...profile, vssStoreUrl: scriptVssStoreUrl, nodeMsgListen: nodeMsgListen! },
            net.rpcUrl, net.aceAddr, rpcApiKey, gasStationKey, chainRpc,
        );
        console.log('\nDeploy script:\n');
        console.log(cmd.display);
        console.log();
        const ran = nonInteractive
            ? (options.yes ? runDeployScript(cmd.run, gcloudReady(), cmd.env, deployRunOpts) : false)
            : await maybeAutoRun(cmd.run, gcloudReady(), 'Run this script now?', cmd.env, { yes: options.yes });
        if (!vssStoreUrl && !ran) {
            throw new Error(
                'The generated deploy script did not complete. CLI-managed Cloud SQL needs the script to finish so the DB password and private IP can be captured. ' +
                'Fix the gcloud error above and re-run node new, or set vssStoreUrl to an existing Postgres store.',
            );
        }
        const defaultEndpoint = ran ? captureCloudRunUrl(handlerServiceName, project, region) : undefined;
        const defaultNodeMsgEndpoint = ran ? captureCloudRunUrl(maintainerServiceName, project, region) : undefined;
        endpoint = nonInteractive
            ? await endpointFromOptions(options, 'Handler service', defaultEndpoint)
            : await promptEndpoint('Handler service URL', defaultEndpoint);
        nodeMsgEndpoint = nonInteractive
            ? nodeMsgEndpointValueFromOptions(options, 'Maintainer node-message service', defaultNodeMsgEndpoint)
            : await promptEndpointValue('Maintainer node-message service URL', nonEmpty(options.nodeMsgEndpoint) ?? defaultNodeMsgEndpoint);
        if (!vssStoreUrl) {
            const privateIp = captureCloudSqlPrivateIp(cloudSqlInstanceName, project);
            vssStoreUrl = cloudSqlVssStoreUrl(
                { databaseName: cloudSqlDatabase, user: cloudSqlUser },
                privateIp ?? '<cloud-sql-private-ip>',
                cloudSqlPassword!,
            );
        }
    } else if (scheme === 'docker-monolith') {
        dockerCfg = { containerName: parsed.containerName!, port: parsed.port! };
        const cmd = dockerRunCmd(parsed.containerName!, image!, parsed.port!,
            { ...profile, vssStoreUrl: vssStoreUrl!, nodeMsgListen: nodeMsgListen! },
            nodeRpcUrl!, net.aceAddr, rpcApiKey, gasStationKey, chainRpc);
        console.log('\nStart command:\n');
        console.log(cmd);
        console.log();
        await maybeAutoRun(cmd, dockerReady(), 'Run this now?', undefined, { yes: options.yes });
        const defaultEndpoint = isLocalnet ? `http://localhost:${parsed.port}` : undefined;
        endpoint = await promptEndpoint("Your node's public URL", defaultEndpoint);
        nodeMsgEndpoint = await promptEndpointValue("Your node-message public URL", nonEmpty(options.nodeMsgEndpoint) ?? nodeMsgEndpointDefault(nodeMsgListen!));
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
        ensureSqliteStoreParent(vssStoreUrl!);
        const runArgs = localRunArgs(
            port,
            { ...profile, vssStoreUrl: vssStoreUrl!, nodeMsgListen: nodeMsgListen! },
            net.rpcUrl,
            net.aceAddr,
            rpcApiKey,
            gasStationKey,
            chainRpc,
        );
        const pid = spawnLocalNode(binaryPath, runArgs, logFile);
        console.log(`\nNode started in background  pid=${pid}  log=${logFile}\n`);

        const logrotateConf = writeLogrotateConf(logFile, logMaxMb);
        runLogrotate(logrotateConf);

        localCfg = { repoPath, port, pid, logFile, logMaxMb };
        endpoint = await promptEndpoint("Your node's public URL", `http://localhost:${port}`);
        nodeMsgEndpoint = await promptEndpointValue("Your node-message public URL", nonEmpty(options.nodeMsgEndpoint) ?? nodeMsgEndpointDefault(nodeMsgListen!));
    }

    await ensureAccountFunded(net.rpcUrl, profile.accountAddr, rpcApiKey, gasStationKey);

    console.log('\nRegistering on-chain...\n');
    await registerOnChain(
        { ...profile, rpcUrl: net.rpcUrl, aceAddr: net.aceAddr, rpcApiKey, gasStationKey },
        endpoint,
        nodeMsgEndpoint,
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
        sigSk:       profile.sigSk,
        sigPk:       profile.sigPk,
        alias:       parsed.alias,
        endpoint,
        nodeMsgEndpoint,
        vssStoreUrl,
        nodeMsgListen,
        image,
        platform,
        mode,
        gcp:          gcpCfg,
        gce:          gceCfg,
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

function detectAptosNetwork(rpcUrl: string): 'localnet' | 'devnet' | 'testnet' | 'mainnet' | 'shelby-private-beta' | 'other' {
    if (/localhost|127\.0\.0\.1/.test(rpcUrl)) return 'localnet';
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

    if (network !== 'testnet' && network !== 'mainnet' && network !== 'shelby-private-beta') return;

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
