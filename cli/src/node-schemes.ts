// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Node deployment schemes — Phase 1/Phase 2 scaffolding for `ace node new`
 * and `ace node edit`.
 *
 * A "scheme" is the (platform, mode) tuple that drives both the wizard's
 * inline scheme picker and the text-form template the user edits. Six are
 * supported today:
 *
 *   * `gcp-vm-monolith`               — platform=gcp-vm, mode=monolith
 *   * `gcp-cloudrun-monolith`         — platform=gcp,    mode=monolith (legacy)
 *   * `gcp-cloudrun-microservices`    — platform=gcp,    mode=microservices
 *   * `docker-monolith`               — platform=docker, mode=monolith
 *   * `local-build-monolith`          — platform=local,  mode=monolith
 *   * `metadata-management-only`       — platform unset, mode=metadata-management-only
 *
 * The GCP options are unavailable when the ACE deployment is on localnet
 * (managed GCP runtimes can't reach a localhost chain endpoint).
 *
 * The template generators in this module produce the TOML text shown to the
 * user; the parser validates the saved file back into a structured form that
 * `node new` / `node edit` consume.
 */

import { parse as parseToml } from 'smol-toml';
import { homedir } from 'os';
import * as path from 'path';
import { escSelect } from './esc-select.js';
import { CLI } from './cli-name.js';
import type { Mode, Platform, GcpConfig, GceConfig, DockerConfig, LocalConfig, ChainRpcOverrides, TrackedNode } from './config.js';

export type Scheme =
    | 'gcp-vm-monolith'
    | 'gcp-cloudrun-monolith'
    | 'gcp-cloudrun-microservices'
    | 'docker-monolith'
    | 'local-build-monolith'
    | 'metadata-management-only';

export function schemeOf(node: Pick<TrackedNode, 'platform' | 'mode'>): Scheme {
    const platform = node.platform ?? 'docker';
    const mode = node.mode ?? 'monolith';
    if (mode === 'metadata-management-only')            return 'metadata-management-only';
    if (platform === 'gcp-vm')                           return 'gcp-vm-monolith';
    if (platform === 'gcp' && mode === 'microservices') return 'gcp-cloudrun-microservices';
    if (platform === 'gcp')                              return 'gcp-cloudrun-monolith';
    if (platform === 'docker')                           return 'docker-monolith';
    return 'local-build-monolith';
}

export function platformOf(scheme: Scheme): Platform | undefined {
    if (scheme === 'metadata-management-only') return undefined;
    if (scheme === 'gcp-vm-monolith') return 'gcp-vm';
    if (scheme.startsWith('gcp-'))    return 'gcp';
    if (scheme.startsWith('docker-')) return 'docker';
    return 'local';
}

export function modeOf(scheme: Scheme): Mode {
    if (scheme === 'metadata-management-only') return 'metadata-management-only';
    return scheme === 'gcp-cloudrun-microservices' ? 'microservices' : 'monolith';
}

// ── Phase 1: scheme picker ───────────────────────────────────────────────────

export async function pickScheme(opts: { isLocalnet: boolean }): Promise<Scheme | null> {
    const choices: { name: string; value: Scheme; disabled?: string }[] = [
        {
            name: 'GCP VM, monolith                — single VM + Docker + persistent sqlite DB',
            value: 'gcp-vm-monolith',
            disabled: opts.isLocalnet ? '(unavailable: deployment is localnet)' : undefined,
        },
        {
            name: 'GCP Cloud Run, microservices    — Maintainer singleton + scaling Handler + Cloud SQL VSS DB',
            value: 'gcp-cloudrun-microservices',
            disabled: opts.isLocalnet ? '(unavailable: deployment is localnet)' : undefined,
        },
        {
            name: 'Local Docker container, monolith',
            value: 'docker-monolith',
        },
        {
            name: 'Local build (from source), monolith',
            value: 'local-build-monolith',
        },
        {
            name: 'Metadata management only — external runtime; CLI manages credentials/on-chain metadata',
            value: 'metadata-management-only',
        },
    ];
    const picked = await escSelect({
        message: 'Deployment scheme',
        choices,
    });
    return picked as Scheme | null;
}

// ── Phase 2: form generation ─────────────────────────────────────────────────

/** Inputs shared by all template generators. */
export interface TemplateInputs {
    /** This node's identity (auto-generated). Shown read-only in the form. */
    identity: {
        accountAddr: string;
        pkeEk:       string;
        sigPk:       string;
    };
    /** Deployment blob values, used for the read-only block + key pre-fill. */
    blob: {
        rpcUrl:         string;
        aceAddr:        string;
        rpcApiKey?:     string;
        gasStationKey?: string;
        /** Docker-only: rpcUrl rewritten for the container's view of the host. */
        nodeRpcUrl?:    string;
    };
    /** Auto-suggested defaults for the scheme-specific block. */
    defaults: SchemeDefaults;
    /** Pre-filled editable values when seeding from an existing node (edit path). */
    existing?: ExistingValues;
}

export interface SchemeDefaults {
    image?:                  string;
    project?:                string;
    region?:                 string;
    serviceName?:            string;
    maintainerServiceName?:  string;
    handlerServiceName?:     string;
    handlerMaxInstances?:    number;
    vpcNetwork?:             string;
    vpcSubnet?:              string;
    cloudSqlInstanceName?:   string;
    cloudSqlDatabase?:       string;
    cloudSqlUser?:           string;
    cloudSqlPrivateRangeName?: string;
    zone?:                   string;
    instanceName?:           string;
    machineType?:            string;
    diskSizeGb?:             number;
    network?:                string;
    port?:                   string;
    containerName?:          string;
    repoPath?:               string;
    logMaxMb?:               number;
    endpoint?:               string;
    vssStoreUrl?:            string;
    nodeMsgListen?:          string;
}

export interface ExistingValues {
    alias?:                  string;
    image?:                  string;
    rpcApiKey?:              string;
    gasStationKey?:          string;
    chainRpc?:               ChainRpcOverrides;
    project?:                string;
    region?:                 string;
    serviceName?:            string;
    maintainerServiceName?:  string;
    handlerServiceName?:     string;
    handlerMaxInstances?:    number;
    vpcNetwork?:             string;
    vpcSubnet?:              string;
    cloudSqlInstanceName?:   string;
    cloudSqlDatabase?:       string;
    cloudSqlUser?:           string;
    cloudSqlPrivateRangeName?: string;
    zone?:                   string;
    instanceName?:           string;
    machineType?:            string;
    diskSizeGb?:             number;
    network?:                string;
    port?:                   string;
    containerName?:          string;
    repoPath?:               string;
    logMaxMb?:               number;
    endpoint?:               string;
    vssStoreUrl?:            string;
    nodeMsgListen?:          string;
}

const CHAIN_RPC_PLACEHOLDERS: Record<keyof ChainRpcOverrides, string> = {
    aptosMainnetApi:      'https://api.mainnet.aptoslabs.com/v1',
    aptosMainnetApikey:   'AG-yourkey...',
    aptosTestnetApi:      'https://api.testnet.aptoslabs.com/v1',
    aptosTestnetApikey:   'AG-yourkey...',
    aptosLocalnetApi:     'http://127.0.0.1:8080/v1',
    aptosLocalnetApikey:  'AG-yourkey...',
    aptosShelbyPrivateBetaApi:    'https://<your-shelby-private-beta-fullnode>/v1',
    aptosShelbyPrivateBetaApikey: 'AG-yourkey...',
};

const CHAIN_RPC_KEYS = Object.keys(CHAIN_RPC_PLACEHOLDERS) as (keyof ChainRpcOverrides)[];
const COMMENT_WIDTH = 88;

function commentBlock(comments: string | string[]): string {
    const lines = Array.isArray(comments) ? comments : [comments];
    return lines.flatMap(wrapComment).join('\n');
}

function wrapComment(text: string): string[] {
    if (text === '') return ['#'];

    const words = text.split(/\s+/);
    const lines: string[] = [];
    let line = '#';

    for (const word of words) {
        const next = line === '#' ? `# ${word}` : `${line} ${word}`;
        if (next.length <= COMMENT_WIDTH || line === '#') {
            line = next;
            continue;
        }
        lines.push(line);
        line = `# ${word}`;
    }
    lines.push(line);
    return lines;
}

function renderChainRpcBlock(existing?: ChainRpcOverrides, applicabilityNote = ''): string {
    const lines = [
        commentBlock([
            'Per-chain RPC overrides.',
            'Commented out by default; uncomment to override worker defaults.',
            ...(applicabilityNote ? [applicabilityNote] : []),
            'Aptos API keys: https://developers.aptoslabs.com/.',
        ]),
        '[chainRpc]',
    ];
    for (const k of CHAIN_RPC_KEYS) {
        const set = existing?.[k];
        const placeholder = CHAIN_RPC_PLACEHOLDERS[k];
        if (set !== undefined && set !== '') {
            lines.push(`${k.padEnd(20)} = "${set}"`);
        } else {
            lines.push(`# ${k.padEnd(20)} = "${placeholder}"`);
        }
    }
    return lines.join('\n');
}

/** Render a possibly-null editable line: uncommented when a value exists,
 *  commented out (with the placeholder as a hint) otherwise. */
function nullableLine(
    key: string,
    value: string | undefined,
    placeholder: string,
    comments: string | string[],
): string {
    const head = `${key.padEnd(20)}`;
    const field = `${head} = "${value ?? placeholder}"`;
    const prefix = value !== undefined && value !== '' ? '' : '# ';
    return `${commentBlock(comments)}\n${prefix}${field}`;
}

function stringLine(key: string, value: string, comments: string | string[]): string {
    return `${commentBlock(comments)}\n${key.padEnd(20)} = "${value}"`;
}

function numberLine(key: string, value: number, comments: string | string[]): string {
    return `${commentBlock(comments)}\n${key.padEnd(20)} = ${value}`;
}

function commentedStringLine(key: string, value: string, comments: string | string[]): string {
    return `${commentBlock(comments)}\n# ${key.padEnd(20)} = "${value}"`;
}

const HEADER_READONLY_NOTE = `#   * Required fields are uncommented; edit to taste.
#   * Optional fields are commented out — uncomment + set a literal value.
#     A commented-out optional field means "unset" (use the default).
#   * Identity / from-blob fields are shown commented for reference only;
#     uncommenting any of them will be rejected when you save.`;

function readonlyIdentityBlock(t: TemplateInputs): string {
    return [
        `# ── Read-only identity / deployment binding (do NOT uncomment) ────────────────`,
        `#  accountAddr     = "${t.identity.accountAddr}"`,
        `#  pkeEk           = "${t.identity.pkeEk}"`,
        `#  sigPk           = "${t.identity.sigPk}"`,
        `#  aceAddr         = "${t.blob.aceAddr}"`,
        ...(t.blob.nodeRpcUrl ? ['#  rpcUrl is the admin-facing RPC URL.'] : []),
        `#  rpcUrl          = "${t.blob.rpcUrl}"`,
        ...(t.blob.nodeRpcUrl ? [
            '#  nodeRpcUrl is the container-facing RPC URL.',
            `#  nodeRpcUrl      = "${t.blob.nodeRpcUrl}"`,
        ] : []),
    ].join('\n');
}

function aliasLine(existing?: string): string {
    return nullableLine(
        'alias', existing, 'my-testnet-node',
        [
            'Optional display name for this node profile.',
            `Shown by \`${CLI} node ls\` and status commands.`,
        ],
    );
}

function keyLines(t: TemplateInputs): string {
    const apiKey = t.existing?.rpcApiKey ?? t.blob.rpcApiKey;
    const gasKey = t.existing?.gasStationKey ?? t.blob.gasStationKey;
    return [
        nullableLine(
            'rpcApiKey', apiKey, 'AG-yourkey...',
            [
                'Deployment API key passed as --ace-deployment-apikey.',
                'Pre-filled from the deployment blob when present.',
                'Comment out to use anonymous RPC, subject to public IP rate limits.',
            ],
        ),
        nullableLine(
            'gasStationKey', gasKey, 'gsk-yourkey...',
            [
                'Gas station key passed as --ace-deployment-gaskey.',
                'Pre-filled from the deployment blob when present.',
                'Comment out if you have no gas station.',
            ],
        ),
    ].join('\n');
}

function runtimeLines(t: TemplateInputs, nodeMsgComment: string): string {
    const e = t.existing ?? {};
    const d = t.defaults;
    return [
        `vssStoreUrl      = "${e.vssStoreUrl ?? d.vssStoreUrl ?? ''}"          # → --vss-store-url. Persistent VSS DB; sqlite://... for local, postgres://... for shared DB`,
        `nodeMsgListen    = "${e.nodeMsgListen ?? d.nodeMsgListen ?? ''}"      # endpoint-default metadata; network-node listens on --port. ${nodeMsgComment}`,
    ].join('\n');
}

function cloudRunMicroservicesRuntimeLines(t: TemplateInputs): string {
    const e = t.existing ?? {};
    const d = t.defaults;
    return [
        nullableLine(
            'vssStoreUrl',
            e.vssStoreUrl,
            'postgres://ace:<generated-password>@<cloud-sql-private-ip>:5432/ace_vss',
            [
                'Optional override for the shared VSS DB.',
                'Leave commented to let the CLI create/reuse Cloud SQL Postgres and fill this automatically.',
            ],
        ),
        `nodeMsgListen    = "${e.nodeMsgListen ?? d.nodeMsgListen ?? ''}"      # endpoint-default metadata; network-node listens on --port. Maintainer service listener for node-to-node VSS messages. Default Cloud Run ingress port is 8080.`,
    ].join('\n');
}

// ── Per-scheme templates ─────────────────────────────────────────────────────

export function generateTemplate(scheme: Scheme, t: TemplateInputs): string {
    switch (scheme) {
        case 'gcp-vm-monolith':        return generateGcpVmMonolith(t);
        case 'gcp-cloudrun-monolith':      return generateGcpMonolith(t);
        case 'gcp-cloudrun-microservices': return generateGcpMicroservices(t);
        case 'docker-monolith':            return generateDockerMonolith(t);
        case 'local-build-monolith':       return generateLocalBuildMonolith(t);
        case 'metadata-management-only':    return generateMetadataManagementOnly(t);
    }
}

function generateGcpVmMonolith(t: TemplateInputs): string {
    const e = t.existing ?? {};
    const d = t.defaults;
    return `# ${CLI} node — scheme: gcp-vm-monolith
#
# Runs one ACE worker as a Docker container on a GCP Compute Engine VM.
# The VM keeps VSS state in sqlite on a persistent disk mounted at /ace-vss.
# Saving emits a gcloud compute provisioning script.
#
# Edit the values below, then save and quit your editor.
${HEADER_READONLY_NOTE}
#
${readonlyIdentityBlock(t)}
#
# ── Editable fields ───────────────────────────────────────────────────────────

${aliasLine(e.alias)}
${stringLine('image', e.image ?? d.image ?? 'aptoslabs/ace-node:latest', `Docker image. List options with \`${CLI} image ls\`.`)}
${stringLine('project', e.project ?? d.project ?? '', [
    'GCP project ID.',
    'Default comes from `gcloud config get-value project`.',
    'List projects with `gcloud projects list`.',
])}
${stringLine('zone', e.zone ?? d.zone ?? 'us-central1-a', `Compute Engine zone. List zones with \`gcloud compute zones list\`.`)}
${stringLine('instanceName', e.instanceName ?? d.instanceName ?? '', [
    'Compute Engine VM name.',
    'Use lowercase letters, digits, and hyphens.',
    'Must start with a letter and be under 64 characters.',
])}
${stringLine('machineType', e.machineType ?? d.machineType ?? 'e2-standard-2', [
    'Compute Engine machine type.',
    'Use a small always-on shape for monolith; increase for heavier traffic.',
])}
${numberLine('diskSizeGb', e.diskSizeGb ?? d.diskSizeGb ?? 50, [
    'Persistent disk size for /ace-vss in GB.',
    'The generated script creates/reuses a non-auto-delete disk.',
])}
${stringLine('network', e.network ?? d.network ?? 'default', 'VPC network name for the VM and firewall rule.')}
${stringLine('port', e.port ?? d.port ?? '19000', 'TCP port exposed by the VM and Docker container.')}
${stringLine('containerName', e.containerName ?? d.containerName ?? 'ace-node', [
    '`docker run --name` value on the VM.',
    'Usually only needs to be unique on that VM.',
])}
${keyLines(t)}
${runtimeLines(t, 'VM monolith uses this same public port for worker and node-message requests.')}

${renderChainRpcBlock(e.chainRpc)}
`;
}

function generateGcpMonolith(t: TemplateInputs): string {
    const e = t.existing ?? {};
    const d = t.defaults;
    return `# ${CLI} node — scheme: gcp-cloudrun-monolith
#
# Edit the values below, then save and quit your editor.
#
${HEADER_READONLY_NOTE}
#
${readonlyIdentityBlock(t)}
#
# ── Editable fields ───────────────────────────────────────────────────────────

${aliasLine(e.alias)}
${stringLine('image', e.image ?? d.image ?? 'aptoslabs/ace-node:latest', `Docker image. List options with \`${CLI} image ls\`.`)}
${stringLine('project', e.project ?? d.project ?? '', [
    'GCP project ID.',
    'Default comes from `gcloud config get-value project`.',
    'List projects with `gcloud projects list`.',
])}
${stringLine('region', e.region ?? d.region ?? 'us-central1', `Cloud Run region. List regions with \`gcloud run regions list\`.`)}
${stringLine('serviceName', e.serviceName ?? d.serviceName ?? '', [
    'Cloud Run service name.',
    'Use lowercase letters, digits, and hyphens.',
    'Must start with a letter and be under 64 characters.',
])}
${keyLines(t)}
${runtimeLines(t, 'Cloud Run monolith currently needs a second listener for node-to-node VSS messages; prefer microservices if deploying on Cloud Run.')}

${renderChainRpcBlock(e.chainRpc)}
`;
}

function generateGcpMicroservices(t: TemplateInputs): string {
    const e = t.existing ?? {};
    const d = t.defaults;
    return `# ${CLI} node — scheme: gcp-cloudrun-microservices
#
# Deploys a Maintainer + Handler pair. The Maintainer is pinned at min=max=1
# (it owns the on-chain DKG/DKR coordination and node-message endpoint, which
# has to be a singleton). The Handler is public and scales 1..handlerMaxInstances.
# Saving emits a provisioning script for Cloud SQL + Cloud Run.
#
# Edit the values below, then save and quit your editor.
${HEADER_READONLY_NOTE}
#
${readonlyIdentityBlock(t)}
#
# ── Editable fields ───────────────────────────────────────────────────────────

${aliasLine(e.alias)}
${stringLine('image', e.image ?? d.image ?? 'aptoslabs/ace-node:latest', `Docker image. List options with \`${CLI} image ls\`.`)}
${stringLine('project', e.project ?? d.project ?? '', [
    'GCP project ID.',
    'Default comes from `gcloud config get-value project`.',
    'List projects with `gcloud projects list`.',
])}
${stringLine('region', e.region ?? d.region ?? 'us-central1', `Cloud Run region. List regions with \`gcloud run regions list\`.`)}
${stringLine('maintainerServiceName', e.maintainerServiceName ?? d.maintainerServiceName ?? '', [
    'Cloud Run service pinned at min=max=1; this is the registered node-message endpoint.',
    'Use lowercase letters, digits, and hyphens.',
    'Must start with a letter and be under 64 characters.',
])}
${stringLine('handlerServiceName', e.handlerServiceName ?? d.handlerServiceName ?? '', [
    'Public Cloud Run service that scales horizontally.',
    'Use the same naming rules as maintainerServiceName.',
])}
${numberLine('handlerMaxInstances', e.handlerMaxInstances ?? d.handlerMaxInstances ?? 10, [
    'Cloud Run autoscaling cap on the Handler.',
    'Higher means more throughput and more cost.',
    'Set to 1 to effectively disable scaling.',
])}
${stringLine('vpcNetwork', e.vpcNetwork ?? d.vpcNetwork ?? 'default', [
    'VPC network for Cloud Run Direct VPC egress and Cloud SQL private IP.',
    'The generated script creates/reuses private service access on this network.',
])}
${stringLine('vpcSubnet', e.vpcSubnet ?? d.vpcSubnet ?? 'default', [
    'VPC subnet for Cloud Run Direct VPC egress.',
    'Must belong to vpcNetwork in the selected region.',
])}
${stringLine('cloudSqlInstanceName', e.cloudSqlInstanceName ?? d.cloudSqlInstanceName ?? '', [
    'Cloud SQL Postgres instance for the shared VSS DB.',
    'The generated script creates it if missing and reuses it otherwise.',
])}
${stringLine('cloudSqlDatabase', e.cloudSqlDatabase ?? d.cloudSqlDatabase ?? 'ace_vss', 'Postgres database name for VSS state.')}
${stringLine('cloudSqlUser', e.cloudSqlUser ?? d.cloudSqlUser ?? 'ace', 'Postgres user for the ACE worker services.')}
${stringLine('cloudSqlPrivateRangeName', e.cloudSqlPrivateRangeName ?? d.cloudSqlPrivateRangeName ?? '', [
    'Reserved VPC peering range used for Cloud SQL private IP.',
    'Only created if no private service access connection already exists.',
])}
${keyLines(t)}
${cloudRunMicroservicesRuntimeLines(t)}

${renderChainRpcBlock(e.chainRpc, 'Applies to the Handler (the Maintainer doesn\'t make per-request chain calls).')}
`;
}

function generateDockerMonolith(t: TemplateInputs): string {
    const e = t.existing ?? {};
    const d = t.defaults;
    return `# ${CLI} node — scheme: docker-monolith
#
# Runs one ACE worker as a Docker container on this machine. Saving emits the
# \`docker run\` command for you to execute.
#
# Edit the values below, then save and quit your editor.
${HEADER_READONLY_NOTE}
#
${readonlyIdentityBlock(t)}
#
# ── Editable fields ───────────────────────────────────────────────────────────

${aliasLine(e.alias)}
${stringLine('image', e.image ?? d.image ?? 'aptoslabs/ace-node:latest', `Docker image. List options with \`${CLI} image ls\`.`)}
${stringLine('port', e.port ?? d.port ?? '19000', 'TCP port the worker listens on. Default: lowest unused port starting at 19000.')}
${stringLine('containerName', e.containerName ?? d.containerName ?? '', [
    '`docker run --name` value.',
    'Must be unique on this host.',
    "List existing containers with `docker ps -a --format '{{.Names}}'`.",
])}
${keyLines(t)}
${runtimeLines(t, 'Container listen address for node-to-node VSS messages; the generated docker command publishes this port too.')}

${renderChainRpcBlock(e.chainRpc)}
`;
}

function generateLocalBuildMonolith(t: TemplateInputs): string {
    const e = t.existing ?? {};
    const d = t.defaults;
    return `# ${CLI} node — scheme: local-build-monolith
#
# Builds and runs the network-node binary directly from a checked-out repo.
# Saving runs \`cargo build --release\` then starts the binary in the background
# with a logrotate config installed.
#
# Edit the values below, then save and quit your editor.
${HEADER_READONLY_NOTE}
#
${readonlyIdentityBlock(t)}
#
# ── Editable fields ───────────────────────────────────────────────────────────

${aliasLine(e.alias)}
${commentedStringLine('image', '(ignored)', 'Local builds use the binary at `<repoPath>/target/release/network-node`.')}
${stringLine('repoPath', e.repoPath ?? d.repoPath ?? '', 'Path to a checked-out ACE repo.')}
${stringLine('port', e.port ?? d.port ?? '19000', 'TCP port the worker listens on. Default: lowest unused port starting at 19000.')}
${numberLine('logMaxMb', e.logMaxMb ?? d.logMaxMb ?? 50, 'Logrotate threshold in MB. Rotates when the log exceeds this size.')}
${keyLines(t)}
${runtimeLines(t, 'Local listen address for node-to-node VSS messages.')}

${renderChainRpcBlock(e.chainRpc)}
`;
}

function generateMetadataManagementOnly(t: TemplateInputs): string {
    const e = t.existing ?? {};
    return `# ${CLI} node — scheme: metadata-management-only
#
# Use this for externally managed workers. The CLI stores credentials and
# on-chain metadata only. It will not emit gcloud/docker commands, start a local
# process, or change worker image versions. Runtime deployment changes still
# belong to the deployment system that runs the worker.
#
# Edit the values below, then save and quit your editor.
${HEADER_READONLY_NOTE}
#
${readonlyIdentityBlock(t)}
#
# ── Editable fields ───────────────────────────────────────────────────────────

${aliasLine(e.alias)}
${stringLine('endpoint', e.endpoint ?? '', 'Public endpoint registered on-chain for this node.')}
${keyLines(t)}

${renderChainRpcBlock(e.chainRpc, 'Your deployment system must apply these values to the runtime.')}
`;
}

// ── Phase 3: parser ──────────────────────────────────────────────────────────

export interface ParsedNodeForm {
    alias?:                  string;
    image?:                  string;
    rpcApiKey?:              string;
    gasStationKey?:          string;
    chainRpc?:               ChainRpcOverrides;
    project?:                string;
    region?:                 string;
    serviceName?:            string;
    maintainerServiceName?:  string;
    handlerServiceName?:     string;
    handlerMaxInstances?:    number;
    vpcNetwork?:             string;
    vpcSubnet?:              string;
    cloudSqlInstanceName?:   string;
    cloudSqlDatabase?:       string;
    cloudSqlUser?:           string;
    cloudSqlPrivateRangeName?: string;
    zone?:                   string;
    instanceName?:           string;
    machineType?:            string;
    diskSizeGb?:             number;
    network?:                string;
    port?:                   string;
    containerName?:          string;
    repoPath?:               string;
    logMaxMb?:               number;
    endpoint?:               string;
    vssStoreUrl?:            string;
    nodeMsgListen?:          string;
}

const FORBIDDEN_TOP = new Set([
    'accountAddr', 'pkeEk', 'pkeDk', 'sigPk', 'sigSk', 'accountSk', 'aceAddr', 'rpcUrl', 'nodeRpcUrl',
    'platform', 'mode', 'gcp', 'gce', 'docker', 'local',
]);

interface SchemaField {
    required: boolean;
    type: 'string' | 'number';
}

const SCHEMA: Record<Scheme, Record<string, SchemaField>> = {
    'gcp-vm-monolith': {
        alias:         { required: false, type: 'string' },
        image:         { required: true,  type: 'string' },
        project:       { required: true,  type: 'string' },
        zone:          { required: true,  type: 'string' },
        instanceName:  { required: true,  type: 'string' },
        machineType:   { required: true,  type: 'string' },
        diskSizeGb:    { required: true,  type: 'number' },
        network:       { required: true,  type: 'string' },
        port:          { required: true,  type: 'string' },
        containerName: { required: true,  type: 'string' },
        rpcApiKey:     { required: false, type: 'string' },
        gasStationKey: { required: false, type: 'string' },
        vssStoreUrl:   { required: true,  type: 'string' },
        nodeMsgListen: { required: true,  type: 'string' },
    },
    'gcp-cloudrun-monolith': {
        alias:         { required: false, type: 'string' },
        image:         { required: true,  type: 'string' },
        project:       { required: true,  type: 'string' },
        region:        { required: true,  type: 'string' },
        serviceName:   { required: true,  type: 'string' },
        rpcApiKey:     { required: false, type: 'string' },
        gasStationKey: { required: false, type: 'string' },
        vssStoreUrl:   { required: true,  type: 'string' },
        nodeMsgListen: { required: true,  type: 'string' },
    },
    'gcp-cloudrun-microservices': {
        alias:                 { required: false, type: 'string' },
        image:                 { required: true,  type: 'string' },
        project:               { required: true,  type: 'string' },
        region:                { required: true,  type: 'string' },
        maintainerServiceName: { required: true,  type: 'string' },
        handlerServiceName:    { required: true,  type: 'string' },
        handlerMaxInstances:   { required: true,  type: 'number' },
        vpcNetwork:            { required: true,  type: 'string' },
        vpcSubnet:             { required: true,  type: 'string' },
        cloudSqlInstanceName:  { required: true,  type: 'string' },
        cloudSqlDatabase:      { required: true,  type: 'string' },
        cloudSqlUser:          { required: true,  type: 'string' },
        cloudSqlPrivateRangeName: { required: true, type: 'string' },
        rpcApiKey:             { required: false, type: 'string' },
        gasStationKey:         { required: false, type: 'string' },
        vssStoreUrl:           { required: false, type: 'string' },
        nodeMsgListen:         { required: true,  type: 'string' },
    },
    'docker-monolith': {
        alias:         { required: false, type: 'string' },
        image:         { required: true,  type: 'string' },
        port:          { required: true,  type: 'string' },
        containerName: { required: true,  type: 'string' },
        rpcApiKey:     { required: false, type: 'string' },
        gasStationKey: { required: false, type: 'string' },
        vssStoreUrl:   { required: true,  type: 'string' },
        nodeMsgListen: { required: true,  type: 'string' },
    },
    'local-build-monolith': {
        alias:         { required: false, type: 'string' },
        repoPath:      { required: true,  type: 'string' },
        port:          { required: true,  type: 'string' },
        logMaxMb:      { required: true,  type: 'number' },
        rpcApiKey:     { required: false, type: 'string' },
        gasStationKey: { required: false, type: 'string' },
        vssStoreUrl:   { required: true,  type: 'string' },
        nodeMsgListen: { required: true,  type: 'string' },
    },
    'metadata-management-only': {
        alias:         { required: false, type: 'string' },
        endpoint:      { required: true,  type: 'string' },
        rpcApiKey:     { required: false, type: 'string' },
        gasStationKey: { required: false, type: 'string' },
    },
};

export function parseTemplate(scheme: Scheme, content: string): ParsedNodeForm {
    let doc: Record<string, unknown>;
    try {
        doc = parseToml(content) as Record<string, unknown>;
    } catch (e) {
        throw new Error(`TOML parse error: ${(e as Error).message}`);
    }

    for (const k of Object.keys(doc)) {
        if (k === 'chainRpc') continue;
        if (FORBIDDEN_TOP.has(k)) {
            throw new Error(
                `Field "${k}" is read-only — it binds this profile to a specific deployment / platform. ` +
                `Remove (or leave commented) and re-save. To change it, recreate the profile.`,
            );
        }
        if (!(k in SCHEMA[scheme])) {
            const allowed = Object.keys(SCHEMA[scheme]).concat('chainRpc').join(', ');
            throw new Error(`Unknown field "${k}" for scheme ${scheme} — typo? Allowed: ${allowed}.`);
        }
    }

    const out: ParsedNodeForm = {};
    for (const [k, f] of Object.entries(SCHEMA[scheme])) {
        const v = doc[k];
        if (v === undefined) {
            if (f.required) {
                throw new Error(`Required field "${k}" is missing (uncomment it and set a value).`);
            }
            continue;
        }
        if (f.type === 'string') {
            if (typeof v !== 'string') {
                throw new Error(`Field "${k}" must be a TOML string in quotes (got ${typeof v}).`);
            }
            if (v === '') {
                if (f.required) throw new Error(`Required field "${k}" is empty.`);
                continue; // empty optional → treat as unset (same as commented-out)
            }
            (out as Record<string, unknown>)[k] = v;
        } else {
            if (typeof v !== 'number' || !Number.isFinite(v)) {
                throw new Error(`Field "${k}" must be a TOML integer/float (got ${typeof v}).`);
            }
            (out as Record<string, unknown>)[k] = v;
        }
    }

    const rpcDoc = doc.chainRpc as Record<string, unknown> | undefined;
    if (rpcDoc !== undefined) {
        if (typeof rpcDoc !== 'object' || Array.isArray(rpcDoc)) {
            throw new Error(`Field "chainRpc" must be a TOML table (use "[chainRpc]" header).`);
        }
        const chainRpc: ChainRpcOverrides = {};
        for (const k of Object.keys(rpcDoc)) {
            if (!CHAIN_RPC_KEYS.includes(k as keyof ChainRpcOverrides)) {
                throw new Error(`Unknown chainRpc key "${k}" — typo? Allowed: ${CHAIN_RPC_KEYS.join(', ')}.`);
            }
            const v = rpcDoc[k];
            if (typeof v !== 'string') {
                throw new Error(`chainRpc."${k}" must be a TOML string (got ${typeof v}).`);
            }
            if (v === '') continue; // empty = leave unset (same as commented)
            (chainRpc as Record<string, string>)[k] = v;
        }
        if (Object.keys(chainRpc).length > 0) out.chainRpc = chainRpc;
    }
    return out;
}

// ── Auto-derived defaults ────────────────────────────────────────────────────

/** Auto-derive default service / container names from the blob's contract addr
 *  and the node's account addr (mirrors the existing onboarding convention). */
export function defaultNamePrefix(aceAddr: string, accountAddr: string): string {
    const a = aceAddr.replace(/^0x/i, '').slice(0, 6);
    const b = accountAddr.replace(/^0x/i, '').slice(0, 6);
    return `ace-${a}-${b}`;
}

export const SUFFIX_MONOLITH = 'mono';
export const SUFFIX_MAINTAINER = 'ms-secret-maintainer';
export const SUFFIX_HANDLER = 'ms-req-handler';

function localVssStoreUrl(prefix: string): string {
    return `sqlite://${path.join(homedir(), '.ace', 'vss', `${prefix}.db`)}`;
}

/** Apply scheme-specific defaults onto the partial values the caller provides. */
export function defaultsFor(
    scheme: Scheme,
    blob: { aceAddr: string; rpcUrl: string },
    profile: { accountAddr: string },
    fallbackImage: string,
    extras: { defaultGcpProject?: string; defaultRepoPath?: string; defaultPort?: string } = {},
): SchemeDefaults {
    const prefix = defaultNamePrefix(blob.aceAddr, profile.accountAddr);
    switch (scheme) {
        case 'gcp-cloudrun-monolith':
            return {
                image: fallbackImage,
                project: extras.defaultGcpProject,
                region: 'us-central1',
                serviceName: `${prefix}-${SUFFIX_MONOLITH}`,
                vssStoreUrl: '',
                nodeMsgListen: '0.0.0.0:8081',
            };
        case 'gcp-vm-monolith':
            return {
                image: fallbackImage,
                project: extras.defaultGcpProject,
                zone: 'us-central1-a',
                instanceName: `${prefix}-${SUFFIX_MONOLITH}`,
                machineType: 'e2-standard-2',
                diskSizeGb: 50,
                network: 'default',
                port: extras.defaultPort ?? '19000',
                containerName: `${prefix}-${SUFFIX_MONOLITH}`,
                vssStoreUrl: 'sqlite:///ace-vss/vss.db',
                nodeMsgListen: `0.0.0.0:${Number(extras.defaultPort ?? '19000')}`,
            };
        case 'gcp-cloudrun-microservices':
            return {
                image: fallbackImage,
                project: extras.defaultGcpProject,
                region: 'us-central1',
                maintainerServiceName: `${prefix}-${SUFFIX_MAINTAINER}`,
                handlerServiceName:    `${prefix}-${SUFFIX_HANDLER}`,
                handlerMaxInstances:   10,
                vpcNetwork:            'default',
                vpcSubnet:             'default',
                cloudSqlInstanceName:  `${prefix}-vss`,
                cloudSqlDatabase:      'ace_vss',
                cloudSqlUser:          'ace',
                cloudSqlPrivateRangeName: `${prefix}-sql-range`,
                nodeMsgListen: '0.0.0.0:8080',
            };
        case 'docker-monolith':
            return {
                image: fallbackImage,
                port: extras.defaultPort ?? '19000',
                containerName: `${prefix}-${SUFFIX_MONOLITH}`,
                vssStoreUrl: 'sqlite:///ace-vss/vss.db',
                nodeMsgListen: `0.0.0.0:${Number(extras.defaultPort ?? '19000') + 1000}`,
            };
        case 'local-build-monolith':
            return {
                repoPath: extras.defaultRepoPath,
                port: extras.defaultPort ?? '19000',
                logMaxMb: 50,
                vssStoreUrl: localVssStoreUrl(prefix),
                nodeMsgListen: `127.0.0.1:${Number(extras.defaultPort ?? '19000') + 1000}`,
            };
        case 'metadata-management-only':
            return {};
    }
}

// ── Microservices deploy helpers ──────────────────────────────────────────────

/** Best-effort Cloud Run URL shape used as a prompt/default; real deploys still
 * capture the emitted service URL because Cloud Run may use legacy hostnames. */
export function cloudRunUrl(serviceName: string, projectNumber: string, region: string): string {
    return `https://${serviceName}-${projectNumber}.${region}.run.app`;
}

// Re-exports for downstream consumers.
export type { GcpConfig, GceConfig, DockerConfig, LocalConfig, ChainRpcOverrides };
