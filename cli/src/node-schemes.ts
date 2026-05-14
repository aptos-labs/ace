// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Node deployment schemes — Phase 1/Phase 2 scaffolding for `ace node new`
 * and `ace node edit`.
 *
 * A "scheme" is the (platform, mode) tuple that drives both the wizard's
 * inline scheme picker and the text-form template the user edits. Four are
 * supported today:
 *
 *   * `gcp-cloudrun-monolith`         — platform=gcp,    mode=monolith
 *   * `gcp-cloudrun-microservices`    — platform=gcp,    mode=microservices
 *   * `docker-monolith`               — platform=docker, mode=monolith
 *   * `local-build-monolith`          — platform=local,  mode=monolith
 *
 * The two GCP options are unavailable when the ACE deployment is on
 * localnet (Cloud Run can't reach a localhost chain endpoint).
 *
 * The template generators in this module produce the TOML text shown to the
 * user; the parser validates the saved file back into a structured form that
 * `node new` / `node edit` consume.
 */

import { parse as parseToml } from 'smol-toml';
import { escSelect } from './esc-select.js';
import { CLI } from './cli-name.js';
import type { Mode, Platform, GcpConfig, DockerConfig, LocalConfig, ChainRpcOverrides, TrackedNode } from './config.js';

export type Scheme =
    | 'gcp-cloudrun-monolith'
    | 'gcp-cloudrun-microservices'
    | 'docker-monolith'
    | 'local-build-monolith';

export function schemeOf(node: Pick<TrackedNode, 'platform' | 'mode'>): Scheme {
    const platform = node.platform ?? 'docker';
    const mode = node.mode ?? 'monolith';
    if (platform === 'gcp' && mode === 'microservices') return 'gcp-cloudrun-microservices';
    if (platform === 'gcp')                              return 'gcp-cloudrun-monolith';
    if (platform === 'docker')                           return 'docker-monolith';
    return 'local-build-monolith';
}

export function platformOf(scheme: Scheme): Platform {
    if (scheme.startsWith('gcp-'))    return 'gcp';
    if (scheme.startsWith('docker-')) return 'docker';
    return 'local';
}

export function modeOf(scheme: Scheme): Mode {
    return scheme === 'gcp-cloudrun-microservices' ? 'microservices' : 'monolith';
}

// ── Phase 1: scheme picker ───────────────────────────────────────────────────

export async function pickScheme(opts: { isLocalnet: boolean }): Promise<Scheme | null> {
    const choices: { name: string; value: Scheme; disabled?: string }[] = [
        {
            name: 'GCP Cloud Run, monolith         — single Cloud Run service does everything',
            value: 'gcp-cloudrun-monolith',
            disabled: opts.isLocalnet ? '(unavailable: deployment is localnet)' : undefined,
        },
        {
            name: 'GCP Cloud Run, microservices    — Maintainer + Handler pair, Handler scales',
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
    ];
    const picked = await escSelect({
        message: 'Deployment scheme',
        choices,
    });
    return picked as Scheme | null;
}

// ── Phase 2: form generation ─────────────────────────────────────────────────

/** Inputs shared by all four template generators. */
export interface TemplateInputs {
    /** This node's identity (auto-generated). Shown read-only in the form. */
    identity: {
        accountAddr: string;
        pkeEk:       string;
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
    port?:                   string;
    containerName?:          string;
    repoPath?:               string;
    logMaxMb?:               number;
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
    handlerServiceAccount?:  string;
    port?:                   string;
    containerName?:          string;
    repoPath?:               string;
    logMaxMb?:               number;
}

const CHAIN_RPC_PLACEHOLDERS: Record<keyof ChainRpcOverrides, string> = {
    aptosMainnetApi:      'https://api.mainnet.aptoslabs.com/v1',
    aptosMainnetApikey:   'AG-yourkey...',
    aptosTestnetApi:      'https://api.testnet.aptoslabs.com/v1',
    aptosTestnetApikey:   'AG-yourkey...',
    aptosLocalnetApi:     'http://127.0.0.1:8080/v1',
    aptosLocalnetApikey:  'AG-yourkey...',
    solanaMainnetBetaRpc: 'https://api.mainnet-beta.solana.com',
    solanaTestnetRpc:     'https://api.testnet.solana.com',
    solanaDevnetRpc:      'https://api.devnet.solana.com',
};

const CHAIN_RPC_KEYS = Object.keys(CHAIN_RPC_PLACEHOLDERS) as (keyof ChainRpcOverrides)[];

function renderChainRpcBlock(existing?: ChainRpcOverrides, applicabilityNote = ''): string {
    const note = applicabilityNote ? ' ' + applicabilityNote : '';
    const lines = [
        '# Per-chain RPC overrides. Commented out by default — uncomment to override',
        `# the worker's compiled-in default.${note} Get Aptos apikeys at https://developers.aptoslabs.com/.`,
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
    trailingComment: string,
): string {
    const head = `${key.padEnd(20)}`;
    if (value !== undefined && value !== '') {
        return `${head} = "${value}"      ${trailingComment}`;
    }
    return `# ${head} = "${placeholder}"      ${trailingComment}`;
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
        `#  aceAddr         = "${t.blob.aceAddr}"`,
        `#  rpcUrl          = "${t.blob.rpcUrl}"${t.blob.nodeRpcUrl ? '                  # admin\'s view' : ''}`,
        ...(t.blob.nodeRpcUrl ? [`#  nodeRpcUrl      = "${t.blob.nodeRpcUrl}"   # rewritten for the container's view of the host`] : []),
    ].join('\n');
}

function aliasLine(existing?: string): string {
    return nullableLine(
        'alias', existing, 'my-testnet-node',
        `# short friendly name shown in \`${CLI} node ls\` / \`${CLI} network-status\`; uncomment + set to label this node`,
    );
}

function keyLines(t: TemplateInputs): string {
    const apiKey = t.existing?.rpcApiKey ?? t.blob.rpcApiKey;
    const gasKey = t.existing?.gasStationKey ?? t.blob.gasStationKey;
    return [
        nullableLine(
            'rpcApiKey', apiKey, 'AG-yourkey...',
            `# → --ace-deployment-apikey. Pre-filled from deployment blob if present. Comment out to use anonymous (subject to public IP rate limits — get your own at https://developers.aptoslabs.com/)`,
        ),
        nullableLine(
            'gasStationKey', gasKey, 'gsk-yourkey...',
            `# → --ace-deployment-gaskey. Pre-filled from deployment blob if present. Comment out if you have no gas station`,
        ),
    ].join('\n');
}

// ── Per-scheme templates ─────────────────────────────────────────────────────

export function generateTemplate(scheme: Scheme, t: TemplateInputs): string {
    switch (scheme) {
        case 'gcp-cloudrun-monolith':      return generateGcpMonolith(t);
        case 'gcp-cloudrun-microservices': return generateGcpMicroservices(t);
        case 'docker-monolith':            return generateDockerMonolith(t);
        case 'local-build-monolith':       return generateLocalBuildMonolith(t);
    }
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
image            = "${e.image ?? d.image ?? 'aptoslabs/ace-node:latest'}"      # Docker image. List options: \`${CLI} image ls\`
project          = "${e.project ?? d.project ?? ''}"                            # GCP project ID. Default from \`gcloud config get-value project\`. List: \`gcloud projects list\`
region           = "${e.region ?? d.region ?? 'us-central1'}"                   # Cloud Run region. List: \`gcloud run regions list\`
serviceName      = "${e.serviceName ?? d.serviceName ?? ''}"                    # Cloud Run service name. Lowercase letters/digits/hyphens, <64 chars, must start with a letter
${keyLines(t)}

${renderChainRpcBlock(e.chainRpc)}
`;
}

function generateGcpMicroservices(t: TemplateInputs): string {
    const e = t.existing ?? {};
    const d = t.defaults;
    return `# ${CLI} node — scheme: gcp-cloudrun-microservices
#
# Deploys a Maintainer + Handler pair. The Maintainer is internal-only and
# pinned at min=max=1 (it owns the on-chain DKG/DKR coordination, which has
# to be a singleton). The Handler is public and scales 1..handlerMaxInstances.
# Saving emits two \`gcloud run deploy\` commands plus one IAM-binding so the
# Handler's service account can invoke the Maintainer's \`/secrets\`.
#
# Edit the values below, then save and quit your editor.
${HEADER_READONLY_NOTE}
#
${readonlyIdentityBlock(t)}
#
# ── Editable fields ───────────────────────────────────────────────────────────

${aliasLine(e.alias)}
image                 = "${e.image ?? d.image ?? 'aptoslabs/ace-node:latest'}"           # Docker image. List options: \`${CLI} image ls\`
project               = "${e.project ?? d.project ?? ''}"                                # GCP project ID. Default from \`gcloud config get-value project\`. List: \`gcloud projects list\`
region                = "${e.region ?? d.region ?? 'us-central1'}"                       # Cloud Run region. List: \`gcloud run regions list\`
maintainerServiceName = "${e.maintainerServiceName ?? d.maintainerServiceName ?? ''}"    # Internal-only Cloud Run service, min=max=1. Lowercase letters/digits/hyphens, <64 chars, must start with a letter
handlerServiceName    = "${e.handlerServiceName ?? d.handlerServiceName ?? ''}"          # Public Cloud Run service, scales horizontally. Naming: same rules as above
handlerMaxInstances   = ${e.handlerMaxInstances ?? d.handlerMaxInstances ?? 10}          # Cloud Run autoscaling cap on the Handler. Higher = more throughput (also more cost); 1 effectively disables scaling
${keyLines(t)}

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
image            = "${e.image ?? d.image ?? 'aptoslabs/ace-node:latest'}"      # Docker image. List options: \`${CLI} image ls\`
port             = "${e.port ?? d.port ?? '19000'}"                            # TCP port the worker listens on. Default: lowest unused port starting at 19000
containerName    = "${e.containerName ?? d.containerName ?? ''}"               # \`docker run --name\`. Must be unique on this host. List existing: \`docker ps -a --format '{{.Names}}'\`
${keyLines(t)}

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
# image          = (ignored — local builds use the binary at \`<repoPath>/target/release/network-node\`)
repoPath         = "${e.repoPath ?? d.repoPath ?? ''}"                         # path to a checked-out ACE repo
port             = "${e.port ?? d.port ?? '19000'}"                            # TCP port the worker listens on. Default: lowest unused port starting at 19000
logMaxMb         = ${e.logMaxMb ?? d.logMaxMb ?? 50}                            # logrotate threshold (MB); rotates when the log file exceeds this size
${keyLines(t)}

${renderChainRpcBlock(e.chainRpc)}
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
    handlerServiceAccount?:  string;
    port?:                   string;
    containerName?:          string;
    repoPath?:               string;
    logMaxMb?:               number;
}

const FORBIDDEN_TOP = new Set([
    'accountAddr', 'pkeEk', 'pkeDk', 'accountSk', 'aceAddr', 'rpcUrl', 'nodeRpcUrl',
    'endpoint', 'platform', 'mode', 'gcp', 'docker', 'local',
]);

interface SchemaField {
    required: boolean;
    type: 'string' | 'number';
}

const SCHEMA: Record<Scheme, Record<string, SchemaField>> = {
    'gcp-cloudrun-monolith': {
        alias:         { required: false, type: 'string' },
        image:         { required: true,  type: 'string' },
        project:       { required: true,  type: 'string' },
        region:        { required: true,  type: 'string' },
        serviceName:   { required: true,  type: 'string' },
        rpcApiKey:     { required: false, type: 'string' },
        gasStationKey: { required: false, type: 'string' },
    },
    'gcp-cloudrun-microservices': {
        alias:                 { required: false, type: 'string' },
        image:                 { required: true,  type: 'string' },
        project:               { required: true,  type: 'string' },
        region:                { required: true,  type: 'string' },
        maintainerServiceName: { required: true,  type: 'string' },
        handlerServiceName:    { required: true,  type: 'string' },
        handlerMaxInstances:   { required: true,  type: 'number' },
        rpcApiKey:             { required: false, type: 'string' },
        gasStationKey:         { required: false, type: 'string' },
    },
    'docker-monolith': {
        alias:         { required: false, type: 'string' },
        image:         { required: true,  type: 'string' },
        port:          { required: true,  type: 'string' },
        containerName: { required: true,  type: 'string' },
        rpcApiKey:     { required: false, type: 'string' },
        gasStationKey: { required: false, type: 'string' },
    },
    'local-build-monolith': {
        alias:         { required: false, type: 'string' },
        repoPath:      { required: true,  type: 'string' },
        port:          { required: true,  type: 'string' },
        logMaxMb:      { required: true,  type: 'number' },
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
            };
        case 'gcp-cloudrun-microservices':
            return {
                image: fallbackImage,
                project: extras.defaultGcpProject,
                region: 'us-central1',
                maintainerServiceName: `${prefix}-${SUFFIX_MAINTAINER}`,
                handlerServiceName:    `${prefix}-${SUFFIX_HANDLER}`,
                handlerMaxInstances:   10,
            };
        case 'docker-monolith':
            return {
                image: fallbackImage,
                port: extras.defaultPort ?? '19000',
                containerName: `${prefix}-${SUFFIX_MONOLITH}`,
            };
        case 'local-build-monolith':
            return {
                repoPath: extras.defaultRepoPath,
                port: extras.defaultPort ?? '19000',
                logMaxMb: 50,
            };
    }
}

// ── Microservices deploy emission ────────────────────────────────────────────

/**
 * The Cloud Run auto-assigned URL follows
 *   `https://<service>-<project_number>.<region>.run.app`
 * and is fully derivable from the service name + project number + region.
 * That lets us bake the Maintainer URL directly into the Handler's
 * `--maintainer-url` flag at generate time — no post-deploy capture needed.
 */
export function cloudRunUrl(serviceName: string, projectNumber: string, region: string): string {
    return `https://${serviceName}-${projectNumber}.${region}.run.app`;
}

/**
 * Auto-derive the Handler's service-account email. GCP IAM caps SA local-parts
 * at 30 chars, so we derive from the short identity prefix (ace-XXXXXX-YYYYYY)
 * rather than from the handler's Cloud Run service name (which already has a
 * long `-ms-req-handler` suffix and would blow the limit).
 *
 * Stable across edits because the identity prefix derives from on-chain
 * binding (aceAddr + accountAddr), both of which are read-only.
 */
export function defaultHandlerServiceAccount(identityPrefix: string, project: string): string {
    return `${identityPrefix}-ms-sa@${project}.iam.gserviceaccount.com`;
}

// Re-exports for downstream consumers.
export type { GcpConfig, DockerConfig, LocalConfig, ChainRpcOverrides };
