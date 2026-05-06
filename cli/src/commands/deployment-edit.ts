// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * `ace deployment edit` — open the resolved deployment profile in `$EDITOR` as a TOML
 * template. Editable fields: `alias`, `rpcUrl`, `network`, `sharedNodeApiKey`,
 * `gasStationApiKey`. Identity fields (`aceAddr`, `adminAddress`, `adminPrivateKey`,
 * `deployedAt*`) are surfaced as comments only — uncommenting / changing them errors out.
 *
 * Pre-warning: credentials are visible in the editor; user must confirm.
 */

import { parse as parseToml } from 'smol-toml';
import { loadConfig, saveConfig, type TrackedDeployment } from '../config.js';
import { resolveDeployment } from '../resolve-profile.js';
import { buildFromEditor } from '../editor.js';

const ALLOWED_KEYS = ['alias', 'rpcUrl', 'network', 'sharedNodeApiKey', 'gasStationApiKey'] as const;
type AllowedKey = typeof ALLOWED_KEYS[number];

function generateTemplate(dep: TrackedDeployment, deploymentKey: string): string {
    return `# ACE deployment profile — edit the values below, then save & quit.
# Lines starting with '#' are comments; identity fields (commented out) are
# read-only — re-introducing them in the live TOML will be rejected.
#
# Profile key: ${deploymentKey}
#
# ── Read-only identity (do NOT uncomment) ─────────────────────────────────────
#  aceAddr          = "${dep.aceAddr}"
#  adminAddress     = "${dep.adminAddress}"
#  adminPrivateKey  = "${dep.adminPrivateKey}"
#  deployedAtTag    = ${dep.deployedAtTag ? `"${dep.deployedAtTag}"` : '<unset>'}
#  deployedAtCommit = ${dep.deployedAtCommit ? `"${dep.deployedAtCommit}"` : '<unset>'}
#  deployedAt       = ${dep.deployedAt ? `"${dep.deployedAt}"` : '<unset>'}
#
# ── Editable ──────────────────────────────────────────────────────────────────
alias            = ${tomlString(dep.alias)}
rpcUrl           = "${dep.rpcUrl}"
network          = ${tomlString(dep.network)}
sharedNodeApiKey = ${tomlString(dep.sharedNodeApiKey)}
gasStationApiKey = ${tomlString(dep.gasStationApiKey)}
`;
}

function tomlString(v: string | undefined): string {
    return v === undefined ? '""' : `"${v}"`;
}

function parseEdited(content: string, dep: TrackedDeployment): Partial<TrackedDeployment> | null {
    let doc: Record<string, unknown>;
    try {
        doc = parseToml(content) as Record<string, unknown>;
    } catch (e) {
        throw new Error(`TOML parse error: ${(e as Error).message}`);
    }

    // Reject identity-field overwrites.
    const FORBIDDEN = ['aceAddr', 'adminAddress', 'adminPrivateKey', 'deployedAtTag', 'deployedAtCommit', 'deployedAt'];
    for (const k of FORBIDDEN) {
        if (k in doc) {
            throw new Error(`Field "${k}" is read-only and cannot be edited. Delete the line and try again.`);
        }
    }

    // Reject any unknown keys (typos, etc.).
    for (const k of Object.keys(doc)) {
        if (!ALLOWED_KEYS.includes(k as AllowedKey)) {
            throw new Error(`Unknown field "${k}". Allowed: ${ALLOWED_KEYS.join(', ')}.`);
        }
    }

    const upd: Partial<TrackedDeployment> = {};
    for (const k of ALLOWED_KEYS) {
        const v = doc[k];
        if (v === undefined) continue;
        if (typeof v !== 'string') {
            throw new Error(`Field "${k}" must be a string (got ${typeof v}).`);
        }
        // Treat empty string as "clear this optional field" (except rpcUrl which is required).
        if (v === '' && k === 'rpcUrl') throw new Error(`Field "rpcUrl" cannot be empty.`);
        (upd as Record<string, string | undefined>)[k] = v === '' ? undefined : v;
    }

    // Avoid touching keys whose value didn't actually change.
    const changed: Partial<TrackedDeployment> = {};
    for (const k of ALLOWED_KEYS) {
        if (upd[k] !== dep[k]) (changed as Record<string, string | undefined>)[k] = upd[k];
    }
    if (Object.keys(changed).length === 0) {
        console.log('No effective changes — cancelled.');
        return null;
    }
    return changed;
}

export async function deploymentEditCommand(opts: { profile?: string; account?: string }): Promise<void> {
    const { deploymentKey, deployment } = resolveDeployment(opts.profile, opts.account);

    const warning =
        '⚠ The editor will display the admin private key and any API keys for this deployment.\n' +
        '  Do NOT share the temp file or your terminal during the edit.\n';

    const changes = await buildFromEditor(
        generateTemplate(deployment, deploymentKey),
        c => parseEdited(c, deployment),
        { fileTag: 'deployment-edit', preWarning: warning },
    );
    if (!changes) return;

    const config = loadConfig();
    const dep = config.deployments[deploymentKey];
    if (!dep) {
        console.error(`Deployment profile "${deploymentKey}" disappeared between resolution and save.`);
        process.exit(1);
    }
    Object.assign(dep, changes);
    saveConfig(config);

    const pretty = Object.entries(changes)
        .map(([k, v]) => `  ${k}: ${v ?? '(unset)'}`)
        .join('\n');
    console.log(`✓ Updated deployment profile "${dep.alias ?? deploymentKey}":\n${pretty}`);
}
