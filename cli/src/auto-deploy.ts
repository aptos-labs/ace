// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Optional auto-run of the deploy commands emitted by `node new` / `node edit`.
 *
 * Behavior: print the command as before, then — if the relevant CLI is
 * installed and reachable — offer to run it inline. The user can always say
 * no and run it themselves; the printed command is the source of truth.
 */

import { execSync, spawnSync } from 'child_process';
import { confirm } from '@inquirer/prompts';

// ANSI escape codes: D = dim, R = reset.
const D = '\x1b[2m', R = '\x1b[0m';

export interface PreflightResult {
    ok: boolean;
    reason?: string;
}

export function gcloudReady(): PreflightResult {
    try {
        execSync('gcloud --version', { stdio: 'ignore' });
    } catch {
        return { ok: false, reason: 'gcloud CLI not on PATH' };
    }
    try {
        const out = execSync(
            'gcloud auth list --filter=status:ACTIVE --format="value(account)"',
            { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
        ).trim();
        if (!out) return { ok: false, reason: 'no active gcloud account (run `gcloud auth login`)' };
    } catch {
        return { ok: false, reason: 'gcloud auth check failed' };
    }
    return { ok: true };
}

export function dockerReady(): PreflightResult {
    try {
        execSync('docker info', { stdio: 'ignore' });
    } catch {
        return { ok: false, reason: 'docker daemon not reachable' };
    }
    return { ok: true };
}

/** Run a shell script via `bash -c`, streaming output to the user's terminal. */
function runShellScript(script: string): boolean {
    const res = spawnSync('bash', ['-c', script], { stdio: 'inherit' });
    return res.status === 0;
}

/**
 * If `preflight.ok`, ask the user whether to run `script` now; on yes, run it
 * and return whether it succeeded. If preflight failed (or the user declined),
 * return false silently — the caller's printed command is the fallback.
 */
export async function maybeAutoRun(
    script: string,
    preflight: PreflightResult,
    promptMsg: string,
): Promise<boolean> {
    if (!preflight.ok) {
        console.log(`${D}(auto-run unavailable: ${preflight.reason}; run the command above when ready)${R}\n`);
        return false;
    }
    const ok = await confirm({ message: promptMsg, default: true });
    if (!ok) return false;
    const success = runShellScript(script);
    if (!success) {
        console.log(`\n${D}(auto-run reported a non-zero exit; re-run the command above by hand if needed)${R}\n`);
    }
    return success;
}

/** Best-effort fetch of a Cloud Run service's auto-assigned URL. */
export function captureCloudRunUrl(
    service: string, project: string, region: string,
): string | undefined {
    try {
        const out = execSync(
            `gcloud run services describe ${service} --project=${project} --region=${region} --format='value(status.url)'`,
            { encoding: 'utf8', stdio: ['ignore', 'pipe', 'ignore'] },
        ).trim();
        return out || undefined;
    } catch {
        return undefined;
    }
}
