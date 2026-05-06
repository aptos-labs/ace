// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { spawn } from 'child_process';
import { createReadStream, existsSync } from 'fs';
import { createInterface } from 'readline';
import { resolveProfile } from '../resolve-profile.js';
import { parseTime } from '../parse-time.js';

// ── Time helpers ─────────────────────────────────────────────────────────────

function toIso(d: Date): string { return d.toISOString(); }

// ── Log line timestamp parser ─────────────────────────────────────────────────
// Local log lines are prefixed: [2024-01-15T10:30:45.123Z] <message>

function parseLocalTimestamp(line: string): Date | null {
    const m = /^\[(\d{4}-\d{2}-\d{2}T[\d:.]+Z)\] /.exec(line);
    return m ? new Date(m[1]!) : null;
}

// ── Stream child process output, optionally stopping at `until` ───────────────

function pipeChildToStdout(
    cmd: string,
    args: string[],
    untilDate?: Date,
): Promise<void> {
    return new Promise((resolve) => {
        const child = spawn(cmd, args, { stdio: ['ignore', 'inherit', 'inherit'] });

        let stopTimer: ReturnType<typeof setTimeout> | undefined;
        if (untilDate) {
            const ms = untilDate.getTime() - Date.now();
            if (ms <= 0) { child.kill(); resolve(); return; }
            stopTimer = setTimeout(() => { child.kill(); resolve(); }, ms);
        }

        child.on('close', () => {
            if (stopTimer) clearTimeout(stopTimer);
            resolve();
        });
    });
}

// ── Platform implementations ──────────────────────────────────────────────────

async function logDocker(
    containerName: string,
    sinceDate?: Date, untilDate?: Date, watch = false,
): Promise<void> {
    const args = ['logs', '--timestamps'];
    if (sinceDate) args.push('--since', toIso(sinceDate));
    // docker logs --follow + --until is unsupported; we handle --until by killing the child
    if (!watch && untilDate) args.push('--until', toIso(untilDate));
    if (watch) args.push('-f');
    args.push(containerName);
    await pipeChildToStdout('docker', args, watch ? untilDate : undefined);
}

async function logGcp(
    serviceName: string, project: string, region: string,
    sinceDate?: Date, untilDate?: Date, watch = false,
): Promise<void> {
    const conditions = [
        `resource.type="cloud_run_revision"`,
        `resource.labels.service_name="${serviceName}"`,
        `resource.labels.location="${region}"`,
    ];
    if (sinceDate)  conditions.push(`timestamp>="${toIso(sinceDate)}"`);
    if (untilDate)  conditions.push(`timestamp<="${toIso(untilDate)}"`);
    const filter = conditions.join(' AND ');

    if (watch) {
        // gcloud beta logging tail exits when killed
        await pipeChildToStdout('gcloud', [
            'beta', 'logging', 'tail', filter,
            `--project=${project}`,
            '--format=value(timestamp,textPayload)',
        ], untilDate);
    } else {
        await pipeChildToStdout('gcloud', [
            'logging', 'read', filter,
            `--project=${project}`,
            `--order=asc`,
            '--format=value(timestamp,textPayload)',
        ]);
    }
}

async function readFileFiltered(file: string, sinceDate?: Date, untilDate?: Date): Promise<void> {
    const stream = createReadStream(file, { encoding: 'utf8' });
    const rl = createInterface({ input: stream, crlfDelay: Infinity });
    await new Promise<void>((resolve) => {
        rl.on('line', (line) => {
            const ts = parseLocalTimestamp(line);
            if (sinceDate && ts && ts < sinceDate) return;
            if (untilDate && ts && ts > untilDate) return;
            process.stdout.write(line + '\n');
        });
        rl.on('close', resolve);
    });
}

async function logLocal(
    logFile: string,
    sinceDate?: Date, untilDate?: Date, watch = false,
): Promise<void> {
    if (!existsSync(logFile)) {
        console.error(`Log file not found: ${logFile}`);
        process.exit(1);
    }

    if (watch) {
        // tail -f; start from beginning only when --since is given, otherwise new lines only
        const child = spawn('tail', ['-f', '-n', sinceDate ? '+1' : '0', logFile], {
            stdio: ['ignore', 'pipe', 'inherit'],
        });

        let stopTimer: ReturnType<typeof setTimeout> | undefined;
        if (untilDate) {
            const ms = untilDate.getTime() - Date.now();
            if (ms > 0) stopTimer = setTimeout(() => { child.kill(); }, ms);
            else { child.kill(); return; }
        }

        const rl = createInterface({ input: child.stdout!, crlfDelay: Infinity });
        rl.on('line', (line) => {
            const ts = parseLocalTimestamp(line);
            if (sinceDate && ts && ts < sinceDate) return;
            if (untilDate && ts && ts > untilDate) { child.kill(); return; }
            process.stdout.write(line + '\n');
        });

        await new Promise<void>((resolve) => {
            child.on('close', () => {
                if (stopTimer) clearTimeout(stopTimer);
                resolve();
            });
        });
    } else {
        // Read rotated backup first (older entries), then current log
        const rotated = `${logFile}.1`;
        if (sinceDate && existsSync(rotated)) {
            await readFileFiltered(rotated, sinceDate, untilDate);
        }
        await readFileFiltered(logFile, sinceDate, untilDate);
    }
}

// ── Entry point ───────────────────────────────────────────────────────────────

export async function logCommand(opts: {
    profile?: string;
    account?: string;
    since?: string;
    until?: string;
    watch?: boolean;
}): Promise<void> {
    const { node } = resolveProfile(opts.profile, opts.account);

    const DEFAULT_SINCE = '-1h';
    const effectiveSince = opts.since ?? (opts.watch ? undefined : DEFAULT_SINCE);
    if (!opts.since && !opts.watch) {
        console.error(`(showing last 1h — use --since to adjust, e.g. --since -6h)\n`);
    }
    const sinceDate = effectiveSince ? parseTime(effectiveSince) : undefined;
    const untilDate = opts.until ? parseTime(opts.until) : undefined;

    if (node.platform === 'docker' && node.docker) {
        await logDocker(node.docker.containerName, sinceDate, untilDate, opts.watch);
    } else if (node.platform === 'gcp' && node.gcp) {
        await logGcp(
            node.gcp.serviceName, node.gcp.project, node.gcp.region,
            sinceDate, untilDate, opts.watch,
        );
    } else if (node.platform === 'local' && node.local?.logFile) {
        await logLocal(node.local.logFile, sinceDate, untilDate, opts.watch);
    } else {
        console.error('No supported deployment platform found for this profile (need docker, gcp, or local with a log file).');
        process.exit(1);
    }
}
