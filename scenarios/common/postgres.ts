// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { execFileSync } from 'child_process';
import { existsSync } from 'fs';
import * as path from 'path';

export type TempPostgres = {
    port: number;
    dataDir: string;
    logFile: string;
    urlForDatabase(dbName: string): string;
    createDatabase(dbName: string): void;
    stop(): void;
};

export function startTempPostgres(tmpRoot: string, label: string, port: number): TempPostgres {
    const binDir = findPostgresBinDir();
    const dataDir = path.join(tmpRoot, `${label}-pg-data`);
    const logFile = path.join(tmpRoot, `${label}-postgres.log`);

    const env = {
        ...process.env,
        PATH: `${binDir}:${process.env.PATH ?? ''}`,
        LC_ALL: 'C',
    };

    runPostgresTool(binDir, 'initdb', [
        '-D', dataDir,
        '-A', 'trust',
        '-U', 'ace',
        '--locale=C',
        '-E', 'UTF8',
    ], env);

    runPostgresTool(binDir, 'pg_ctl', [
        '-D', dataDir,
        '-l', logFile,
        '-o', `-p ${port} -h 127.0.0.1 -k /tmp`,
        '-w',
        'start',
    ], env);

    return {
        port,
        dataDir,
        logFile,
        urlForDatabase(dbName: string): string {
            return `postgres://ace@127.0.0.1:${port}/${dbName}`;
        },
        createDatabase(dbName: string): void {
            runPostgresTool(binDir, 'createdb', [
                '-h', '127.0.0.1',
                '-p', String(port),
                '-U', 'ace',
                dbName,
            ], env);
        },
        stop(): void {
            try {
                runPostgresTool(binDir, 'pg_ctl', [
                    '-D', dataDir,
                    '-m', 'fast',
                    '-w',
                    'stop',
                ], env);
            } catch {
                // Best-effort cleanup; the scenario will already be failing with the root cause.
            }
        },
    };
}

function runPostgresTool(
    binDir: string,
    tool: string,
    args: string[],
    env: NodeJS.ProcessEnv,
): void {
    const cmd = path.join(binDir, tool);
    try {
        execFileSync(cmd, args, { stdio: 'pipe', env });
    } catch (err) {
        const error = err as { stdout?: unknown; stderr?: unknown; message?: string };
        const stdout = commandOutput(error.stdout);
        const stderr = commandOutput(error.stderr);
        throw new Error([
            `${tool} failed: ${error.message ?? 'unknown error'}`,
            stdout && `stdout:\n${stdout}`,
            stderr && `stderr:\n${stderr}`,
        ].filter(Boolean).join('\n'));
    }
}

function commandOutput(output: unknown): string {
    if (!output) return '';
    if (Buffer.isBuffer(output)) return output.toString('utf8').trim();
    return String(output).trim();
}

export function findPostgresBinDir(): string {
    const pathDirs = (process.env.PATH ?? '').split(path.delimiter).filter(Boolean);
    const candidates = [
        ...pathDirs,
        '/opt/homebrew/opt/postgresql@16/bin',
        '/usr/local/opt/postgresql@16/bin',
        '/opt/homebrew/opt/postgresql/bin',
        '/usr/local/opt/postgresql/bin',
        '/usr/lib/postgresql/16/bin',
        '/usr/lib/postgresql/15/bin',
        '/usr/lib/postgresql/14/bin',
    ];
    for (const dir of candidates) {
        if (
            existsSync(path.join(dir, 'initdb')) &&
            existsSync(path.join(dir, 'pg_ctl')) &&
            existsSync(path.join(dir, 'createdb')) &&
            existsSync(path.join(dir, 'psql'))
        ) {
            return dir;
        }
    }
    throw new Error(
        'PostgreSQL tools not found. Run scripts/install-tools.sh to install initdb, pg_ctl, createdb, and psql.',
    );
}
