// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { spawn } from 'child_process';
import { mkdirSync, openSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';
import { execSync } from 'child_process';

const LOG_DIR = join(homedir(), '.ace', 'logs');

export function logFilePath(nodeKey: string): string {
    mkdirSync(LOG_DIR, { recursive: true });
    const slug = nodeKey.replace(/\//g, '_').replace(/[^a-zA-Z0-9_.-]/g, '-');
    return join(LOG_DIR, `${slug}.log`);
}

/**
 * Spawn network-node in the background (detached, stdio → log file via fd).
 * Returns the child's PID.
 */
export function spawnLocalNode(binaryPath: string, runArgs: string[], logFile: string): number {
    mkdirSync(LOG_DIR, { recursive: true });
    const logFd = openSync(logFile, 'a');

    const child = spawn(binaryPath, runArgs, {
        detached: true,
        stdio: ['ignore', logFd, logFd],
    });
    child.unref();

    return child.pid!;
}

/**
 * Returns true if a process with `pid` is running and its command line contains
 * `network-node` (guards against PID reuse by unrelated processes).
 */
export function isLocalNodeAlive(pid: number): boolean {
    try {
        process.kill(pid, 0); // throws if process doesn't exist
        const cmd = execSync(`ps -p ${pid} -o command= 2>/dev/null`, { encoding: 'utf8' }).trim();
        return cmd.includes('network-node');
    } catch {
        return false;
    }
}

export function killLocalNode(pid: number): void {
    try { process.kill(pid, 'SIGTERM'); } catch { /* already gone */ }
}

export { LOG_DIR };
