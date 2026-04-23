// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from 'child_process';
import type { NodeProfile } from './profile.js';

export interface RunOptions {
  rpcUrl: string;
  /** Geomi node API key — forwarded as `--ace-deployment-apikey`. */
  rpcApikey?: string;
  aceAddr: string;
  /** Port to expose on the host and pass as `--port` to the binary. */
  port?: number;
  /** Docker image to run, e.g. `aptoslabs/ace-node:v0.2.0`. */
  image: string;
  /** Gas station API key — forwarded as `--ace-deployment-gaskey`. */
  gasStationKey?: string;
  /** Extra arguments forwarded verbatim to the `network-node run` binary. */
  extraArgs: string[];
}

export function run(profile: NodeProfile, opts: RunOptions): void {
  const dockerArgs: string[] = ['run', '--rm', '-it', '--platform', 'linux/amd64'];

  if (opts.port !== undefined) {
    dockerArgs.push('-p', `${opts.port}:${opts.port}`);
  }

  dockerArgs.push(opts.image);

  // network-node subcommand
  dockerArgs.push('run');

  // Flags sourced from the profile
  dockerArgs.push('--account-addr',       profile.accountAddr);
  dockerArgs.push('--account-sk',         profile.accountSk);
  dockerArgs.push('--pke-dk',             profile.pkeDk);

  // Flags sourced from CLI options
  dockerArgs.push('--ace-deployment-api',  opts.rpcUrl);
  dockerArgs.push('--ace-deployment-addr', opts.aceAddr);

  if (opts.rpcApikey) {
    dockerArgs.push('--ace-deployment-apikey', opts.rpcApikey);
  }
  if (opts.gasStationKey) {
    dockerArgs.push('--ace-deployment-gaskey', opts.gasStationKey);
  }
  if (opts.port !== undefined) {
    dockerArgs.push('--port', String(opts.port));
  }

  // Pass-through args (everything after -- on the ace-node command line)
  dockerArgs.push(...opts.extraArgs);

  // Print the full command so the operator can inspect / reproduce it
  const printable = dockerArgs.map(a => {
    // Mask secrets in printed output
    if (a === profile.accountSk || a === profile.pkeDk) return '<redacted>';
    return /\s/.test(a) ? `"${a}"` : a;
  });
  process.stderr.write(`\ndocker ${printable.join(' ')}\n\n`);

  const result = spawnSync('docker', dockerArgs, { stdio: 'inherit' });
  if (result.error) {
    process.stderr.write(`Failed to start docker: ${result.error.message}\n`);
    process.exit(1);
  }
  process.exit(result.status ?? 0);
}
