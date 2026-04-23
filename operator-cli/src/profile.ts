// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { readFileSync } from 'fs';

export interface NodeProfile {
  accountAddr: string;
  accountSk: string;
  pkeDk: string;
  pkeEk: string;
}

const ENV_KEYS: Record<keyof NodeProfile, string> = {
  accountAddr: 'ACE_ACCOUNT_ADDR',
  accountSk:   'ACE_ACCOUNT_SK',
  pkeDk:       'ACE_PKE_DK',
  pkeEk:       'ACE_PKE_EK',
};

/** Read a profile from a .env file, or fall back to environment variables. */
export function readProfile(envFile: string | undefined): NodeProfile {
  const vars: Record<string, string> = envFile
    ? parseEnvFile(envFile)
    : process.env as Record<string, string>;

  const profile: Partial<NodeProfile> = {};
  for (const [field, envKey] of Object.entries(ENV_KEYS) as [keyof NodeProfile, string][]) {
    const val = vars[envKey];
    if (!val) {
      const hint = envFile ? `in ${envFile}` : `(set ${envKey} or use --profile)`;
      throw new Error(`Missing ${envKey} ${hint}`);
    }
    profile[field] = val;
  }
  return profile as NodeProfile;
}

function parseEnvFile(filePath: string): Record<string, string> {
  const vars: Record<string, string> = {};
  for (const line of readFileSync(filePath, 'utf8').split('\n')) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const idx = trimmed.indexOf('=');
    if (idx === -1) continue;
    vars[trimmed.slice(0, idx).trim()] = trimmed.slice(idx + 1).trim();
  }
  return vars;
}
