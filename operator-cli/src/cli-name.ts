// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

const arg = process.argv[1] ?? '';
const isDev = arg.endsWith('.ts') || arg.includes('/tsx') || arg.includes('/ts-node');

/** The name to use when printing suggested follow-up commands. */
export const CLI = isDev ? 'pnpm run dev' : 'ace';
