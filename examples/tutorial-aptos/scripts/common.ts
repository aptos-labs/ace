// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import * as readline from 'readline';
import { AccountAddress } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

// ── ACE deployment targeted by this tutorial ──────────────────────────────────
// Default: the public ACE testnet preview (`preview20260506`). To target a
// different deployment — e.g. one you bootstrapped yourself — replace the
// three constants below with literals (see the commented example).
const _knownDeployment = ACE.knownDeployments.preview20260506;
export const TUTORIAL_ACE_DEPLOYMENT = _knownDeployment.aceDeployment;
export const TUTORIAL_CHAIN_ID       = _knownDeployment.chainId;
export const TUTORIAL_KEYPAIR_ID     = _knownDeployment.keypairId;
export const TUTORIAL_APP_ORIGIN     = 'https://tutorial.ace.aptos.dev';
//
// Example: pointing the tutorial at a self-bootstrapped devnet deployment.
// Replace the three lines above with:
//
//   import { AccountAddress } from '@aptos-labs/ts-sdk';
//   export const TUTORIAL_ACE_DEPLOYMENT = new ACE.AceDeployment({
//       apiEndpoint:  'https://api.devnet.aptoslabs.com/v1',
//       contractAddr: AccountAddress.fromString('0xYOUR_ACE_CONTRACT_ADDR'),
//   });
//   export const TUTORIAL_CHAIN_ID   = 140;  // devnet
//   export const TUTORIAL_KEYPAIR_ID = AccountAddress.fromString('0xYOUR_KEYPAIR_ID');
// ──────────────────────────────────────────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const ROOT = path.join(__dirname, '..');
export const CONTRACT_DIR = path.join(ROOT, 'contract');
export const DATA_DIR = path.join(ROOT, 'data');

export interface ItemSpec {
    name: string;
    plaintext: string;
    priceOctas: number;
}

export const ITEMS: ItemSpec[] = [
    { name: 'song-1.mp3', plaintext: 'Lyrics for song 1: hello sunshine!', priceOctas: 10_000_000 },
    { name: 'song-2.mp3', plaintext: 'Lyrics for song 2: goodbye rain!',  priceOctas: 10_000_000 },
];

export function ensureDataDir(): void {
    if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
}

export function readJson<T>(filePath: string): T {
    return JSON.parse(readFileSync(filePath, 'utf8')) as T;
}

export function writeJson(filePath: string, data: unknown): void {
    writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
}

export function log(...args: unknown[]): void {
    console.log(`[${new Date().toISOString()}]`, ...args);
}

export function waitForEnter(prompt: string): Promise<void> {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise(resolve => rl.question(prompt, () => { rl.close(); resolve(); }));
}

/**
 * Builds the `fullMessage` an AIP-62 wallet would return from `aptos:signMessage`
 * for `{ message, nonce, address: true, application: true, chainId: true }`.
 *
 * Wire layout: literal prefix `APTOS`, then `<field>: <value>` lines joined by
 * `\n`, one per included field. This is the labeled multi-line encoding the
 * Aptos wallet-adapter implements; the canonical encoder/decoder pair lives at
 * https://github.com/aptos-labs/aptos-wallet-adapter/blob/294f5a49af55549a75e549ca0d303e45d70809bf/packages/derived-wallet-base/src/StructuredMessage.ts
 * (see `encodeStructuredMessage` / `decodeStructuredMessage`). The
 * `signMessage` API and `fullMessage` field are specified in AIP-62:
 * https://github.com/aptos-foundation/AIPs/blob/bb5b7ebcdb01b29622e968f785b03cd71cfb6c17/aips/aip-062-wallet-standard.md
 *
 * Worker-side parsing only requires the `APTOS` prefix and an `application:`
 * line (origin extraction); field ordering past that is not load-bearing.
 */
export function buildAptosWalletFullMessage(args: {
    accountAddress: AccountAddress | string;
    chainId: number;
    message: string;
    nonce: string;
}): string {
    const address = typeof args.accountAddress === 'string'
        ? args.accountAddress
        : args.accountAddress.toStringLong();
    return [
        'APTOS',
        `address: ${address}`,
        `application: ${TUTORIAL_APP_ORIGIN}`,
        `chainId: ${args.chainId}`,
        `message: ${args.message}`,
        `nonce: ${args.nonce}`,
    ].join('\n');
}

export const ALICE_FILE = path.join(DATA_DIR, 'alice.json');
export const BOB_FILE = path.join(DATA_DIR, 'bob.json');
export const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
export const CATALOG_FILE = path.join(DATA_DIR, 'catalog.json');

export interface AccountFile {
    address: string;
    privateKeyHex: string;
}

export interface ConfigFile {
    appContractAddr: string;
}

export interface CatalogEntry {
    name: string;
    priceOctas: number;
    ciphertextHex: string;
}

export interface CatalogFile {
    items: CatalogEntry[];
}
