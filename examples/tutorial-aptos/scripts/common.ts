// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import * as readline from 'readline';
import { AccountAddress } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';

// ── ACE deployment targeted by this tutorial ──────────────────────────────────
// Point the example at an explicit ACE deployment. Preview addresses are not
// treated as permanent configuration.
const aceContract = process.env.ACE_CONTRACT;
if (!aceContract) throw new Error('Set ACE_CONTRACT to the target ACE contract address.');
export const TUTORIAL_ACE_DEPLOYMENT = new ACE.AceDeployment({
    apiEndpoint: process.env.ACE_API_ENDPOINT ?? 'https://api.testnet.aptoslabs.com/v1',
    contractAddr: AccountAddress.fromString(aceContract),
});
export const TUTORIAL_CHAIN_ID = Number(process.env.ACE_CHAIN_ID ?? '2');
export const TUTORIAL_APP_ORIGIN     = 'https://tutorial.ace.aptos.dev';

export function tutorialIbeKeypairId(): AccountAddress {
    const value = process.env.IBE_KEYPAIR_ID;
    if (!value) {
        throw new Error('Set IBE_KEYPAIR_ID to the t-IBE keypair for the target ACE deployment.');
    }
    return AccountAddress.fromString(value);
}
//
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
