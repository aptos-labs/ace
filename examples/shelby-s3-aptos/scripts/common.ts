// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import * as readline from 'readline';
import * as ACE from '@aptos-labs/ace-sdk';

// Default: the public ACE testnet preview. Replace these constants if you want
// to target a self-hosted ACE deployment.
const knownDeployment = ACE.knownDeployments.preview20260506;
export const SHELBY_ACE_DEPLOYMENT = knownDeployment.aceDeployment;
export const SHELBY_CHAIN_ID = knownDeployment.chainId;
export const SHELBY_KEYPAIR_ID = knownDeployment.keypairId;

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const ROOT = path.join(__dirname, '..');
export const CONTRACT_DIR = path.join(ROOT, 'contract');
export const DATA_DIR = path.join(ROOT, 'data');

export const OWNER_FILE = path.join(DATA_DIR, 'owner.json');
export const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
export const UPLOAD_FILE = path.join(DATA_DIR, 'upload.json');
export const ACCESS_TOKEN_FILE = path.join(DATA_DIR, 'access-token.json');

export const DEMO_FILE = {
    fileId: 'shelby-s3://demo-owner/contracts/acquisition-plan.txt',
    plaintext: [
        'Shelby S3 private file',
        'Project: encrypted upload with bearer access token',
        'Only the owner or someone holding the generated token should decrypt this.',
    ].join('\n'),
};

export interface AccountFile {
    address: string;
    privateKeyHex: string;
}

export interface ConfigFile {
    appContractAddr: string;
}

export interface UploadFile {
    fileId: string;
    ownerAddress: string;
    tokenAddress: string;
    ciphertextHex: string;
}

export interface AccessTokenFile extends AccountFile {
    kind: 'ed25519-private-key';
    scope: string;
}

export function ensureDataDir(): void {
    if (!existsSync(DATA_DIR)) mkdirSync(DATA_DIR, { recursive: true });
}

export function readJson<T>(filePath: string): T {
    return JSON.parse(readFileSync(filePath, 'utf8')) as T;
}

export function writeJson(filePath: string, data: unknown): void {
    writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
}

export function privateKeyHex(account: { privateKey: { toUint8Array(): Uint8Array } }): string {
    return '0x' + Buffer.from(account.privateKey.toUint8Array()).toString('hex');
}

export function log(...args: unknown[]): void {
    console.log(`[${new Date().toISOString()}]`, ...args);
}

export function waitForEnter(prompt: string): Promise<void> {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise(resolve => rl.question(prompt, () => { rl.close(); resolve(); }));
}
