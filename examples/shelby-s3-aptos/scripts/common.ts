// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { createHash } from 'crypto';
import * as path from 'path';
import { fileURLToPath } from 'url';
import * as readline from 'readline';
import { Account, Ed25519PrivateKey } from '@aptos-labs/ts-sdk';
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
    tokenNonce: string;
    tokenAddress: string;
    ciphertextHex: string;
}

export interface AccessTokenFile extends AccountFile {
    kind: 'ed25519-private-key';
    derivedFrom: 'owner-signature';
    nonce: string;
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

export function accessTokenSeedMessage(ownerAddress: string, fileId: string, tokenNonce: string): string {
    return [
        'shelby-s3/access-token/v1',
        `owner=${ownerAddress}`,
        `file_id=${fileId}`,
        `nonce=${tokenNonce}`,
    ].join('\n');
}

export function deriveAccessTokenAccount(
    owner: {
        accountAddress: { toStringLong(): string };
        sign(message: Uint8Array): { toUint8Array(): Uint8Array };
    },
    fileId: string,
    tokenNonce: string,
): { account: Account; privateKeyHex: string; seedMessage: string } {
    const seedMessage = accessTokenSeedMessage(owner.accountAddress.toStringLong(), fileId, tokenNonce);
    const ownerSignature = owner.sign(new TextEncoder().encode(seedMessage)).toUint8Array();
    const tokenSeed = createHash('sha256')
        .update('shelby-s3/derived-token-key/v1')
        .update(ownerSignature)
        .digest();
    const tokenPrivateKeyHex = '0x' + tokenSeed.toString('hex');

    return {
        account: Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(tokenPrivateKeyHex) }),
        privateKeyHex: tokenPrivateKeyHex,
        seedMessage,
    };
}

export function log(...args: unknown[]): void {
    console.log(`[${new Date().toISOString()}]`, ...args);
}

export function waitForEnter(prompt: string): Promise<void> {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise(resolve => rl.question(prompt, () => { rl.close(); resolve(); }));
}
