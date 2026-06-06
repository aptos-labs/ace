// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import { AccountAddress, Serializer } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { bls12_381 } from '@noble/curves/bls12-381';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';

// ── Deployment target ────────────────────────────────────────────────────────
//
// This demo is localnet-only. Bring up an ACE localnet via
// `pnpm --filter ace-scenarios run-local-network-forever` (wait for the
// "ACE local network is READY" banner) and the steps below read the chain
// RPC + ACE worker contract + DKG'd keypair_id from /tmp/ace-localnet-config.json.

export const LOCALNET_CONFIG_PATH = '/tmp/ace-localnet-config.json';

interface LocalnetConfig {
    apiEndpoint: string;
    contractAddr: string;
    keypairId: string;
}

/** Different scenario harnesses write the localnet config under slightly
 *  different schemas (singular `keypairId` vs plural `keypairIds[0]`).
 *  Accept either. */
export function readLocalnetConfig(): LocalnetConfig {
    let raw: any;
    try {
        raw = JSON.parse(readFileSync(LOCALNET_CONFIG_PATH, 'utf8'));
    } catch {
        throw new Error(
            `Could not read ${LOCALNET_CONFIG_PATH}. Bring up an ACE localnet first via ` +
            `\`pnpm --filter ace-scenarios run-local-network-forever\` and wait ` +
            `for the "ACE local network is READY" banner.`,
        );
    }
    const keypairId = raw.keypairId ?? (Array.isArray(raw.keypairIds) ? raw.keypairIds[0] : undefined);
    if (!raw.apiEndpoint || !raw.contractAddr || !keypairId) {
        throw new Error(`Malformed ${LOCALNET_CONFIG_PATH}: need {apiEndpoint, contractAddr, keypairId|keypairIds[]}`);
    }
    return { apiEndpoint: raw.apiEndpoint, contractAddr: raw.contractAddr, keypairId };
}

export const LOCALNET_FAUCET_URL = 'http://localhost:8081';

/** Matches `EXPECTED_APP_ORIGIN` in `presigned_access.move`. */
export const APP_ORIGIN = 'https://shelby.example';

/** Matches `SIGNABLE_REQUEST_DST` in `presigned_access.move`. */
export const SIGNABLE_REQUEST_DST = 'ACE_PRESIGNED_ACCESS_v2';

/** IETF BLS-min-pubkey-size signature DST — same one
 *  `aptos_std::bls12381::verify_normal_signature` consumes, confirmed by a
 *  Move-side round-trip spike when the contract was first written. */
export const BLS_HASH_DST = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_';

// ── Filesystem layout ────────────────────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/** This package layout is one level deeper than tutorial-aptos: scripts
 *  live under `demo-cli-flow/scripts/`, so `..` from here is the demo-cli
 *  package root, and `../..` is the example root where `contract/` lives. */
export const DEMO_ROOT = path.join(__dirname, '..');
export const EXAMPLE_ROOT = path.join(DEMO_ROOT, '..');
export const CONTRACT_DIR = path.join(EXAMPLE_ROOT, 'contract');
export const DATA_DIR = path.join(DEMO_ROOT, 'data');

export const ALICE_FILE  = path.join(DATA_DIR, 'alice.json');
export const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
export const GRANT_FILE  = path.join(DATA_DIR, 'grant.json');

export interface AccountFile {
    address: string;
    privateKeyHex: string;
}

export interface ConfigFile {
    appContractAddr: string;
}

/** The "pre-signed URL" Alice hands to Bob out-of-band. Carrying the
 *  ciphertext alongside the bearer key is a convenience: in real life
 *  the ciphertext lives on Shelby and the grant just points to it. */
export interface GrantFile {
    blobSuffix: string;
    blobIdHex: string;        // utf8 hex of `@<canon-owner>/<suffix>`
    ciphertextHex: string;
    accessTokenHex: string;   // 32-byte hex; reduced mod r when used as a scalar
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

export function log(...args: unknown[]): void {
    console.log(`[${new Date().toISOString()}]`, ...args);
}

// ── Faucet ───────────────────────────────────────────────────────────────────

export async function fundViaFaucet(addr: AccountAddress, octas: number): Promise<void> {
    const r = await fetch(
        `${LOCALNET_FAUCET_URL}/mint?amount=${octas}&address=${addr.toStringLong()}`,
        { method: 'POST' },
    );
    if (!r.ok) throw new Error(`faucet ${r.status}: ${await r.text()}`);
    await new Promise(res => setTimeout(res, 1000));
}

// ── Bearer-token crypto (mirrors presigned_access.move) ──────────────────────

/** Derive the BLS12-381 access keypair from 32 bytes of tVRF output.
 *  Reduces to an Fr scalar (`accessToken`) and computes `accessPk =
 *  accessToken * G1`. The bias from 256-bit-mod-r reduction is ~2^-255,
 *  negligible for this use case. */
export function vrfOutputToAccessKeypair(vrfBytes: Uint8Array): {
    accessToken: bigint;
    accessPk: Uint8Array;
} {
    if (vrfBytes.length !== 32) throw new Error(`vrfBytes: expected 32, got ${vrfBytes.length}`);
    const accessToken = BigInt('0x' + bytesToHex(vrfBytes)) % bls12_381.fields.Fr.ORDER;
    const accessPk = bls12_381.G1.ProjectivePoint.BASE.multiply(accessToken).toRawBytes(true);
    return { accessToken, accessPk };
}

/** Build the bytes the bearer's `accessToken` actually signs. Must match
 *  `bcs::to_bytes(&SignableRequest { dst, label, user_epk, origin })`
 *  on-chain — struct BCS = concat of fields, each `vector<u8>` =
 *  ULEB128(len)||bytes. */
export function buildSignableMessage(args: {
    label: Uint8Array;
    userEpk: Uint8Array;
    origin: Uint8Array;
}): Uint8Array {
    const s = new Serializer();
    s.serializeBytes(utf8ToBytes(SIGNABLE_REQUEST_DST));
    s.serializeBytes(args.label);
    s.serializeBytes(args.userEpk);
    s.serializeBytes(args.origin);
    return s.toUint8Array();
}

export function signWithAccessToken(accessToken: bigint, msg: Uint8Array): Uint8Array {
    return (bls12_381.G2.hashToCurve(msg, { DST: BLS_HASH_DST }) as any)
        .multiply(accessToken)
        .toRawBytes(true);
}

/** Build `payload: vector<u8>` — the worker passes this opaquely to the
 *  contract: `BCS({ origin, sig })`. */
export function buildPayload(origin: Uint8Array, sig: Uint8Array): Uint8Array {
    const s = new Serializer();
    s.serializeBytes(origin);
    s.serializeBytes(sig);
    return s.toUint8Array();
}

/** Mirrors AIP-62 `aptos:signMessage` output for the labeled multi-line layout
 *  the ACE worker parses (`APTOS` prefix + `<field>: <value>\n` lines). The
 *  same helper lives in `examples/tutorial-aptos/scripts/common.ts`; pulled
 *  inline here so the demo has no cross-package import. */
export function buildAptosWalletFullMessage(args: {
    accountAddress: AccountAddress;
    chainId: number;
    message: string;
    nonce: string;
}): string {
    return [
        'APTOS',
        `address: ${args.accountAddress.toStringLong()}`,
        `application: ${APP_ORIGIN}`,
        `chainId: ${args.chainId}`,
        `message: ${args.message}`,
        `nonce: ${args.nonce}`,
    ].join('\n');
}

// ── ACE deployment handle from the localnet config ───────────────────────────

export function aceDeploymentFromConfig(cfg: LocalnetConfig): ACE.AceDeployment {
    return new ACE.AceDeployment({
        apiEndpoint: cfg.apiEndpoint,
        contractAddr: AccountAddress.fromString(cfg.contractAddr),
    });
}

