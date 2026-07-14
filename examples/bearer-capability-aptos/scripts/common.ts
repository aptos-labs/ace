// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import * as path from 'path';
import { fileURLToPath } from 'url';
import * as readline from 'readline';
import { AccountAddress, Aptos, AptosConfig, Network, Serializer } from '@aptos-labs/ts-sdk';
import * as ACE from '@aptos-labs/ace-sdk';
import { bls12_381 } from '@noble/curves/bls12-381';
import { bytesToHex, utf8ToBytes } from '@noble/hashes/utils';

// ── Deployment target ────────────────────────────────────────────────────────
//
// Default: an explicitly configured testnet deployment. Set ACE_NETWORK=localnet
// (or use the package's *:localnet scripts) to target a local ACE network.

export const LOCALNET_CONFIG_PATH = '/tmp/ace-localnet-config.json';

export type AceNetwork = 'localnet' | 'testnet';

export interface AceConfig {
    network: AceNetwork;
    apiEndpoint: string;
    apiKey?: string;
    contractAddr: string;
    ibeKeypairId: string;
    vrfKeypairId: string;
}

function targetNetwork(): AceNetwork {
    const raw = (process.env.ACE_NETWORK ?? 'testnet').toLowerCase();
    if (raw === 'localnet' || raw === 'testnet') return raw;
    throw new Error(`Unsupported ACE_NETWORK="${raw}" (expected localnet or testnet).`);
}

function idsFromEnv(): { ibeKeypairId: string; vrfKeypairId: string } | undefined {
    const splitIds = process.env.KEYPAIR_IDS?.split(',').map(s => s.trim()).filter(Boolean);
    const ibeKeypairId = process.env.IBE_KEYPAIR_ID ?? process.env.KEYPAIR_ID ?? splitIds?.[0];
    const vrfKeypairId = process.env.VRF_KEYPAIR_ID ?? splitIds?.[1];
    if (!ibeKeypairId || !vrfKeypairId) return undefined;
    return { ibeKeypairId, vrfKeypairId };
}

/** Different localnet harnesses write slightly different schemas. Accept the
 *  old singular `keypairId` for IBE, but require an explicit VRF id so stale
 *  IBE-only configs fail before making worker requests. */
function readLocalnetConfig(): AceConfig {
    let raw: any;
    try {
        raw = JSON.parse(readFileSync(LOCALNET_CONFIG_PATH, 'utf8'));
    } catch {
        throw new Error(
            `Could not read ${LOCALNET_CONFIG_PATH}. Bring up an ACE localnet first via ` +
            `\`pnpm --filter ace-scenarios run-local-network-forever\` and wait ` +
            `until the terminal prints "ACE local network is READY".`,
        );
    }
    const splitIds = Array.isArray(raw.keypairIds) ? raw.keypairIds : undefined;
    const ibeKeypairId = raw.ibeKeypairId ?? raw.keypairId ?? splitIds?.[0];
    const vrfKeypairId = raw.vrfKeypairId ?? splitIds?.[1];
    if (!raw.apiEndpoint || !raw.contractAddr || !ibeKeypairId || !vrfKeypairId) {
        throw new Error(
            `Malformed ${LOCALNET_CONFIG_PATH}: need {apiEndpoint, contractAddr, ` +
            `ibeKeypairId, vrfKeypairId} or {apiEndpoint, contractAddr, keypairIds[]}. ` +
            `Restart \`pnpm --filter ace-scenarios run-local-network-forever\` if this file is stale.`,
        );
    }
    return { network: 'localnet', apiEndpoint: raw.apiEndpoint, contractAddr: raw.contractAddr, ibeKeypairId, vrfKeypairId };
}

export function readAceConfig(): AceConfig {
    const network = targetNetwork();
    const envIds = idsFromEnv();
    if (process.env.ACE_CONTRACT) {
        if (!envIds) {
            throw new Error('Set IBE_KEYPAIR_ID and VRF_KEYPAIR_ID when overriding ACE_CONTRACT.');
        }
        return {
            network,
            apiEndpoint: process.env.ACE_API_ENDPOINT ??
                (network === 'testnet' ? 'https://api.testnet.aptoslabs.com/v1' : 'http://localhost:8080/v1'),
            apiKey: process.env.ACE_API_KEY ?? process.env.NODE_API_KEY,
            contractAddr: process.env.ACE_CONTRACT,
            ...envIds,
        };
    }

    if (network === 'testnet') {
        const knownDeployment = ACE.knownDeployments.preview20260714.withApiKey(
            process.env.ACE_API_KEY ?? process.env.NODE_API_KEY,
        );
        return {
            network,
            apiEndpoint: process.env.ACE_API_ENDPOINT ?? knownDeployment.aceDeployment.apiEndpoint,
            apiKey: knownDeployment.aceDeployment.apiKey,
            contractAddr: knownDeployment.aceDeployment.contractAddr.toStringLong(),
            ibeKeypairId: envIds?.ibeKeypairId ?? knownDeployment.ibeKeypairId.toStringLong(),
            vrfKeypairId: envIds?.vrfKeypairId ?? knownDeployment.vrfKeypairId.toStringLong(),
        };
    }

    return readLocalnetConfig();
}

export const LOCALNET_FAUCET_URL = 'http://localhost:8081';

/** Matches `EXPECTED_APP_ORIGIN` in `capability_access.move`. */
export const APP_ORIGIN = 'https://example.com';

/** Matches `SIGNABLE_REQUEST_DST` in `capability_access.move`. */
export const SIGNABLE_REQUEST_DST = 'ACE_BEARER_CAPABILITY_v1';

/** IETF BLS-min-pubkey-size signature DST — same one
 *  `aptos_std::bls12381::verify_normal_signature` consumes, confirmed by a
 *  Move-side round-trip spike when the contract was first written. */
export const BLS_HASH_DST = 'BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_';

// ── Filesystem layout ────────────────────────────────────────────────────────

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

export const ROOT = path.join(__dirname, '..');
export const CONTRACT_DIR = path.join(ROOT, 'contract');
export const DATA_DIR = path.join(ROOT, 'data');

export const ALICE_FILE  = path.join(DATA_DIR, 'alice.json');
export const CONFIG_FILE = path.join(DATA_DIR, 'config.json');
export const CAPABILITY_FILE  = path.join(DATA_DIR, 'capability.json');

export interface AccountFile {
    address: string;
    privateKeyHex: string;
}

export interface ConfigFile {
    appContractAddr: string;
}

/** The "bearer capability" Alice hands to Bob out-of-band. Carrying the
 *  ciphertext alongside the bearer key is a convenience: in real life
 *  the ciphertext lives in object storage and the capability just points to it. */
export interface CapabilityFile {
    blobSuffix: string;
    blobIdHex: string;        // utf8 hex of `@<canon-owner>/<suffix>`
    ciphertextHex: string;
    accessPrivateKeyHex: string;   // 32-byte BLS Fr scalar hex; this is the bearer token
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

export function waitForEnter(prompt: string): Promise<void> {
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    return new Promise(resolve => rl.question(prompt, () => { rl.close(); resolve(); }));
}

// ── Faucet ───────────────────────────────────────────────────────────────────

export async function fundViaLocalnetFaucet(addr: AccountAddress, octas: number): Promise<void> {
    const r = await fetch(
        `${LOCALNET_FAUCET_URL}/mint?amount=${octas}&address=${addr.toStringLong()}`,
        { method: 'POST' },
    );
    if (!r.ok) throw new Error(`faucet ${r.status}: ${await r.text()}`);
    await new Promise(res => setTimeout(res, 1000));
}

// ── Bearer-token crypto (mirrors capability_access.move) ──────────────────────

/** Derive the BLS12-381 access keypair from 32 bytes of tVRF output.
 *  Reduces to an Fr scalar (`accessPrivateKey`) and computes
 *  `accessPublicKey = accessPrivateKey * G1`. The bias from 256-bit-mod-r
 *  reduction is ~2^-255, negligible for this use case. */
export function vrfOutputToAccessKeypair(vrfBytes: Uint8Array): {
    accessPrivateKey: bigint;
    accessPublicKey: Uint8Array;
} {
    if (vrfBytes.length !== 32) throw new Error(`vrfBytes: expected 32, got ${vrfBytes.length}`);
    const accessPrivateKey = BigInt(`0x${bytesToHex(vrfBytes)}`) % bls12_381.fields.Fr.ORDER;
    if (accessPrivateKey === 0n) throw new Error('vrfBytes reduced to the zero BLS scalar');
    const accessPublicKey = bls12_381.G1.ProjectivePoint.BASE.multiply(accessPrivateKey).toRawBytes(true);
    return { accessPrivateKey, accessPublicKey };
}

export function accessPrivateKeyToHex(accessPrivateKey: bigint): string {
    if (accessPrivateKey <= 0n || accessPrivateKey >= bls12_381.fields.Fr.ORDER) {
        throw new Error('accessPrivateKey must be a non-zero BLS Fr scalar');
    }
    return accessPrivateKey.toString(16).padStart(64, '0');
}

export function accessPrivateKeyFromHex(accessPrivateKeyHex: string): bigint {
    const normalized = accessPrivateKeyHex.startsWith('0x')
        ? accessPrivateKeyHex.slice(2)
        : accessPrivateKeyHex;
    if (!/^[0-9a-fA-F]{64}$/.test(normalized)) {
        throw new Error('accessPrivateKeyHex must be a 32-byte hex string');
    }
    const accessPrivateKey = BigInt(`0x${normalized}`);
    if (accessPrivateKey <= 0n || accessPrivateKey >= bls12_381.fields.Fr.ORDER) {
        throw new Error('accessPrivateKeyHex is not a valid non-zero BLS Fr scalar');
    }
    return accessPrivateKey;
}

/** What the bearer's `accessPrivateKey` actually signs. Mirrors the
 *  on-chain `SignableRequest` Move struct — BCS for a struct is the
 *  concatenation of its fields, and each `vector<u8>` is encoded as
 *  ULEB128(len)||bytes. */
export class SignableRequest {
    dst: Uint8Array;
    label: Uint8Array;
    userEpk: Uint8Array;
    origin: Uint8Array;

    constructor(args: { label: Uint8Array; userEpk: Uint8Array; origin: Uint8Array }) {
        this.dst = utf8ToBytes(SIGNABLE_REQUEST_DST);
        this.label = args.label;
        this.userEpk = args.userEpk;
        this.origin = args.origin;
    }

    serialize(s: Serializer): void {
        s.serializeBytes(this.dst);
        s.serializeBytes(this.label);
        s.serializeBytes(this.userEpk);
        s.serializeBytes(this.origin);
    }

    toBytes(): Uint8Array {
        const s = new Serializer();
        this.serialize(s);
        return s.toUint8Array();
    }
}

/** The `payload: vector<u8>` the worker passes opaquely to the contract.
 *  The contract bcs_stream-decodes it as `{ origin, sig }`; mirror that
 *  shape here. */
export class ReaderProof {
    origin: Uint8Array;
    sig: Uint8Array;

    constructor(args: { origin: Uint8Array; sig: Uint8Array }) {
        this.origin = args.origin;
        this.sig = args.sig;
    }

    serialize(s: Serializer): void {
        s.serializeBytes(this.origin);
        s.serializeBytes(this.sig);
    }

    toBytes(): Uint8Array {
        const s = new Serializer();
        this.serialize(s);
        return s.toUint8Array();
    }
}

export function signWithAccessPrivateKey(accessPrivateKey: bigint, msg: Uint8Array): Uint8Array {
    return (bls12_381.G2.hashToCurve(msg, { DST: BLS_HASH_DST }) as any)
        .multiply(accessPrivateKey)
        .toRawBytes(true);
}

// ── Aptos + ACE handles from config ──────────────────────────────────────────

export function aceDeploymentFromConfig(cfg: AceConfig): ACE.AceDeployment {
    return new ACE.AceDeployment({
        apiEndpoint: cfg.apiEndpoint,
        apiKey: cfg.apiKey,
        contractAddr: AccountAddress.fromString(cfg.contractAddr),
    });
}

export function aptosFromConfig(cfg: AceConfig): Aptos {
    return new Aptos(new AptosConfig({
        network: cfg.network === 'testnet' ? Network.TESTNET : Network.LOCAL,
        fullnode: cfg.apiEndpoint,
    }));
}
