// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * ACE Worker v2 — threshold IBE mode.
 *
 * Reads cryptographic state from an on-chain ACE network contract and a local
 * SQLite DB. Uses dummy DKG/DKR: the master scalar r is stored on-chain
 * (INSECURE: for testing purposes only), allowing each worker to deterministically
 * derive its Shamir share.
 */

import {
    Account,
    Aptos,
    AptosConfig,
    Ed25519PrivateKey,
    Network,
} from '@aptos-labs/ts-sdk';
import { ace, threshold_ibe, ace_threshold } from '@aptos-labs/ace-sdk';
import { WeierstrassPoint } from '@noble/curves/abstract/weierstrass';
import { bls12_381 } from '@noble/curves/bls12-381';
import { bytesToNumberBE, bytesToNumberLE, numberToBytesLE } from '@noble/curves/utils';
import { bytesToHex, hexToBytes, randomBytes } from '@noble/hashes/utils';
import { sha3_256 } from '@noble/hashes/sha3';
import express, { Request, Response } from 'express';
import cors from 'cors';
import { randomUUID } from 'crypto';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import * as path from 'path';

// ============================================================================
// Options
// ============================================================================

export interface Options {
    port: number;
    rpcUrl: string;
    keypairPath?: string;
    privateKey?: string;
    aceContract: string;
}

// ============================================================================
// Key share store (JSON file)
// ============================================================================

interface KeyShare {
    scalar_share_hex: string;
    base_hex: string;
    acquired_at_epoch: number;
}

type ShareStore = Record<string, KeyShare>;

function loadStore(storePath: string): ShareStore {
    if (!existsSync(storePath)) return {};
    return JSON.parse(readFileSync(storePath, 'utf-8')) as ShareStore;
}

function saveStore(storePath: string, store: ShareStore): void {
    writeFileSync(storePath, JSON.stringify(store, null, 2));
}

function storeKeyShare(
    storePath: string,
    secretId: number,
    scalarShareHex: string,
    baseHex: string,
    acquiredAtEpoch: number,
): void {
    const store = loadStore(storePath);
    store[String(secretId)] = { scalar_share_hex: scalarShareHex, base_hex: baseHex, acquired_at_epoch: acquiredAtEpoch };
    saveStore(storePath, store);
}

// ============================================================================
// Fr arithmetic for deterministic share derivation (dummy mode)
// ============================================================================

const FR_MODULUS = 0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001n;

function frMod(a: bigint): bigint {
    return ((a % FR_MODULUS) + FR_MODULUS) % FR_MODULUS;
}

/**
 * Derive Shamir polynomial coefficient a_k deterministically.
 * a_k = sha3_256(r_le32 || epoch_le8 || k_le4) mod Fr
 */
function deriveCoefficient(rBytes: Uint8Array, epoch: number, k: number): bigint {
    const epochBuf = new Uint8Array(8);
    new DataView(epochBuf.buffer).setBigUint64(0, BigInt(epoch), true);
    const kBuf = new Uint8Array(4);
    new DataView(kBuf.buffer).setUint32(0, k, true);
    const input = new Uint8Array(rBytes.length + 8 + 4);
    input.set(rBytes, 0);
    input.set(epochBuf, rBytes.length);
    input.set(kBuf, rBytes.length + 8);
    return frMod(bytesToNumberLE(sha3_256(input)));
}

/**
 * Compute Shamir share f(workerIndex):
 *   f(x) = r + a_1·x + ... + a_{t-1}·x^{t-1}  (all mod Fr)
 *   a_k = KDF(r, epoch, k)
 */
function computeShare(rBytes: Uint8Array, epoch: number, threshold: number, workerIndex: number): bigint {
    const r = frMod(bytesToNumberLE(rBytes));
    const x = BigInt(workerIndex);
    let y = r;
    let xPow = x;
    for (let k = 1; k < threshold; k++) {
        const ak = deriveCoefficient(rBytes, epoch, k);
        y = frMod(y + frMod(ak * xPow));
        xPow = frMod(xPow * x);
    }
    return y;
}

// ============================================================================
// On-chain interaction helpers
// ============================================================================

function createAptos(rpcUrl: string): Aptos {
    return new Aptos(new AptosConfig({ network: Network.CUSTOM, fullnode: rpcUrl }));
}

async function callView(aptos: Aptos, contractAddr: string, fn: string, extraArgs: any[]): Promise<any[]> {
    return aptos.view({
        payload: {
            function: `${contractAddr}::ace_network::${fn}` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [contractAddr, ...extraArgs],
        },
    });
}

async function submitTxn(
    aptos: Aptos,
    account: Account,
    contractAddr: string,
    fn: string,
    args: any[],
): Promise<void> {
    const txn = await aptos.transaction.build.simple({
        sender: account.accountAddress,
        data: {
            function: `${contractAddr}::ace_network::${fn}` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: args,
        },
    });
    const pending = await aptos.signAndSubmitTransaction({ signer: account, transaction: txn });
    await aptos.waitForTransaction({ transactionHash: pending.hash });
}

function sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================================
// DKG processing (dummy mode)
// ============================================================================

async function processDkg(
    aptos: Aptos,
    account: Account,
    storePath: string,
    contractAddr: string,
    myAddress: string,
    myIndex: number,
    epochNum: number,
    nodes: string[],
    threshold: number,
): Promise<void> {
    const [hasPending, dkgIdStr] = await callView(aptos, contractAddr, 'get_pending_dkg', []);
    if (!hasPending) return;
    const dkgId = Number(dkgIdStr);

    const secretCountBefore = Number((await callView(aptos, contractAddr, 'get_secret_count', []))[0]);

    // Check if we already have this secret's share
    const store = loadStore(storePath);
    if (store[String(secretCountBefore)]) return; // Already processed

    // Elected node: lexicographically smallest address in the committee
    const sortedNodes = [...nodes].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
    const isDealer = myAddress.toLowerCase() === sortedNodes[0].toLowerCase();

    if (isDealer) {
        // Generate (base, r, MPK) and contribute final blob
        const basePoint = bls12_381.G1.hashToCurve(randomBytes(32)) as unknown as WeierstrassPoint<bigint>;
        const rBE = bls12_381.utils.randomSecretKey();
        const r = bytesToNumberBE(rBE);
        const mpkPoint = basePoint.multiply(r);

        const baseBytes = basePoint.toBytes();   // 48 bytes
        const mpkBytes = mpkPoint.toBytes();     // 48 bytes
        const rLE = numberToBytesLE(r, 32);      // 32 bytes

        // [0x01][mpk_48][base_48][r_32] = 129 bytes
        const contribution = new Uint8Array(129);
        contribution[0] = 0x01;
        contribution.set(mpkBytes, 1);
        contribution.set(baseBytes, 49);
        contribution.set(rLE, 97);

        console.log(`[DKG] dealer contributing final blob for dkg_id=${dkgId}`);
        await submitTxn(aptos, account, contractAddr, 'contribute_to_dkg', [dkgId, Array.from(contribution)]);
    }

    // Wait for secret to appear on-chain
    for (let i = 0; i < 30; i++) {
        await sleep(1000);
        const count = Number((await callView(aptos, contractAddr, 'get_secret_count', []))[0]);
        if (count > secretCountBefore) break;
    }

    await deriveAndStoreShare(aptos, storePath, contractAddr, secretCountBefore, epochNum, threshold, myIndex);
}

async function deriveAndStoreShare(
    aptos: Aptos,
    storePath: string,
    contractAddr: string,
    secretId: number,
    epochNum: number,
    threshold: number,
    myIndex: number,
): Promise<void> {
    const [, baseHex, , dummySecretHex] = await callView(aptos, contractAddr, 'get_secret', [secretId]);
    const rBytes = hexToBytes((dummySecretHex as string).replace('0x', ''));
    const scalarShare = computeShare(rBytes, epochNum, threshold, myIndex);
    const scalarShareHex = bytesToHex(numberToBytesLE(scalarShare, 32));
    const baseHexClean = (baseHex as string).replace('0x', '');
    storeKeyShare(storePath, secretId, scalarShareHex, baseHexClean, epochNum);
    console.log(`[DKG] share acquired for secret_id=${secretId} at epoch=${epochNum}`);
}

// ============================================================================
// Epoch change processing (dummy mode)
// ============================================================================

async function processEpochChange(
    aptos: Aptos,
    account: Account,
    storePath: string,
    contractAddr: string,
    myAddress: string,
    epochNum: number,
    nodes: string[],
): Promise<void> {
    const [hasPending, epochChangeIdStr] = await callView(aptos, contractAddr, 'get_pending_epoch_change', []);
    if (!hasPending) return;
    const epochChangeId = Number(epochChangeIdStr);

    const pendingRaw = await callView(aptos, contractAddr, 'get_pending_resharing_secret_ids', [epochChangeId]);
    const pendingSecretIds = (pendingRaw[0] as any[]).map(Number);
    if (pendingSecretIds.length === 0) return;

    const sortedNodes = [...nodes].sort((a, b) => a.toLowerCase().localeCompare(b.toLowerCase()));
    const isDealer = myAddress.toLowerCase() === sortedNodes[0].toLowerCase();

    if (isDealer) {
        for (const secretId of pendingSecretIds) {
            // Final contribution: [0x01] — "done" marker
            console.log(`[EpochChange] contributing done for secret_id=${secretId}`);
            await submitTxn(aptos, account, contractAddr, 'contribute_to_epoch_change', [
                epochChangeId, secretId, [0x01],
            ]);
        }
    }

    // Wait for epoch to increment, then re-derive shares
    for (let i = 0; i < 30; i++) {
        await sleep(1000);
        const [newEpochNumStr, newNodes, newThresholdStr] = await callView(aptos, contractAddr, 'get_current_epoch', []);
        const newEpochNum = Number(newEpochNumStr);
        if (newEpochNum > epochNum) {
            const newThreshold = Number(newThresholdStr);
            const newNodeList = newNodes as string[];
            const myNewIndex = newNodeList.findIndex(n => n.toLowerCase() === myAddress.toLowerCase()) + 1;
            if (myNewIndex > 0) {
                const secretCount = Number((await callView(aptos, contractAddr, 'get_secret_count', []))[0]);
                const store = loadStore(storePath);
                for (let sid = 0; sid < secretCount; sid++) {
                    const existing = store[String(sid)];
                    if (existing && existing.acquired_at_epoch === newEpochNum) continue;
                    await deriveAndStoreShare(aptos, storePath, contractAddr, sid, newEpochNum, newThreshold, myNewIndex);
                }
            }
            break;
        }
    }
}

// ============================================================================
// Background poller
// ============================================================================

async function poll(
    aptos: Aptos,
    account: Account,
    storePath: string,
    contractAddr: string,
    myAddress: string,
): Promise<void> {
    try {
        const [epochNumStr, nodes, thresholdStr] = await callView(aptos, contractAddr, 'get_current_epoch', []);
        const epochNum = Number(epochNumStr);
        const nodeList = nodes as string[];
        const threshold = Number(thresholdStr);
        const myIndex = nodeList.findIndex(n => n.toLowerCase() === myAddress.toLowerCase()) + 1;
        if (myIndex === 0) {
            console.log(`[poller] epoch=${epochNum} nodeList=${JSON.stringify(nodeList)} myAddress=${myAddress} → not in committee, skipping`);
            return;
        }

        await processDkg(aptos, account, storePath, contractAddr, myAddress, myIndex, epochNum, nodeList, threshold);
        await processEpochChange(aptos, account, storePath, contractAddr, myAddress, epochNum, nodeList);
    } catch (err) {
        console.error(`[poller] error: ${err}`);
    }
}

// ============================================================================
// HTTP request handler
// ============================================================================

function createRequestHandler(
    storePath: string,
    aptos: Aptos,
    contractAddr: string,
    myAddress: string,
    rpcConfig: ace.RpcConfig,
) {
    return async (req: Request, res: Response): Promise<void> => {
        const sessionId = randomUUID().slice(0, 8);
        console.log(`[${sessionId}] BEGIN`);

        // Parse request
        let request: ace.RequestForDecryptionKey;
        try {
            const bodyHex = typeof req.body === 'string' ? req.body : String(req.body);
            const parseResult = ace.RequestForDecryptionKey.fromHex(bodyHex);
            if (!parseResult.isOk) throw parseResult.errValue;
            request = parseResult.okValue!;
        } catch (err) {
            console.warn(`[${sessionId}] DENIED: parse error: ${err}`);
            res.status(400).send('Could not parse request.');
            return;
        }

        try {
            // Only Aptos scheme supported in v2
            if (request.contractId.scheme !== ace.ContractID.SCHEME_APTOS || request.proof.scheme !== 0) {
                console.warn(`[${sessionId}] DENIED: unsupported scheme`);
                res.status(400).send('Only Aptos scheme supported in v2');
                return;
            }

            const fullDecryptionDomain = new ace.FullDecryptionDomain({
                contractId: request.contractId,
                domain: request.domain,
            });

            // Verify permission via ACE Aptos mechanism
            const verifyResult = await ace_threshold.verifyAptosPermission({
                fullDecryptionDomain,
                proof: request.proof.inner as ace.AptosProofOfPermission,
                rpcEndpoint: rpcConfig?.aptos?.localnet?.endpoint,
            });
            if (!verifyResult.isOk) {
                console.warn(`[${sessionId}] DENIED: ${verifyResult.errValue}`);
                console.warn(`[${sessionId}] extra: ${JSON.stringify(verifyResult.extra, null, 2)}`);
                res.status(400).send('Permission denied');
                return;
            }

            // Get my index in the current committee
            const [, nodeList] = await callView(aptos, contractAddr, 'get_current_epoch', []);
            const myIndex = (nodeList as string[]).findIndex(n => n.toLowerCase() === myAddress.toLowerCase()) + 1;
            if (myIndex === 0) {
                res.status(400).send('Worker not in committee');
                return;
            }

            // Load key share (use latest active secret)
            const secretCount = Number((await callView(aptos, contractAddr, 'get_secret_count', []))[0]);
            if (secretCount === 0) {
                res.status(503).send('No secrets available yet');
                return;
            }
            const secretId = secretCount - 1;
            const store = loadStore(storePath);
            const row = store[String(secretId)];
            if (!row) {
                res.status(503).send('Key share not yet derived');
                return;
            }

            const scalarShare = bytesToNumberLE(hexToBytes(row.scalar_share_hex));
            const base = bls12_381.G1.Point.fromBytes(hexToBytes(row.base_hex)) as unknown as WeierstrassPoint<bigint>;
            const keyShare = new threshold_ibe.MasterKeyShare(base, scalarShare, myIndex);

            const partial = threshold_ibe.partialExtract(keyShare, fullDecryptionDomain.toBytes());
            console.log(`[${sessionId}] APPROVED (workerIndex=${myIndex})`);
            res.status(200).send(partial.toHex());
        } catch (err) {
            console.error(`[${sessionId}] ERROR: ${err}`);
            res.status(500).send('Internal error');
        }
    };
}

// ============================================================================
// Registration
// ============================================================================

async function ensureRegistered(
    aptos: Aptos,
    account: Account,
    contractAddr: string,
    endpoint: string,
): Promise<void> {
    try {
        await callView(aptos, contractAddr, 'get_node_endpoint', [account.accountAddress.toStringLong()]);
        console.log('Node already registered.');
        return;
    } catch {
        // Not registered yet
    }
    console.log(`Registering node with endpoint=${endpoint}...`);
    await submitTxn(aptos, account, contractAddr, 'register_node', [endpoint]);
    console.log('Node registered.');
}

// ============================================================================
// Main entry point
// ============================================================================

export async function run(options: Options): Promise<void> {
    const rawKey = options.privateKey ?? (options.keypairPath ? readFileSync(options.keypairPath, 'utf-8').trim() : null);
    if (!rawKey) throw new Error('Either --keypair or ACE_WORKER_V2_PRIVATE_KEY must be provided');

    const privateKey = new Ed25519PrivateKey(rawKey.replace('0x', ''));
    const account = Account.fromPrivateKey({ privateKey });
    const myAddress = account.accountAddress.toStringLong();

    const aptos = createAptos(options.rpcUrl);
    const contractAddr = options.aceContract.startsWith('0x') ? options.aceContract : `0x${options.aceContract}`;
    const endpoint = `http://localhost:${options.port}`;
    const storePath = path.join(process.cwd(), `worker_shares_${options.port}.json`);

    console.log(`ACE Worker v2`);
    console.log(`  Address:  ${myAddress}`);
    console.log(`  Endpoint: ${endpoint}`);
    console.log(`  Contract: ${contractAddr}`);
    console.log(`  Store:    ${storePath}`);

    const rpcConfig: ace.RpcConfig = {
        aptos: { localnet: { endpoint: options.rpcUrl } },
    };

    await ensureRegistered(aptos, account, contractAddr, endpoint);
    await poll(aptos, account, storePath, contractAddr, myAddress);

    setInterval(() => {
        poll(aptos, account, storePath, contractAddr, myAddress).catch(console.error);
    }, 5000);

    const app = express();
    app.use(cors());
    app.use(express.text());

    app.post('/', createRequestHandler(storePath, aptos, contractAddr, myAddress, rpcConfig));

    app.get('/ibe_mpk', async (_req, res) => {
        try {
            const [mpkHex] = await callView(aptos, contractAddr, 'get_secret', [0]);
            res.status(200).send((mpkHex as string).replace('0x', ''));
        } catch {
            res.status(503).send('MPK not yet available');
        }
    });

    app.get('/health', (_req, res) => {
        res.status(200).json({ status: 'ok', address: myAddress, timestamp: Date.now() });
    });

    app.get('/', (_req, res) => res.status(200).send('ACE Worker v2 OK'));

    app.listen(options.port, () => {
        console.log(`ACE Worker v2 listening on port ${options.port}`);
    });
}
