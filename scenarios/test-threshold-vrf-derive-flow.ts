// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Threshold-VRF derive flow sketch for Shelby S3 bearer-token minting.
 *
 * This is intentionally a scenario/spec test, not a production implementation.
 * It pins down the user-request-handler contract we want:
 *
 *   owner signs a derivation transcript
 *   -> each ACE node authenticates owner and returns s_i * H(owner, blob)
 *   -> owner verifies shares with pairings and reconstructs s * H(owner, blob)
 *   -> owner derives an Ed25519 bearer-token account for Aptos basic flow
 *
 * The Rust handler endpoint is not implemented yet. Set
 * ACE_THRESHOLD_VRF_HANDLER_URL=http://localhost:<port>/derive-vrf-share once
 * it exists; until then this scenario only exercises the local transcript,
 * pairing, reconstruction, and token derivation semantics.
 */

import { randomBytes } from 'crypto';

import { Account, AccountAddress, Ed25519PrivateKey } from '@aptos-labs/ts-sdk';
import { bls12_381 } from '@noble/curves/bls12-381';
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from '@noble/hashes/utils';
import { sha256 } from '@noble/hashes/sha256';

import { CHAIN_ID } from './common/config';
import { assert, log } from './common/helpers';

const REQUEST_VERSION = 1;
const PURPOSE = 'ace.threshold-vrf.derive.v1';
const HASH_TO_G1_DST = 'ACE_THRESHOLD_VRF_BLS12381G1_XMD:SHA-256_SSWU_RO_';
const TOKEN_SEED_INFO = 'ace.shelby-s3.ed25519-token.v1';
const VRF_KEY_ID = 'epoch-0-secret-0';
const THRESHOLD = 3;

interface G1Point {
    add(other: G1Point): G1Point;
    multiply(scalar: bigint): G1Point;
    toRawBytes(isCompressed?: boolean): Uint8Array;
}

interface G2Point {
    multiply(scalar: bigint): G2Point;
    toRawBytes(isCompressed?: boolean): Uint8Array;
}

interface ThresholdVrfDerivePayloadV1 {
    version: 1;
    purpose: typeof PURPOSE;
    vrfKeyId: string;
    chainId: number;
    appContractAddr: string;
    ownerAddr: string;
    blobId: string;
    tokenNonceHex: string;
    sessionEncPkHex: string;
    expiresAtUnixMs: number;
}

interface AptosOwnerProofV1 {
    scheme: 'aptos';
    userAddr: string;
    pkScheme: 'ed25519';
    publicKeyHex: string;
    sigScheme: 'ed25519';
    signatureHex: string;
    fullMessage: string;
}

interface ThresholdVrfDeriveRequestV1 {
    payload: ThresholdVrfDerivePayloadV1;
    ownerProof: AptosOwnerProofV1;
}

interface ThresholdVrfShareResponseV1 {
    version: 1;
    workerIndex: number;
    evalPoint: number;
    vrfShareHex: string;
    sharePkHex: string;
}

interface MockWorkerShare {
    workerIndex: number;
    evalPoint: number;
    scalar: bigint;
    sharePk: G2Point;
}

function derivePrettyMessage(payload: ThresholdVrfDerivePayloadV1): string {
    return [
        'ACE Threshold VRF Derive Request',
        `version: ${payload.version}`,
        `purpose: ${payload.purpose}`,
        `vrfKeyId: ${payload.vrfKeyId}`,
        `chainId: ${payload.chainId}`,
        `appContractAddr: ${payload.appContractAddr}`,
        `ownerAddr: ${payload.ownerAddr}`,
        `blobId: ${payload.blobId}`,
        `tokenNonce: 0x${payload.tokenNonceHex}`,
        `sessionEncPk: 0x${payload.sessionEncPkHex}`,
        `expiresAtUnixMs: ${payload.expiresAtUnixMs}`,
    ].join('\n');
}

function vrfInputBytes(payload: ThresholdVrfDerivePayloadV1): Uint8Array {
    return sha256(concatBytes(
        utf8ToBytes('ACE_THRESHOLD_VRF_INPUT_V1'),
        utf8ToBytes(payload.vrfKeyId),
        new Uint8Array([payload.chainId]),
        AccountAddress.fromString(payload.appContractAddr).toUint8Array(),
        AccountAddress.fromString(payload.ownerAddr).toUint8Array(),
        utf8ToBytes(payload.blobId),
        hexToBytes(payload.tokenNonceHex),
    ));
}

function buildOwnerRequest(payload: ThresholdVrfDerivePayloadV1, owner: Account): ThresholdVrfDeriveRequestV1 {
    const fullMessage = derivePrettyMessage(payload);
    const messageBytes = utf8ToBytes(fullMessage);
    return {
        payload,
        ownerProof: {
            scheme: 'aptos',
            userAddr: owner.accountAddress.toStringLong(),
            pkScheme: 'ed25519',
            publicKeyHex: bytesToHex(owner.publicKey.toUint8Array()),
            sigScheme: 'ed25519',
            signatureHex: bytesToHex(owner.sign(messageBytes).toUint8Array()),
            fullMessage,
        },
    };
}

function modFr(x: bigint): bigint {
    const r = bls12_381.fields.Fr.ORDER;
    const y = x % r;
    return y >= 0n ? y : y + r;
}

function lagrangeCoefficientAtZero(evalPoint: number, allEvalPoints: number[]): bigint {
    let num = 1n;
    let den = 1n;
    const xi = BigInt(evalPoint);
    for (const xjNumber of allEvalPoints) {
        const xj = BigInt(xjNumber);
        if (xj === xi) continue;
        num = modFr(num * -xj);
        den = modFr(den * (xi - xj));
    }
    return modFr(num * bls12_381.fields.Fr.inv(den));
}

function mockSplitSecret(secret: bigint): MockWorkerShare[] {
    const coeff1 = 0x101112131415161718191a1b1c1d1e1fn;
    const coeff2 = 0x202122232425262728292a2b2c2d2e2fn;
    const g2 = bls12_381.G2.ProjectivePoint.BASE;
    return [1, 2, 3, 4].map((evalPoint, workerIndex) => {
        const x = BigInt(evalPoint);
        const scalar = modFr(secret + coeff1 * x + coeff2 * x * x);
        return {
            workerIndex,
            evalPoint,
            scalar,
            sharePk: g2.multiply(scalar) as G2Point,
        };
    });
}

function computeShareResponse(worker: MockWorkerShare, h: G1Point): ThresholdVrfShareResponseV1 {
    const share = h.multiply(worker.scalar) as G1Point;
    return {
        version: 1,
        workerIndex: worker.workerIndex,
        evalPoint: worker.evalPoint,
        vrfShareHex: bytesToHex(share.toRawBytes(true)),
        sharePkHex: bytesToHex(worker.sharePk.toRawBytes(true)),
    };
}

function parseG1(hex: string): G1Point {
    return bls12_381.G1.ProjectivePoint.fromHex(hexToBytes(hex)) as unknown as G1Point;
}

function parseG2(hex: string): G2Point {
    return bls12_381.G2.ProjectivePoint.fromHex(hexToBytes(hex)) as unknown as G2Point;
}

function verifyShare(h: G1Point, response: ThresholdVrfShareResponseV1): boolean {
    const share = parseG1(response.vrfShareHex);
    const sharePk = parseG2(response.sharePkHex);
    const lhs = bls12_381.pairing(share as any, bls12_381.G2.ProjectivePoint.BASE);
    const rhs = bls12_381.pairing(h as any, sharePk as any);
    return bls12_381.fields.Fp12.eql(lhs, rhs);
}

function reconstructVrf(responses: ThresholdVrfShareResponseV1[]): G1Point {
    const evalPoints = responses.map(r => r.evalPoint);
    let acc = bls12_381.G1.ProjectivePoint.ZERO as unknown as G1Point;
    for (const response of responses) {
        const lambda = lagrangeCoefficientAtZero(response.evalPoint, evalPoints);
        acc = acc.add(parseG1(response.vrfShareHex).multiply(lambda));
    }
    return acc as G1Point;
}

function verifyFullVrf(h: G1Point, vrf: G1Point, groupPk: G2Point): boolean {
    const lhs = bls12_381.pairing(vrf as any, bls12_381.G2.ProjectivePoint.BASE);
    const rhs = bls12_381.pairing(h as any, groupPk as any);
    return bls12_381.fields.Fp12.eql(lhs, rhs);
}

function deriveTokenAccount(vrf: G1Point, request: ThresholdVrfDeriveRequestV1): {
    account: Account;
    privateKeyHex: string;
} {
    const seed = sha256(concatBytes(
        utf8ToBytes(TOKEN_SEED_INFO),
        vrf.toRawBytes(true),
        AccountAddress.fromString(request.payload.ownerAddr).toUint8Array(),
        utf8ToBytes(request.payload.blobId),
        hexToBytes(request.payload.tokenNonceHex),
    ));
    return {
        account: Account.fromPrivateKey({ privateKey: new Ed25519PrivateKey(seed) }),
        privateKeyHex: `0x${bytesToHex(seed)}`,
    };
}

async function maybeExerciseFutureHandler(request: ThresholdVrfDeriveRequestV1): Promise<void> {
    const url = process.env.ACE_THRESHOLD_VRF_HANDLER_URL;
    if (!url) {
        log('Rust threshold-VRF user request handler is not implemented yet.');
        log('Skipping network call. Set ACE_THRESHOLD_VRF_HANDLER_URL to exercise POST /derive-vrf-share later.');
        return;
    }

    const response = await fetch(url, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(request),
    });
    assert(response.ok, `future handler returned ${response.status}`);
}

async function main() {
    const owner = Account.generate();
    const appContractAddr = AccountAddress.fromString(`0x${'0'.repeat(60)}0ace`).toStringLong();
    const blobId = 'shelby-s3://owner-bucket/contracts/acquisition-plan.txt';
    const payload: ThresholdVrfDerivePayloadV1 = {
        version: REQUEST_VERSION,
        purpose: PURPOSE,
        vrfKeyId: VRF_KEY_ID,
        chainId: CHAIN_ID,
        appContractAddr,
        ownerAddr: owner.accountAddress.toStringLong(),
        blobId,
        tokenNonceHex: bytesToHex(randomBytes(16)),
        sessionEncPkHex: bytesToHex(randomBytes(32)),
        expiresAtUnixMs: Date.now() + 5 * 60_000,
    };
    const request = buildOwnerRequest(payload, owner);
    const input = vrfInputBytes(payload);
    const h = bls12_381.G1.hashToCurve(input, { DST: HASH_TO_G1_DST }) as unknown as G1Point;

    log('Pinned threshold-VRF derive request transcript.');
    console.log(request.ownerProof.fullMessage);

    const masterSecret = modFr(0x4242424242424242424242424242424242424242424242424242424242424242n);
    const groupPk = bls12_381.G2.ProjectivePoint.BASE.multiply(masterSecret) as unknown as G2Point;
    const workers = mockSplitSecret(masterSecret);
    const responses = workers.map(worker => computeShareResponse(worker, h));

    const accepted = responses.slice(0, THRESHOLD);
    for (const response of accepted) {
        assert(verifyShare(h, response), `share ${response.workerIndex} pairing verification`);
    }

    const vrf = reconstructVrf(accepted);
    assert(verifyFullVrf(h, vrf, groupPk), 'reconstructed VRF verifies against group public key');

    const token = deriveTokenAccount(vrf, request);
    log(`Derived Aptos bearer-token address: ${token.account.accountAddress.toStringLong()}`);
    log(`Derived token private key seed: ${token.privateKeyHex}`);
    log('Expected downstream use: owner allowlists token address; reader signs Aptos basic-flow decrypt requests with token private key.');

    await maybeExerciseFutureHandler(request);
}

main().catch(err => { console.error(err); process.exit(1); });
