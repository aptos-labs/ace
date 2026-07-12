// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import {
    AccountAddress,
    AccountPublicKey,
    AnyPublicKey,
    AnySignature,
    Deserializer,
    PublicKey,
    Secp256r1PublicKey,
    Serializer,
    Signature,
    WebAuthnSignature,
} from "@aptos-labs/ts-sdk";
import { bls12_381 } from "@noble/curves/bls12-381";
import { bytesToNumberBE } from "@noble/curves/utils";
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { sha512 } from "@noble/hashes/sha512";
import { sha3_256 } from "@noble/hashes/sha3";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

import * as dkg from "../dkg";
import * as dkr from "../dkr";
import * as pke from "../pke";
import * as group from "../group";
import {
    AceDeployment,
    ContractID,
    createAptos,
    fetchNetworkState,
    NetworkState,
    WorkerRequest,
} from "../_internal/common";
import { getPublicKeyScheme, getSignatureScheme } from "../_internal/aptos";
import { PcsPublicParams, PublicPoint } from "../vss";
import { FR_MODULUS, frInv, frMod, frMul } from "../group/bls12381fr";

export { buildAptosWalletFullMessage } from "../_internal/aptos-wallet-message";

export const PURPOSE = "ace.threshold-vrf.derive.v1";

export interface RequestToSignArgs {
    aceDeployment: AceDeployment;
    keypairId: AccountAddress;
    contractId: ContractID;
    label: Uint8Array;
    accountAddress: AccountAddress;
}

export class ThresholdVrfRequestPayload {
    keypairId: AccountAddress;
    epoch: number;
    contractId: ContractID;
    label: Uint8Array;
    accountAddress: AccountAddress;
    responseEncKey: pke.EncryptionKey;

    constructor(args: {
        keypairId: AccountAddress,
        epoch: number,
        contractId: ContractID,
        label: Uint8Array,
        accountAddress: AccountAddress,
        responseEncKey: pke.EncryptionKey,
    }) {
        this.keypairId = args.keypairId;
        this.epoch = args.epoch;
        this.contractId = args.contractId;
        this.label = args.label;
        this.accountAddress = args.accountAddress;
        this.responseEncKey = args.responseEncKey;
    }

    serialize(serializer: Serializer): void {
        this.keypairId.serialize(serializer);
        serializer.serializeU64(BigInt(this.epoch));
        this.contractId.serialize(serializer);
        serializer.serializeBytes(this.label);
        this.accountAddress.serialize(serializer);
        this.responseEncKey.serialize(serializer);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    static deserialize(deserializer: Deserializer): ThresholdVrfRequestPayload {
        const keypairId = AccountAddress.deserialize(deserializer);
        const epoch = Number(deserializer.deserializeU64());
        const contractId = ContractID.deserialize(deserializer)
            .unwrapOrThrow("ThresholdVrfRequestPayload.deserialize: contractId");
        const label = deserializer.deserializeBytes();
        const accountAddress = AccountAddress.deserialize(deserializer);
        const responseEncKey = pke.EncryptionKey.deserialize(deserializer)
            .unwrapOrThrow("ThresholdVrfRequestPayload.deserialize: responseEncKey");
        return new ThresholdVrfRequestPayload({
            keypairId, epoch, contractId, label, accountAddress, responseEncKey,
        });
    }

    static fromBytes(bytes: Uint8Array): ThresholdVrfRequestPayload {
        const deserializer = new Deserializer(bytes);
        const payload = ThresholdVrfRequestPayload.deserialize(deserializer);
        if (deserializer.remaining() !== 0) {
            throw new Error("ThresholdVrfRequestPayload.fromBytes: trailing bytes");
        }
        return payload;
    }

    toWebAuthnChallenge(): Uint8Array {
        const seed = sha3_256(new TextEncoder().encode("ACE::ThresholdVrfRequestPayload"));
        const body = this.toBytes();
        const preimage = new Uint8Array(seed.length + body.length);
        preimage.set(seed, 0);
        preimage.set(body, seed.length);
        return sha3_256(preimage);
    }

    toVrfInputBytes(): Uint8Array {
        const serializer = new Serializer();
        serializer.serializeStr("ace.threshold-vrf.input.v1");
        this.keypairId.serialize(serializer);
        this.contractId.serialize(serializer);
        serializer.serializeBytes(this.label);
        return serializer.toUint8Array();
    }
}

export class AptosAccountSignatureProof {
    userAddr: AccountAddress;
    publicKeyScheme: number;
    publicKey: AccountPublicKey;
    signatureScheme: number;
    signature: Signature;
    fullMessage: string;

    constructor(args: {
        userAddr: AccountAddress,
        publicKey: PublicKey,
        signature: Signature,
        fullMessage: string,
    }) {
        this.userAddr = args.userAddr;
        this.publicKey = args.publicKey as AccountPublicKey;
        this.signature = args.signature;
        this.fullMessage = args.fullMessage;
        this.publicKeyScheme = getPublicKeyScheme(args.publicKey);
        this.signatureScheme = getSignatureScheme(args.signature);
    }

    serialize(serializer: Serializer): void {
        this.userAddr.serialize(serializer);
        serializer.serializeU8(this.publicKeyScheme);
        serializer.serialize(this.publicKey);
        serializer.serializeU8(this.signatureScheme);
        serializer.serialize(this.signature);
        serializer.serializeStr(this.fullMessage);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }
}

export class ThresholdVrfRequest {
    payload: ThresholdVrfRequestPayload;
    authProof: AptosAccountSignatureProof;

    constructor(args: { payload: ThresholdVrfRequestPayload, authProof: AptosAccountSignatureProof }) {
        this.payload = args.payload;
        this.authProof = args.authProof;
    }

    serialize(serializer: Serializer): void {
        this.payload.serialize(serializer);
        this.authProof.serialize(serializer);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }
}

export class ThresholdVrfShare {
    evalPoint: number;
    share: group.Element;
    proof: ThresholdVrfShareProof;

    constructor(args: { evalPoint: number, share: group.Element, proof: ThresholdVrfShareProof }) {
        this.evalPoint = args.evalPoint;
        this.share = args.share;
        this.proof = args.proof;
    }

    static deserialize(deserializer: Deserializer): ThresholdVrfShare {
        const evalPoint = Number(deserializer.deserializeU64());
        const share = group.Element.deserialize(deserializer)
            .unwrapOrThrow("ThresholdVrfShare.deserialize: parse share");
        const proof = ThresholdVrfShareProof.deserialize(deserializer);
        return new ThresholdVrfShare({ evalPoint, share, proof });
    }

    static fromBytes(bytes: Uint8Array): ThresholdVrfShare {
        const deserializer = new Deserializer(bytes);
        const share = ThresholdVrfShare.deserialize(deserializer);
        if (deserializer.remaining() !== 0) {
            throw new Error("ThresholdVrfShare.fromBytes: trailing bytes");
        }
        return share;
    }
}

export class ThresholdVrfShareProof {
    commitmentNonce: group.Element;
    vrfNonce: group.Element;
    zSecret: group.Scalar;
    zBlinding: group.Scalar;

    constructor(args: {
        commitmentNonce: group.Element,
        vrfNonce: group.Element,
        zSecret: group.Scalar,
        zBlinding: group.Scalar,
    }) {
        this.commitmentNonce = args.commitmentNonce;
        this.vrfNonce = args.vrfNonce;
        this.zSecret = args.zSecret;
        this.zBlinding = args.zBlinding;
    }

    static deserialize(deserializer: Deserializer): ThresholdVrfShareProof {
        const commitmentNonce = group.Element.deserialize(deserializer)
            .unwrapOrThrow("ThresholdVrfShareProof.deserialize: commitmentNonce");
        const vrfNonce = group.Element.deserialize(deserializer)
            .unwrapOrThrow("ThresholdVrfShareProof.deserialize: vrfNonce");
        const zSecret = group.Scalar.deserialize(deserializer)
            .unwrapOrThrow("ThresholdVrfShareProof.deserialize: zSecret");
        const zBlinding = group.Scalar.deserialize(deserializer)
            .unwrapOrThrow("ThresholdVrfShareProof.deserialize: zBlinding");
        return new ThresholdVrfShareProof({
            commitmentNonce,
            vrfNonce,
            zSecret,
            zBlinding,
        });
    }
}

async function fetchCurrentNodeInfos(
    aceDeployment: AceDeployment,
    networkState: NetworkState,
): Promise<Array<{ nodeAddr: string, endpoint: string, nodeEncKey: pke.EncryptionKey }>> {
    const aptos = createAptos(aceDeployment.apiEndpoint, aceDeployment.apiKey);
    const aceContractAddr = aceDeployment.contractAddr.toStringLong();

    return Promise.all(networkState.curNodes.map(async (nodeAddr) => {
        const addrStr = nodeAddr.toStringLong();
        const [[endpoint], [ekHex]] = await Promise.all([
            aptos.view({
                payload: {
                    function: `${aceContractAddr}::worker_config::get_client_endpoint` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [addrStr],
                },
            }),
            aptos.view({
                payload: {
                    function: `${aceContractAddr}::worker_config::get_pke_enc_key_bcs` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [addrStr],
                },
            }),
        ]);
        const nodeEncKey = pke.EncryptionKey.fromBytes(hexToBytes((ekHex as string).replace(/^0x/, "")))
            .unwrapOrThrow(`ACE.VRF_Aptos: parse pke enc key for ${addrStr}`);
        return { nodeAddr: addrStr, endpoint: endpoint as string, nodeEncKey };
    }));
}

async function fetchCurrentSessionCommitments(
    aceDeployment: AceDeployment,
    networkState: NetworkState,
    keypairId: AccountAddress,
): Promise<{ pcsContext: PcsPublicParams, shareCommitments: PublicPoint[] }> {
    const aptos = createAptos(aceDeployment.apiEndpoint, aceDeployment.apiKey);
    const aceContractAddr = aceDeployment.contractAddr.toStringLong();
    const keypairIdStr = keypairId.toStringLong();
    const secret = networkState.secrets.find(s => s.keypairId.toStringLong() === keypairIdStr);
    if (secret === undefined) {
        throw new Error(`ACE.VRF_Aptos: keypairId ${keypairIdStr} not found in network state secrets`);
    }
    const isInitialDkg = secret.currentSession.toStringLong() === keypairIdStr;
    const sessionFn = isInitialDkg ? "dkg::get_session_bcs" : "dkr::get_session_bcs";
    const [hexBytes] = await aptos.view({
        payload: {
            function: `${aceContractAddr}::${sessionFn}` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [secret.currentSession.toStringLong()],
        },
    });
    const sessionBytes = hexToBytes((hexBytes as string).replace(/^0x/, ""));
    if (isInitialDkg) {
        const session = dkg.Session.fromBytes(sessionBytes)
            .unwrapOrThrow("ACE.VRF_Aptos: parse DKG session");
        return { pcsContext: session.pcsContext, shareCommitments: session.shareCommitments };
    }
    const session = dkr.Session.fromBytes(sessionBytes)
        .unwrapOrThrow("ACE.VRF_Aptos: parse DKR session");
    return { pcsContext: session.pcsContext, shareCommitments: session.shareCommitments };
}

const DST_THRESHOLD_VRF_G1 = new TextEncoder().encode("ACE_THRESHOLD_VRF_BLS12381G1/HASH_TO_CURVE/v1");
const THRESHOLD_VRF_SHARE_PROOF_PURPOSE = "ace.threshold-vrf.share-proof.v1";

function scalarForScheme(scheme: number, value: bigint): group.Scalar {
    const scalar = frMod(value);
    if (scheme === group.SCHEME_BLS12381G1) {
        return new group.Scalar(
            scheme,
            group.bls12381G1.PrivateScalar.fromBigint(scalar)
                .unwrapOrThrow("scalarForScheme: G1 scalar"),
        );
    }
    if (scheme === group.SCHEME_BLS12381G2) {
        return new group.Scalar(
            scheme,
            group.bls12381G2.PrivateScalar.fromBigint(scalar)
                .unwrapOrThrow("scalarForScheme: G2 scalar"),
        );
    }
    throw new Error(`scalarForScheme: unsupported scheme ${scheme}`);
}

function thresholdVrfInputElement(payload: ThresholdVrfRequestPayload): group.Element {
    const q = bls12_381.G1.hashToCurve(payload.toVrfInputBytes(), { DST: DST_THRESHOLD_VRF_G1 }) as any;
    return group.Element.fromBls12381G1(new group.bls12381G1.PublicPoint(q));
}

function thresholdVrfShareProofChallenge(args: {
    payload: ThresholdVrfRequestPayload,
    evalPoint: number,
    pcsContext: PcsPublicParams,
    shareCommitment: PublicPoint,
    inputElement: group.Element,
    share: ThresholdVrfShare,
}): bigint {
    const { payload, evalPoint, pcsContext, shareCommitment, inputElement, share } = args;
    const serializer = new Serializer();
    serializer.serializeStr(THRESHOLD_VRF_SHARE_PROOF_PURPOSE);
    payload.keypairId.serialize(serializer);
    payload.contractId.serialize(serializer);
    serializer.serializeBytes(payload.label);
    serializer.serializeU64(BigInt(evalPoint));
    pcsContext.generatorG.serialize(serializer);
    pcsContext.generatorH.serialize(serializer);
    shareCommitment.serialize(serializer);
    inputElement.serialize(serializer);
    share.share.serialize(serializer);
    share.proof.commitmentNonce.serialize(serializer);
    share.proof.vrfNonce.serialize(serializer);
    return bytesToNumberBE(sha512(serializer.toUint8Array())) % FR_MODULUS;
}

function verifyThresholdVrfShare(args: {
    share: ThresholdVrfShare,
    sdkIdx: number,
    payload: ThresholdVrfRequestPayload,
    pcsContext: PcsPublicParams,
    shareCommitment: PublicPoint,
    nodeAddr: string,
    endpoint: string,
}): boolean {
    const { share, sdkIdx, payload, pcsContext, shareCommitment, nodeAddr, endpoint } = args;
    const expectedEval = sdkIdx + 1;
    if (share.evalPoint !== expectedEval) {
        console.log(`  [tVRF] worker ${nodeAddr} (${endpoint}): evalPoint mismatch (got ${share.evalPoint}, expected ${expectedEval})`);
        return false;
    }
    if (share.share.scheme !== group.SCHEME_BLS12381G1) {
        console.log(`  [tVRF] worker ${nodeAddr} (${endpoint}): share scheme mismatch (got ${share.share.scheme}, expected G1)`);
        return false;
    }
    if (pcsContext.generatorG.scheme !== group.SCHEME_BLS12381G2
        || pcsContext.generatorH.scheme !== group.SCHEME_BLS12381G2
        || shareCommitment.scheme !== group.SCHEME_BLS12381G2) {
        console.log(`  [tVRF] worker ${nodeAddr} (${endpoint}): PCS context/share commitment are not G2`);
        return false;
    }
    if (share.proof.commitmentNonce.scheme !== group.SCHEME_BLS12381G2
        || share.proof.vrfNonce.scheme !== group.SCHEME_BLS12381G1
        || share.proof.zSecret.scheme !== group.SCHEME_BLS12381G2
        || share.proof.zBlinding.scheme !== group.SCHEME_BLS12381G2) {
        console.log(`  [tVRF] worker ${nodeAddr} (${endpoint}): proof scheme mismatch`);
        return false;
    }

    try {
        const inputElement = thresholdVrfInputElement(payload);
        const c = thresholdVrfShareProofChallenge({
            payload,
            evalPoint: share.evalPoint,
            pcsContext,
            shareCommitment,
            inputElement,
            share,
        });
        const zSecret = share.proof.zSecret.asBls12381G2().scalar;
        const zBlinding = share.proof.zBlinding.asBls12381G2().scalar;
        const zSecretG2 = scalarForScheme(group.SCHEME_BLS12381G2, zSecret);
        const zBlindingG2 = scalarForScheme(group.SCHEME_BLS12381G2, zBlinding);
        const challengeG2 = scalarForScheme(group.SCHEME_BLS12381G2, c);
        const leftCommitment = pcsContext.generatorG.scale(zSecretG2)
            .add(pcsContext.generatorH.scale(zBlindingG2));
        const rightCommitment = share.proof.commitmentNonce
            .add(shareCommitment.scale(challengeG2));
        if (!leftCommitment.equals(rightCommitment)) {
            console.log(`  [tVRF] worker ${nodeAddr} (${endpoint}): commitment proof equation failed`);
            return false;
        }

        const zSecretG1 = scalarForScheme(group.SCHEME_BLS12381G1, zSecret);
        const challengeG1 = scalarForScheme(group.SCHEME_BLS12381G1, c);
        const leftVrf = inputElement.scale(zSecretG1);
        const rightVrf = share.proof.vrfNonce.add(share.share.scale(challengeG1));
        if (!leftVrf.equals(rightVrf)) {
            console.log(`  [tVRF] worker ${nodeAddr} (${endpoint}): VRF proof equation failed`);
            return false;
        }
        return true;
    } catch (e) {
        console.log(`  [tVRF] worker ${nodeAddr} (${endpoint}): proof verification threw - ${e}`);
        return false;
    }
}

function reconstructThresholdVrf(shares: ThresholdVrfShare[]): Uint8Array {
    if (shares.length === 0) {
        throw new Error("ACE.VRF_Aptos.reconstructThresholdVrf: no shares");
    }
    const xs = shares.map((s) => frMod(BigInt(s.evalPoint)));
    for (let i = 0; i < xs.length; i++) {
        for (let j = i + 1; j < xs.length; j++) {
            if (xs[i] === xs[j]) throw new Error("ACE.VRF_Aptos.reconstructThresholdVrf: duplicate evalPoint");
        }
    }

    let full: any | null = null;
    for (let i = 0; i < shares.length; i++) {
        let lambda = 1n;
        for (let j = 0; j < shares.length; j++) {
            if (i === j) continue;
            lambda = frMul(lambda, frMul(frMod(-xs[j]), frInv(frMod(xs[i] - xs[j]))));
        }
        if (lambda === 0n) continue;
        const point = (shares[i].share.inner as group.bls12381G1.PublicPoint).pt as any;
        const scaled = point.multiply(lambda);
        full = full === null ? scaled : full.add(scaled);
    }
    if (full === null) {
        throw new Error("ACE.VRF_Aptos.reconstructThresholdVrf: all Lagrange coefficients were zero");
    }

    const pointBytes = new group.bls12381G1.PublicPoint(full).rawBytes();
    const seed = sha3_256(new TextEncoder().encode("ACE::ThresholdVrfOutput"));
    const preimage = new Uint8Array(seed.length + pointBytes.length);
    preimage.set(seed, 0);
    preimage.set(pointBytes, seed.length);
    return sha3_256(preimage);
}

export class DerivationSession {
    aceDeployment: AceDeployment;
    keypairId: AccountAddress;
    contractId: ContractID;
    label: Uint8Array;
    accountAddress: AccountAddress;
    responseEncryptionKey: pke.EncryptionKey;
    responseDecryptionKey: pke.DecryptionKey;
    networkState: NetworkState | undefined;
    payload: ThresholdVrfRequestPayload | undefined;
    message: string | undefined;

    private constructor(args: RequestToSignArgs & {
        responseEncryptionKey: pke.EncryptionKey,
        responseDecryptionKey: pke.DecryptionKey,
    }) {
        this.aceDeployment = args.aceDeployment;
        this.keypairId = args.keypairId;
        this.contractId = args.contractId;
        this.label = args.label;
        this.accountAddress = args.accountAddress;
        this.responseEncryptionKey = args.responseEncryptionKey;
        this.responseDecryptionKey = args.responseDecryptionKey;
    }

    static async create(args: RequestToSignArgs): Promise<DerivationSession> {
        const { encryptionKey, decryptionKey } = await pke.keygen();
        return new DerivationSession({
            ...args,
            responseEncryptionKey: encryptionKey,
            responseDecryptionKey: decryptionKey,
        });
    }

    private async refreshPayload(): Promise<ThresholdVrfRequestPayload> {
        const networkState = await fetchNetworkState(this.aceDeployment);
        const payload = new ThresholdVrfRequestPayload({
            keypairId: this.keypairId,
            epoch: networkState.epoch,
            contractId: this.contractId,
            label: this.label,
            accountAddress: this.accountAddress,
            responseEncKey: this.responseEncryptionKey,
        });
        this.networkState = networkState;
        this.payload = payload;
        this.message = '0x' + bytesToHex(payload.toBytes());
        return payload;
    }

    async getRequestToSign(): Promise<string> {
        const payload = await this.refreshPayload();
        return '0x' + bytesToHex(payload.toBytes());
    }

    async getRequestToSignForWebAuthn(): Promise<Uint8Array> {
        const payload = await this.refreshPayload();
        return payload.toWebAuthnChallenge();
    }

    async deriveWithSignature(args: {
        pubKey: PublicKey;
        signature: Signature;
        fullMessage: string;
    }): Promise<Uint8Array> {
        if (this.payload === undefined || this.message === undefined) {
            throw new Error("ACE.VRF_Aptos.DerivationSession.deriveWithSignature: call getRequestToSign() first");
        }
        const authProof = new AptosAccountSignatureProof({
            userAddr: this.accountAddress,
            publicKey: args.pubKey,
            signature: args.signature,
            fullMessage: args.fullMessage,
        });
        const requestBytes = WorkerRequest.newThresholdVrf(
            new ThresholdVrfRequest({ payload: this.payload, authProof }),
        ).toBytes();
        if (requestBytes.length === 0) throw new Error("ACE.VRF_Aptos.DerivationSession.deriveWithSignature: empty request");

        const networkState = this.networkState;
        if (networkState === undefined) {
            throw new Error("ACE.VRF_Aptos.DerivationSession.deriveWithSignature: missing network state");
        }
        const [nodeInfos, currentSessionCommitments] = await Promise.all([
            fetchCurrentNodeInfos(this.aceDeployment, networkState),
            fetchCurrentSessionCommitments(this.aceDeployment, networkState, this.keypairId),
        ]);
        if (currentSessionCommitments.shareCommitments.length !== networkState.curNodes.length) {
            throw new Error(
                `ACE.VRF_Aptos.DerivationSession.deriveWithSignature: shareCommitments length ${currentSessionCommitments.shareCommitments.length} != curNodes length ${networkState.curNodes.length}`,
            );
        }
        const workerErrors: string[] = [];
        let sawNotImplemented = false;
        const shares: ThresholdVrfShare[] = [];

        await Promise.all(nodeInfos.map(async ({ nodeAddr, endpoint, nodeEncKey }, sdkIdx) => {
            try {
                const encReqHex = (await pke.encrypt({ encryptionKey: nodeEncKey, plaintext: requestBytes })).toHex();
                const ctrl = new AbortController();
                const tid = setTimeout(() => ctrl.abort(), 8000);
                let resp: Response;
                try {
                    resp = await fetch(endpoint, { method: "POST", body: encReqHex, signal: ctrl.signal });
                } finally {
                    clearTimeout(tid);
                }
                if (!resp.ok) {
                    const body = await resp.text().catch(() => "");
                    const detail = body.trim().slice(0, 120);
                    console.log(`  [tVRF] worker ${nodeAddr} (${endpoint}): HTTP ${resp.status}${detail ? ` - ${detail}` : ""}`);
                    if (resp.status === 501) sawNotImplemented = true;
                    workerErrors.push(`${nodeAddr}: HTTP ${resp.status}${detail ? ` ${detail}` : ""}`);
                    return;
                }
                const hexText = (await resp.text()).trim();
                const respCt = pke.Ciphertext.fromHex(hexText).okValue ?? null;
                if (respCt === null) {
                    console.log(`  [tVRF] worker ${nodeAddr} (${endpoint}): response ciphertext parse failed`);
                    workerErrors.push(`${nodeAddr}: response ciphertext parse failed`);
                    return;
                }
                const shareBytes = (await pke.decrypt({
                    decryptionKey: this.responseDecryptionKey,
                    ciphertext: respCt,
                })).okValue ?? null;
                if (shareBytes === null) {
                    console.log(`  [tVRF] worker ${nodeAddr} (${endpoint}): response decryption failed`);
                    workerErrors.push(`${nodeAddr}: response decryption failed`);
                    return;
                }
                try {
                    const share = ThresholdVrfShare.fromBytes(shareBytes);
                    if (!verifyThresholdVrfShare({
                        share,
                        sdkIdx,
                        payload: this.payload!,
                        pcsContext: currentSessionCommitments.pcsContext,
                        shareCommitment: currentSessionCommitments.shareCommitments[sdkIdx],
                        nodeAddr,
                        endpoint,
                    })) {
                        workerErrors.push(`${nodeAddr}: invalid tVRF share`);
                        return;
                    }
                    shares.push(share);
                    console.log(`  [tVRF] worker ${nodeAddr} (${endpoint}): OK`);
                } catch (e) {
                    console.log(`  [tVRF] worker ${nodeAddr} (${endpoint}): share parse failed - ${e}`);
                    workerErrors.push(`${nodeAddr}: share parse failed`);
                }
            } catch (e) {
                console.log(`  [tVRF] worker ${nodeAddr} (${endpoint}): fetch error - ${e}`);
                workerErrors.push(`${nodeAddr}: ${e}`);
            }
        }));

        if (sawNotImplemented) {
            throw new Error("ACE.VRF_Aptos.DerivationSession.deriveWithSignature: threshold VRF worker handler is not implemented yet");
        }
        if (shares.length >= networkState.curThreshold) {
            return reconstructThresholdVrf(shares.slice(0, networkState.curThreshold));
        }
        throw new Error(`ACE.VRF_Aptos.DerivationSession.deriveWithSignature: need ${networkState.curThreshold} valid shares, got ${shares.length} (${workerErrors.join("; ")})`);
    }

    /**
     * Build the encrypted POST body for one specific worker. This does not fan
     * out to the committee and does not reconstruct the final VRF output.
     * It is intended for load testing and low-level tooling.
     */
    async buildPerNodeRequest(args: {
        pubKey: PublicKey;
        signature: Signature;
        fullMessage: string;
        targetEndpoint: string;
    }): Promise<{ encReqHex: string, epoch: number, sdkIdx: number }> {
        if (this.payload === undefined || this.message === undefined) {
            throw new Error("ACE.VRF_Aptos.DerivationSession.buildPerNodeRequest: call getRequestToSign() first");
        }
        const networkState = this.networkState;
        if (networkState === undefined) {
            throw new Error("ACE.VRF_Aptos.DerivationSession.buildPerNodeRequest: missing network state");
        }
        const authProof = new AptosAccountSignatureProof({
            userAddr: this.accountAddress,
            publicKey: args.pubKey,
            signature: args.signature,
            fullMessage: args.fullMessage,
        });
        const requestBytes = WorkerRequest.newThresholdVrf(
            new ThresholdVrfRequest({ payload: this.payload, authProof }),
        ).toBytes();
        const nodeInfos = await fetchCurrentNodeInfos(this.aceDeployment, networkState);
        const target = args.targetEndpoint.replace(/\/$/, "");
        const sdkIdx = nodeInfos.findIndex(n => n.endpoint.replace(/\/$/, "") === target);
        if (sdkIdx < 0) {
            throw new Error(
                `ACE.VRF_Aptos.DerivationSession.buildPerNodeRequest: targetEndpoint ${args.targetEndpoint} is not in the current committee. Registered endpoints: ${nodeInfos.map(n => n.endpoint).join(", ")}`,
            );
        }
        const { nodeEncKey } = nodeInfos[sdkIdx]!;
        const encReqHex = (await pke.encrypt({ encryptionKey: nodeEncKey, plaintext: requestBytes })).toHex();
        return { encReqHex, epoch: networkState.epoch, sdkIdx };
    }

    async deriveWithWebAuthnAssertion(args: {
        pubKey: Secp256r1PublicKey;
        authenticatorData: Uint8Array;
        clientDataJSON: Uint8Array;
        signature: Uint8Array;
    }): Promise<Uint8Array> {
        if (this.payload === undefined || this.message === undefined) {
            throw new Error("ACE.VRF_Aptos.DerivationSession.deriveWithWebAuthnAssertion: call getRequestToSignForWebAuthn() first");
        }

        const sigRs = derEcdsaToRawLowS(args.signature);
        const cdjHash = sha256(args.clientDataJSON);
        const preimage = new Uint8Array(args.authenticatorData.length + cdjHash.length);
        preimage.set(args.authenticatorData, 0);
        preimage.set(cdjHash, args.authenticatorData.length);

        return this.deriveWithSignature({
            pubKey: new AnyPublicKey(args.pubKey),
            signature: new AnySignature(new WebAuthnSignature(
                sigRs,
                args.authenticatorData,
                args.clientDataJSON,
            )),
            fullMessage: bytesToHex(preimage),
        });
    }
}

function derEcdsaToRawLowS(der: Uint8Array): Uint8Array {
    const sig = p256.Signature.fromDER(der).normalizeS();
    return sig.toCompactRawBytes();
}

/**
 * One-shot tVRF derive. Wraps `DerivationSession.create →
 * getRequestToSign → deriveWithSignature` for callers (CLIs, scripts,
 * server-side jobs) that already know how to sign and don't need to
 * keep the session object around between phases.
 *
 * The two-phase `DerivationSession` API is the right shape for wallets
 * that render the message to a user between phases; this is for
 * everything else.
 *
 * Takes the Aptos contract identity (`chainId`, `moduleAddr`,
 * `moduleName`) as flat fields rather than a pre-built `ContractID`.
 * tVRF is Aptos-only at the worker layer (`verify_threshold_vrf_aptos`).
 *
 * Example:
 *
 *   const vrfBytes = await ACE.VRF_Aptos.derive({
 *       aceDeployment, keypairId, chainId, moduleAddr, moduleName,
 *       label, accountAddress: owner.accountAddress,
 *       sign: async msg => {
 *           const fullMessage = buildAptosWalletFullMessage({ ... message: msg, ... });
 *           return { pubKey: owner.publicKey, signature: owner.sign(fullMessage), fullMessage };
 *       },
 *   });
 */
export async function derive(args: {
    aceDeployment: AceDeployment;
    keypairId: AccountAddress;
    chainId: number;
    moduleAddr: AccountAddress;
    moduleName: string;
    label: Uint8Array;
    accountAddress: AccountAddress;
    sign: (msgToSign: string) => Promise<{
        pubKey: PublicKey;
        signature: Signature;
        fullMessage: string;
    }>;
}): Promise<Uint8Array> {
    const session = await DerivationSession.create({
        aceDeployment: args.aceDeployment,
        keypairId: args.keypairId,
        contractId: ContractID.newAptos({
            chainId: args.chainId,
            moduleAddr: args.moduleAddr,
            moduleName: args.moduleName,
        }),
        label: args.label,
        accountAddress: args.accountAddress,
    });
    const message = await session.getRequestToSign();
    return session.deriveWithSignature(await args.sign(message));
}
