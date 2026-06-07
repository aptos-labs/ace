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
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { sha3_256 } from "@noble/hashes/sha3";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

import * as pke from "../pke";
import * as group from "../group";
import {
    AceDeployment,
    ContractID,
    createAptos,
    fetchCurrentSessionPks,
    fetchNetworkState,
    NetworkState,
    WorkerRequest,
} from "../_internal/common";
import { getPublicKeyScheme, getSignatureScheme } from "../_internal/aptos";
import { frInv, frMod, frMul } from "../group/bls12381fr";

export const PURPOSE = "ace.threshold-vrf.derive.v1";
const DST_THRESHOLD_VRF_G1 = new TextEncoder().encode("ACE_THRESHOLD_VRF_BLS12381G1/HASH_TO_CURVE/v1");

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
        this.accountAddress.serialize(serializer);
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

    constructor(args: { evalPoint: number, share: group.Element }) {
        this.evalPoint = args.evalPoint;
        this.share = args.share;
    }

    static deserialize(deserializer: Deserializer): ThresholdVrfShare {
        const evalPoint = Number(deserializer.deserializeU64());
        const share = group.Element.deserialize(deserializer)
            .unwrapOrThrow("ThresholdVrfShare.deserialize: parse share");
        return new ThresholdVrfShare({ evalPoint, share });
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

async function fetchCurrentNodeInfos(
    aceDeployment: AceDeployment,
    networkState: NetworkState,
): Promise<Array<{ nodeAddr: string, endpoint: string, nodeEncKey: pke.EncryptionKey }>> {
    const aptos = createAptos(aceDeployment.apiEndpoint);
    const aceContractAddr = aceDeployment.contractAddr.toStringLong();

    return Promise.all(networkState.curNodes.map(async (nodeAddr) => {
        const addrStr = nodeAddr.toStringLong();
        const [[endpoint], [ekHex]] = await Promise.all([
            aptos.view({
                payload: {
                    function: `${aceContractAddr}::worker_config::get_endpoint` as `${string}::${string}::${string}`,
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

function verifyThresholdVrfShare(args: {
    share: ThresholdVrfShare,
    sdkIdx: number,
    sessionPks: { basePoint: group.Element, sharePks: group.Element[] },
    vrfInput: Uint8Array,
    nodeAddr: string,
    endpoint: string,
}): boolean {
    const { share, sdkIdx, sessionPks, vrfInput, nodeAddr, endpoint } = args;
    const expectedEval = sdkIdx + 1;
    if (share.evalPoint !== expectedEval) {
        console.log(`  [tVRF] worker ${nodeAddr} (${endpoint}): evalPoint mismatch (got ${share.evalPoint}, expected ${expectedEval})`);
        return false;
    }
    if (share.share.scheme !== group.SCHEME_BLS12381G1) {
        console.log(`  [tVRF] worker ${nodeAddr} (${endpoint}): share scheme mismatch (got ${share.share.scheme}, expected G1)`);
        return false;
    }
    if (sessionPks.basePoint.scheme !== group.SCHEME_BLS12381G2) {
        throw new Error(`ACE.VRF_Aptos: threshold VRF requires a G2 keypair, got basePoint scheme ${sessionPks.basePoint.scheme}`);
    }
    const sharePk = sessionPks.sharePks[sdkIdx];
    if (sharePk === undefined) {
        console.log(`  [tVRF] worker ${nodeAddr} (${endpoint}): missing sharePk at SDK index ${sdkIdx}`);
        return false;
    }
    if (sharePk.scheme !== group.SCHEME_BLS12381G2) {
        console.log(`  [tVRF] worker ${nodeAddr} (${endpoint}): sharePk scheme mismatch (got ${sharePk.scheme}, expected G2)`);
        return false;
    }

    const shareInner = share.share.inner as group.bls12381G1.PublicPoint;
    const basePointInner = sessionPks.basePoint.inner as group.bls12381G2.PublicPoint;
    const sharePkInner = sharePk.inner as group.bls12381G2.PublicPoint;
    const inputPoint = bls12_381.G1.hashToCurve(vrfInput, { DST: DST_THRESHOLD_VRF_G1 });
    const lhs = bls12_381.pairing(shareInner.pt as any, basePointInner.pt as any);
    const rhs = bls12_381.pairing(inputPoint as any, sharePkInner.pt as any);
    if (!bls12_381.fields.Fp12.eql(lhs, rhs)) {
        console.log(`  [tVRF] worker ${nodeAddr} (${endpoint}): share failed pairing verification`);
        return false;
    }
    return true;
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
        const [nodeInfos, sessionPks] = await Promise.all([
            fetchCurrentNodeInfos(this.aceDeployment, networkState),
            fetchCurrentSessionPks(this.aceDeployment, networkState, this.keypairId),
        ]);
        if (sessionPks.sharePks.length !== networkState.curNodes.length) {
            throw new Error(`ACE.VRF_Aptos.DerivationSession.deriveWithSignature: sharePks length ${sessionPks.sharePks.length} != curNodes length ${networkState.curNodes.length}`);
        }
        if (sessionPks.basePoint.scheme !== group.SCHEME_BLS12381G2) {
            throw new Error(`ACE.VRF_Aptos.DerivationSession.deriveWithSignature: threshold VRF requires a G2 keypair, got basePoint scheme ${sessionPks.basePoint.scheme}`);
        }
        const vrfInput = this.payload.toVrfInputBytes();
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
                    if (!verifyThresholdVrfShare({ share, sdkIdx, sessionPks, vrfInput, nodeAddr, endpoint })) {
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
 * `moduleName`) as flat fields rather than a pre-built `ContractID`
 * — matches the shape of `ACE.IBE_Aptos.encrypt` / `decryptCustomFlow`. tVRF
 * is Aptos-only at the worker layer (`verify_threshold_vrf_aptos`),
 * so there's no Solana variant to keep optional.
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
