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
import { p256 } from "@noble/curves/p256";
import { sha256 } from "@noble/hashes/sha256";
import { sha3_256 } from "@noble/hashes/sha3";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

import * as pke from "../pke";
import * as group from "../group";
import {
    AceDeployment,
    createAptos,
    fetchNetworkState,
    NetworkState,
    RequestForDecryptionKey,
} from "../_internal/common";
import { getPublicKeyScheme, getSignatureScheme } from "../_internal/aptos";

export const PURPOSE = "ace.threshold-vrf.derive.v1";

export interface RequestToSignArgs {
    aceDeployment: AceDeployment;
    keypairId: AccountAddress;
    label: Uint8Array;
    accountAddress: AccountAddress;
}

export class ThresholdVrfRequestPayload {
    keypairId: AccountAddress;
    epoch: number;
    chainId: number;
    label: Uint8Array;
    accountAddress: AccountAddress;
    responseEncKey: pke.EncryptionKey;

    constructor(args: {
        keypairId: AccountAddress,
        epoch: number,
        chainId: number,
        label: Uint8Array,
        accountAddress: AccountAddress,
        responseEncKey: pke.EncryptionKey,
    }) {
        this.keypairId = args.keypairId;
        this.epoch = args.epoch;
        this.chainId = args.chainId;
        this.label = args.label;
        this.accountAddress = args.accountAddress;
        this.responseEncKey = args.responseEncKey;
    }

    serialize(serializer: Serializer): void {
        this.keypairId.serialize(serializer);
        serializer.serializeU64(BigInt(this.epoch));
        serializer.serializeU8(this.chainId);
        serializer.serializeBytes(this.label);
        this.accountAddress.serialize(serializer);
        this.responseEncKey.serialize(serializer);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    toPrettyMessage(): string {
        return [
            "ACE Threshold VRF Derive Request",
            `purpose: ${PURPOSE}`,
            `keypairId: ${this.keypairId.toStringLong()}`,
            `epoch: ${this.epoch}`,
            `chainId: ${this.chainId}`,
            `label: 0x${bytesToHex(this.label)}`,
            `accountAddress: ${this.accountAddress.toStringLong()}`,
            `responseEncKey: ${this.responseEncKey.toHex()}`,
        ].join("\n");
    }

    toWebAuthnChallenge(): Uint8Array {
        const seed = sha3_256(new TextEncoder().encode("ACE::ThresholdVrfRequestPayload"));
        const body = this.toBytes();
        const preimage = new Uint8Array(seed.length + body.length);
        preimage.set(seed, 0);
        preimage.set(body, seed.length);
        return sha3_256(preimage);
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
            .unwrapOrThrow(`ACE.tVRF: parse pke enc key for ${addrStr}`);
        return { nodeAddr: addrStr, endpoint: endpoint as string, nodeEncKey };
    }));
}

export class DerivationSession {
    aceDeployment: AceDeployment;
    keypairId: AccountAddress;
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
        const [networkState, chainId] = await Promise.all([
            fetchNetworkState(this.aceDeployment),
            createAptos(this.aceDeployment.apiEndpoint).getChainId(),
        ]);
        const payload = new ThresholdVrfRequestPayload({
            keypairId: this.keypairId,
            epoch: networkState.epoch,
            chainId,
            label: this.label,
            accountAddress: this.accountAddress,
            responseEncKey: this.responseEncryptionKey,
        });
        this.networkState = networkState;
        this.payload = payload;
        this.message = payload.toPrettyMessage();
        return payload;
    }

    async getRequestToSign(): Promise<string> {
        const payload = await this.refreshPayload();
        return payload.toPrettyMessage();
    }

    async getRequestToSignForWebAuthn(): Promise<Uint8Array> {
        const payload = await this.refreshPayload();
        return payload.toWebAuthnChallenge();
    }

    async deriveWithSignature(args: {
        pubKey: PublicKey;
        signature: Signature;
        fullMessage?: string;
    }): Promise<Uint8Array> {
        if (this.payload === undefined || this.message === undefined) {
            throw new Error("ACE.tVRF.DerivationSession.deriveWithSignature: call getRequestToSign() first");
        }
        const authProof = new AptosAccountSignatureProof({
            userAddr: this.accountAddress,
            publicKey: args.pubKey,
            signature: args.signature,
            fullMessage: args.fullMessage ?? this.message,
        });
        const requestBytes = RequestForDecryptionKey.newThresholdVrf(
            new ThresholdVrfRequest({ payload: this.payload, authProof }),
        ).toBytes();
        if (requestBytes.length === 0) throw new Error("ACE.tVRF.DerivationSession.deriveWithSignature: empty request");

        const networkState = this.networkState;
        if (networkState === undefined) {
            throw new Error("ACE.tVRF.DerivationSession.deriveWithSignature: missing network state");
        }
        const nodeInfos = await fetchCurrentNodeInfos(this.aceDeployment, networkState);
        const workerErrors: string[] = [];
        let sawNotImplemented = false;
        const shares: ThresholdVrfShare[] = [];

        await Promise.all(nodeInfos.map(async ({ nodeAddr, endpoint, nodeEncKey }) => {
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
            throw new Error("ACE.tVRF.DerivationSession.deriveWithSignature: threshold VRF worker handler is not implemented yet");
        }
        if (shares.length >= networkState.curThreshold) {
            throw new Error("ACE.tVRF.DerivationSession.deriveWithSignature: threshold VRF reconstruction is not implemented yet");
        }
        throw new Error(`ACE.tVRF.DerivationSession.deriveWithSignature: no worker returned a tVRF response (${workerErrors.join("; ")})`);
    }

    async deriveWithWebAuthnAssertion(args: {
        pubKey: Secp256r1PublicKey;
        authenticatorData: Uint8Array;
        clientDataJSON: Uint8Array;
        signature: Uint8Array;
    }): Promise<Uint8Array> {
        if (this.payload === undefined || this.message === undefined) {
            throw new Error("ACE.tVRF.DerivationSession.deriveWithWebAuthnAssertion: call getRequestToSignForWebAuthn() first");
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
