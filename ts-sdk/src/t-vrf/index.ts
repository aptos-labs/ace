// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import {
    AccountAddress,
    PublicKey,
    Serializer,
    Signature,
} from "@aptos-labs/ts-sdk";
import { bytesToHex } from "@noble/hashes/utils";

import * as pke from "../pke";
import {
    AceDeployment,
    fetchNetworkState,
    NetworkState,
    ProofOfPermission,
} from "../_internal/common";

export const PURPOSE = "ace.threshold-vrf.derive.v1";

export interface RequestToSignArgs {
    aceDeployment: AceDeployment;
    keypairId: AccountAddress;
    label: Uint8Array;
    accountAddress: AccountAddress;
}

export interface DeriveWithSignatureArgs {
    pubKey: PublicKey;
    signature: Signature;
    fullMessage?: string;
}

export class ThresholdVrfRequestPayload {
    keypairId: AccountAddress;
    epoch: number;
    label: Uint8Array;
    accountAddress: AccountAddress;
    responseEncKey: pke.EncryptionKey;

    constructor(args: {
        keypairId: AccountAddress,
        epoch: number,
        label: Uint8Array,
        accountAddress: AccountAddress,
        responseEncKey: pke.EncryptionKey,
    }) {
        this.keypairId = args.keypairId;
        this.epoch = args.epoch;
        this.label = args.label;
        this.accountAddress = args.accountAddress;
        this.responseEncKey = args.responseEncKey;
    }

    serialize(serializer: Serializer): void {
        this.keypairId.serialize(serializer);
        serializer.serializeU64(BigInt(this.epoch));
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
            `label: 0x${bytesToHex(this.label)}`,
            `accountAddress: ${this.accountAddress.toStringLong()}`,
            `responseEncKey: ${this.responseEncKey.toHex()}`,
        ].join("\n");
    }
}

export class ThresholdVrfRequest {
    payload: ThresholdVrfRequestPayload;
    proof: ProofOfPermission;

    constructor(args: { payload: ThresholdVrfRequestPayload, proof: ProofOfPermission }) {
        this.payload = args.payload;
        this.proof = args.proof;
    }

    serialize(serializer: Serializer): void {
        this.payload.serialize(serializer);
        this.proof.serialize(serializer);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }
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

    async getRequestToSign(): Promise<string> {
        const networkState = await fetchNetworkState(this.aceDeployment);
        const payload = new ThresholdVrfRequestPayload({
            keypairId: this.keypairId,
            epoch: networkState.epoch,
            label: this.label,
            accountAddress: this.accountAddress,
            responseEncKey: this.responseEncryptionKey,
        });
        this.networkState = networkState;
        this.payload = payload;
        this.message = payload.toPrettyMessage();
        return this.message;
    }

    async deriveWithSignature(args: DeriveWithSignatureArgs): Promise<Uint8Array> {
        if (this.payload === undefined || this.message === undefined) {
            throw new Error("ACE.tVRF.DerivationSession.deriveWithSignature: call getRequestToSign() first");
        }
        const proof = ProofOfPermission.createAptos({
            userAddr: this.accountAddress,
            publicKey: args.pubKey,
            signature: args.signature,
            fullMessage: args.fullMessage ?? this.message,
        });
        const requestBytes = new ThresholdVrfRequest({ payload: this.payload, proof }).toBytes();
        if (requestBytes.length === 0) throw new Error("ACE.tVRF.DerivationSession.deriveWithSignature: empty request");
        throw new Error("ACE.tVRF.DerivationSession.deriveWithSignature: threshold VRF worker handler is not implemented yet");
    }
}
