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
    expiresAtUnixMs?: number;
}

export interface RequestToSignResult extends RequestToSignArgs {
    networkState: NetworkState;
    payload: ThresholdVrfRequestPayload;
    message: string;
    responseEncryptionKey: pke.EncryptionKey;
    responseDecryptionKey: pke.DecryptionKey;
}

export interface DeriveArgs extends RequestToSignResult {
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
    expiresAtUnixMs: number;

    constructor(args: {
        keypairId: AccountAddress,
        epoch: number,
        label: Uint8Array,
        accountAddress: AccountAddress,
        responseEncKey: pke.EncryptionKey,
        expiresAtUnixMs: number,
    }) {
        this.keypairId = args.keypairId;
        this.epoch = args.epoch;
        this.label = args.label;
        this.accountAddress = args.accountAddress;
        this.responseEncKey = args.responseEncKey;
        this.expiresAtUnixMs = args.expiresAtUnixMs;
    }

    serialize(serializer: Serializer): void {
        this.keypairId.serialize(serializer);
        serializer.serializeU64(BigInt(this.epoch));
        serializer.serializeBytes(this.label);
        this.accountAddress.serialize(serializer);
        this.responseEncKey.serialize(serializer);
        serializer.serializeU64(BigInt(this.expiresAtUnixMs));
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
            `expiresAtUnixMs: ${this.expiresAtUnixMs}`,
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

export async function requestToSign(args: RequestToSignArgs): Promise<RequestToSignResult> {
    const networkState = await fetchNetworkState(args.aceDeployment);
    const { encryptionKey, decryptionKey } = await pke.keygen();
    const payload = new ThresholdVrfRequestPayload({
        keypairId: args.keypairId,
        epoch: networkState.epoch,
        label: args.label,
        accountAddress: args.accountAddress,
        responseEncKey: encryptionKey,
        expiresAtUnixMs: args.expiresAtUnixMs ?? Date.now() + 5 * 60_000,
    });
    return {
        ...args,
        networkState,
        payload,
        message: payload.toPrettyMessage(),
        responseEncryptionKey: encryptionKey,
        responseDecryptionKey: decryptionKey,
    };
}

export async function derive(args: DeriveArgs): Promise<Uint8Array> {
    const proof = ProofOfPermission.createAptos({
        userAddr: args.accountAddress,
        publicKey: args.pubKey,
        signature: args.signature,
        fullMessage: args.fullMessage ?? args.message,
    });
    const requestBytes = new ThresholdVrfRequest({ payload: args.payload, proof }).toBytes();
    if (requestBytes.length === 0) throw new Error("ACE.tVRF.derive: empty request");
    throw new Error("ACE.tVRF.derive: threshold VRF worker handler is not implemented yet");
}

export type TVRFFunction = ((args: DeriveArgs) => Promise<Uint8Array>) & {
    requestToSign: typeof requestToSign;
    derive: typeof derive;
};

export const tVRF: TVRFFunction = Object.assign(
    (args: DeriveArgs) => derive(args),
    { requestToSign, derive },
);
