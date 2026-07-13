// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddressInput, Aptos, Serializer } from "@aptos-labs/ts-sdk";
import { hexToBytes } from "@noble/hashes/utils";
import * as pke from "../pke";
import * as sig from "../sig";

export type WorkerEndpointResource = {
    endpoint: string;
};

export type WorkerClientEndpointResource = WorkerEndpointResource;

type MoveEnumJson = {
    __variant__: string;
    _0: Record<string, unknown>;
};

export type WorkerPkeEncryptionKeyResource = {
    ek: MoveEnumJson;
};

export type WorkerSigVerificationKeyResource = {
    pk: MoveEnumJson;
};

function isRecord(value: unknown): value is Record<string, unknown> {
    return value !== null && typeof value === "object";
}

function moveBytesFromJson(value: unknown, context: string): Uint8Array {
    if (typeof value === "string") {
        return hexToBytes(value.replace(/^0x/i, ""));
    }
    if (Array.isArray(value)) {
        return Uint8Array.from(value.map((byte, i) => {
            if (!Number.isInteger(byte) || byte < 0 || byte > 255) {
                throw new Error(`${context}: invalid byte at index ${i}`);
            }
            return byte;
        }));
    }
    if (isRecord(value) && "data" in value) {
        return moveBytesFromJson(value.data, `${context}.data`);
    }
    throw new Error(`${context}: expected hex string, byte array, or { data }`);
}

function requireMoveEnum(value: unknown, context: string): MoveEnumJson {
    if (!isRecord(value) || typeof value.__variant__ !== "string" || !isRecord(value._0)) {
        throw new Error(`${context}: invalid Move enum resource shape`);
    }
    return {
        __variant__: value.__variant__,
        _0: value._0,
    };
}

export function pkeEncryptionKeyFromResource(
    resource: WorkerPkeEncryptionKeyResource,
    context: string = "PkeEncryptionKey resource",
): pke.EncryptionKey {
    const ek = requireMoveEnum(resource.ek, context);

    const serializer = new Serializer();
    if (ek.__variant__ === "ElGamalOtpRistretto255") {
        serializer.serializeU8(pke.SCHEME_ELGAMAL_OTP_RISTRETTO255);
        serializer.serializeBytes(moveBytesFromJson(ek._0.enc_base, `${context}.ek._0.enc_base`));
        serializer.serializeBytes(moveBytesFromJson(ek._0.public_point, `${context}.ek._0.public_point`));
    } else if (ek.__variant__ === "HpkeX25519ChaCha20Poly1305") {
        serializer.serializeU8(pke.SCHEME_HPKE_X25519_HKDF_SHA256_CHACHA20POLY1305);
        serializer.serializeBytes(moveBytesFromJson(ek._0.pk, `${context}.ek._0.pk`));
    } else {
        throw new Error(`${context}: unsupported PKE key variant ${ek.__variant__}`);
    }

    return pke.EncryptionKey.fromBytes(serializer.toUint8Array())
        .unwrapOrThrow(`${context}: parse pke enc key`);
}

export function sigVerificationKeyFromResource(
    resource: WorkerSigVerificationKeyResource,
    context: string = "SigVerificationKey resource",
): sig.PublicKey {
    const pk = requireMoveEnum(resource.pk, context);
    if (pk.__variant__ !== "Ed25519") {
        throw new Error(`${context}: unsupported sig public key variant ${pk.__variant__}`);
    }
    return new sig.PublicKey(
        sig.SCHEME_ED25519,
        moveBytesFromJson(pk._0.bytes, `${context}.pk._0.bytes`),
    );
}

export function endpointFromResource(
    resource: WorkerEndpointResource,
    context: string = "Endpoint resource",
): string {
    if (typeof resource.endpoint !== "string") {
        throw new Error(`${context}: missing endpoint string`);
    }
    return resource.endpoint;
}

export function clientEndpointFromResource(
    resource: WorkerClientEndpointResource,
    context: string = "ClientEndpoint resource",
): string {
    return endpointFromResource(resource, context);
}

export async function fetchWorkerClientEndpoint(
    aptos: Aptos,
    aceContractAddr: string,
    workerAddr: AccountAddressInput,
): Promise<string> {
    const resource = await aptos.getAccountResource<WorkerClientEndpointResource>({
        accountAddress: workerAddr,
        resourceType: `${aceContractAddr}::worker_config::ClientEndpoint`,
    });
    return endpointFromResource(resource, `ClientEndpoint resource for ${workerAddr}`);
}

export async function fetchWorkerPkeEncryptionKey(
    aptos: Aptos,
    aceContractAddr: string,
    workerAddr: AccountAddressInput,
    context: string = `PkeEncryptionKey resource for ${workerAddr}`,
): Promise<pke.EncryptionKey> {
    const resource = await aptos.getAccountResource<WorkerPkeEncryptionKeyResource>({
        accountAddress: workerAddr,
        resourceType: `${aceContractAddr}::worker_config::PkeEncryptionKey`,
    });
    return pkeEncryptionKeyFromResource(resource, context);
}

export async function fetchWorkerSigVerificationKey(
    aptos: Aptos,
    aceContractAddr: string,
    workerAddr: AccountAddressInput,
    context: string = `SigVerificationKey resource for ${workerAddr}`,
): Promise<sig.PublicKey> {
    const resource = await aptos.getAccountResource<WorkerSigVerificationKeyResource>({
        accountAddress: workerAddr,
        resourceType: `${aceContractAddr}::worker_config::SigVerificationKey`,
    });
    return sigVerificationKeyFromResource(resource, context);
}
