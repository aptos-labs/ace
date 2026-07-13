// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

// Must match worker-components/network-node/src/verify/limits.rs.
export const MAX_WORKER_REQUEST_PLAINTEXT_BYTES = 64 * 1024;
export const MAX_WORKER_REQUEST_LABEL_BYTES = 1024;
export const MAX_WORKER_REQUEST_MODULE_NAME_BYTES = 256;
export const MAX_WORKER_REQUEST_CUSTOM_PAYLOAD_BYTES = 16 * 1024;
export const MAX_WORKER_REQUEST_FULL_MESSAGE_BYTES = 16 * 1024;
export const MAX_WORKER_REQUEST_WEBAUTHN_CLIENT_DATA_JSON_BYTES = 16 * 1024;
export const MAX_WORKER_REQUEST_WEBAUTHN_AUTHENTICATOR_DATA_BYTES = 4 * 1024;

const ENCODER = new TextEncoder();

function utf8Len(value: string): number {
    return ENCODER.encode(value).length;
}

export function assertMaxBytes(field: string, actual: number, max: number): void {
    if (actual > max) {
        throw new Error(`${field} length ${actual} exceeds max ${max}`);
    }
}

export function assertWorkerLabelLimit(field: string, bytes: Uint8Array): void {
    assertMaxBytes(field, bytes.length, MAX_WORKER_REQUEST_LABEL_BYTES);
}

export function assertWorkerModuleNameLimit(field: string, value: string): void {
    assertMaxBytes(field, utf8Len(value), MAX_WORKER_REQUEST_MODULE_NAME_BYTES);
}

export function assertWorkerCustomPayloadLimit(field: string, bytes: Uint8Array): void {
    assertMaxBytes(field, bytes.length, MAX_WORKER_REQUEST_CUSTOM_PAYLOAD_BYTES);
}

export function assertWorkerFullMessageLimit(field: string, value: string): void {
    assertMaxBytes(field, utf8Len(value), MAX_WORKER_REQUEST_FULL_MESSAGE_BYTES);
}

export function assertWorkerRequestPlaintextLimit(field: string, bytes: Uint8Array): void {
    assertMaxBytes(field, bytes.length, MAX_WORKER_REQUEST_PLAINTEXT_BYTES);
}

export function assertWorkerWebAuthnLimits(args: {
    authenticatorData: Uint8Array;
    clientDataJSON: Uint8Array;
}): void {
    assertMaxBytes(
        "webauthn.authenticatorData",
        args.authenticatorData.length,
        MAX_WORKER_REQUEST_WEBAUTHN_AUTHENTICATOR_DATA_BYTES,
    );
    assertMaxBytes(
        "webauthn.clientDataJSON",
        args.clientDataJSON.length,
        MAX_WORKER_REQUEST_WEBAUTHN_CLIENT_DATA_JSON_BYTES,
    );
}
