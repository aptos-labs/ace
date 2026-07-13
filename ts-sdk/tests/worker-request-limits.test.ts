// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, Ed25519PublicKey, Ed25519Signature } from "@aptos-labs/ts-sdk";
import { describe, expect, it } from "vitest";
import { ContractID, ProofOfPermission } from "../src/_internal/aptos";
import {
    assertWorkerCustomPayloadLimit,
    assertWorkerLabelLimit,
    assertWorkerWebAuthnLimits,
    MAX_WORKER_REQUEST_CUSTOM_PAYLOAD_BYTES,
    MAX_WORKER_REQUEST_FULL_MESSAGE_BYTES,
    MAX_WORKER_REQUEST_LABEL_BYTES,
    MAX_WORKER_REQUEST_MODULE_NAME_BYTES,
    MAX_WORKER_REQUEST_WEBAUTHN_CLIENT_DATA_JSON_BYTES,
} from "../src/_internal/worker-request-limits";

const ADDR_42 = AccountAddress.fromString(`0x${"42".padStart(64, "0")}`);
const ADDR_123 = AccountAddress.fromString(`0x${"123".padStart(64, "0")}`);

describe("worker request size limits", () => {
    it("rejects oversized labels and custom-flow payloads", () => {
        expect(() => assertWorkerLabelLimit(
            "label",
            new Uint8Array(MAX_WORKER_REQUEST_LABEL_BYTES + 1),
        )).toThrow("label length");

        expect(() => assertWorkerCustomPayloadLimit(
            "customPayload",
            new Uint8Array(MAX_WORKER_REQUEST_CUSTOM_PAYLOAD_BYTES + 1),
        )).toThrow("customPayload length");
    });

    it("rejects oversized Aptos contract module names", () => {
        expect(() => new ContractID(
            4,
            ADDR_42,
            "m".repeat(MAX_WORKER_REQUEST_MODULE_NAME_BYTES + 1),
        )).toThrow("ContractID.moduleName length");
    });

    it("rejects oversized Aptos fullMessage strings", () => {
        expect(() => new ProofOfPermission({
            userAddr: ADDR_123,
            publicKey: new Ed25519PublicKey(new Uint8Array(32)),
            signature: new Ed25519Signature(new Uint8Array(64)),
            fullMessage: "x".repeat(MAX_WORKER_REQUEST_FULL_MESSAGE_BYTES + 1),
        })).toThrow("ProofOfPermission.fullMessage length");
    });

    it("rejects oversized WebAuthn client data", () => {
        expect(() => assertWorkerWebAuthnLimits({
            authenticatorData: new Uint8Array(32),
            clientDataJSON: new Uint8Array(MAX_WORKER_REQUEST_WEBAUTHN_CLIENT_DATA_JSON_BYTES + 1),
        })).toThrow("webauthn.clientDataJSON length");
    });
});
