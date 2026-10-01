// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { AccountAddress } from "@aptos-labs/ts-sdk";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";

import { ContractID } from "../src/_internal/common";
import * as pke from "../src/pke";
import {
    CvmRootBinding,
    CvmRootVrfRequest,
    ThresholdVrfRequestPayload,
    cvmRootAttestationNonce,
    cvmRootWorkerSignatureMessage,
} from "../src/vrf-for-aptos";

describe("attested CVM root VRF wire", () => {
    it("matches the Python and Rust BCS request", () => {
        const payload = new ThresholdVrfRequestPayload({
            keypairId: AccountAddress.fromString("0x" + "01".repeat(32)),
            epoch: 7,
            contractId: ContractID.newAptos({
                chainId: 119,
                moduleAddr: AccountAddress.fromString("0x" + "02".repeat(32)),
                moduleName: "confidential_worker",
            }),
            label: new TextEncoder().encode("c26t/root/v1"),
            accountAddress: AccountAddress.fromString("0x" + "03".repeat(32)),
            responseEncKey: pke.EncryptionKey.fromHex("0120" + "04".repeat(32)).unwrapOrThrow("ek"),
        });
        const binding = new CvmRootBinding({
            workerAddr: new Uint8Array(32).fill(5),
            workerPk: hexToBytes("ea4a6c63e29c520abef5507b132ec5f9954776aebebe7b92421eea691446d22c"),
            tlsSpkiSha256: new Uint8Array(32).fill(6),
            workerSignature: hexToBytes("1df4d2fd976963346d4bb6026803a1f12bcfe908687fbe024701ccfac46769763297b0b04cdc7483d5c0a698a0c45fb2682cb0c722af44ba81ec5f4d9a559e0c"),
        });
        const req = new CvmRootVrfRequest({ payload, binding, attestationJwt: "test.jwt" });
        expect(bytesToHex(req.toBytes())).toBe(
            "04" + "01".repeat(32) + "0700000000000000" + "00" + "77" + "02".repeat(32)
            + "13636f6e666964656e7469616c5f776f726b6572" + "0c633236742f726f6f742f7631"
            + "03".repeat(32) + "0120" + "04".repeat(32)
            + "05".repeat(32) + bytesToHex(binding.workerPk) + "06".repeat(32)
            + "40" + bytesToHex(binding.workerSignature) + "08746573742e6a7774"
        );
        expect(cvmRootAttestationNonce(payload, binding)).toBe("TUlW5QIbVxjiomgeFYQASwvhk8K6fKoM6Ab-BiEcsaQ");
        expect(bytesToHex(cvmRootWorkerSignatureMessage(
            payload, binding.workerAddr, binding.workerPk, binding.tlsSpkiSha256,
        ))).toContain(bytesToHex(binding.workerPk));
        expect(cvmRootAttestationNonce(payload, new CvmRootBinding({
            ...binding,
            tlsSpkiSha256: new Uint8Array(32).fill(8),
        }))).not.toBe(cvmRootAttestationNonce(payload, binding));
    });
});
