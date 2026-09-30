// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { AccountAddress } from "@aptos-labs/ts-sdk";
import { bytesToHex } from "@noble/hashes/utils";

import { ContractID } from "../src/_internal/common";
import * as pke from "../src/pke";
import { CvmRootVrfRequest, ThresholdVrfRequestPayload, cvmRootAttestationNonce } from "../src/vrf-for-aptos";

describe("attested CVM root VRF wire", () => {
    it("matches the Python and Rust BCS request", () => {
        const payload = new ThresholdVrfRequestPayload({
            keypairId: AccountAddress.fromString("0x" + "01".repeat(32)),
            epoch: 7,
            contractId: ContractID.newAptos({
                chainId: 119,
                moduleAddr: AccountAddress.fromString("0x" + "02".repeat(32)),
                moduleName: "c26t_vault",
            }),
            label: new TextEncoder().encode("c26t/root/v1"),
            accountAddress: AccountAddress.fromString("0x" + "03".repeat(32)),
            responseEncKey: pke.EncryptionKey.fromHex("0120" + "04".repeat(32)).unwrapOrThrow("ek"),
        });
        const req = new CvmRootVrfRequest({ payload, attestationJwt: "test.jwt" });
        expect(bytesToHex(req.toBytes())).toBe(
            "04" + "01".repeat(32) + "0700000000000000" + "00" + "77" + "02".repeat(32)
            + "0a633236745f7661756c74" + "0c633236742f726f6f742f7631"
            + "03".repeat(32) + "0120" + "04".repeat(32) + "08746573742e6a7774"
        );
        expect(cvmRootAttestationNonce(payload)).toBe("V5aLE5kkgTxD2AaOrc1IoUbpslJFUPfsnprk0tJUqCU");
    });
});
