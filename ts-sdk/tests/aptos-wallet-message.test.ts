// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from "@aptos-labs/ts-sdk";
import { describe, expect, it } from "vitest";
import { IBE_Aptos } from "../src";

describe("Aptos wallet fullMessage helper", () => {
    it("builds the wallet-style message shape used by ACE service signing", () => {
        const accountAddress = "0x0000000000000000000000000000000000000000000000000000000000000abc";
        const fullMessage = IBE_Aptos.buildAptosWalletFullMessage({
            accountAddress: AccountAddress.fromString(accountAddress),
            application: "https://app.example",
            chainId: 2,
            message: "0x1234",
            nonce: "nonce-1",
        });

        expect(fullMessage).toBe([
            "APTOS",
            `address: ${accountAddress}`,
            "application: https://app.example",
            "chainId: 2",
            "message: 0x1234",
            "nonce: nonce-1",
        ].join("\n"));
    });
});
