// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress } from "@aptos-labs/ts-sdk";
import {
    FederatedKeylessPublicKey,
    KeylessPublicKey,
} from "@aptos-labs/ts-sdk/keyless";
import { describe, expect, it } from "vitest";
import { getPublicKeyScheme } from "../src/_internal/aptos";

describe("Keyless public-key scheme dispatch", () => {
    const idCommitment = new Uint8Array(32);
    const keyless = new KeylessPublicKey("https://accounts.google.com", idCommitment);

    it("maps KeylessPublicKey from the keyless subpath to scheme 4", () => {
        expect(getPublicKeyScheme(keyless)).toBe(4);
    });

    it("maps FederatedKeylessPublicKey from the keyless subpath to scheme 5", () => {
        const federated = new FederatedKeylessPublicKey(AccountAddress.ONE, keyless);
        expect(getPublicKeyScheme(federated)).toBe(5);
    });
});
