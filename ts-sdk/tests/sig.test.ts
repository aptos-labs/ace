// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import * as sig from "../src/sig";

describe("SIG (Ed25519)", () => {
    it("keygen, sign, verify round-trip", async () => {
        const { publicKey, signingKey } = await sig.keygen();
        const message = new TextEncoder().encode("hello sig");

        const signature = signingKey.sign(message);

        expect(sig.verify(message, signature, publicKey)).toBe(true);
        expect(sig.verify(new TextEncoder().encode("wrong"), signature, publicKey)).toBe(false);
    });

    it("keygen keys: toHex / fromHex round-trip", async () => {
        const { publicKey, signingKey } = await sig.keygen();

        const publicKeyBack = sig.PublicKey.fromHex(publicKey.toHex()).unwrapOrThrow("pk fromHex");
        const signingKeyBack = sig.SigningKey.fromHex(signingKey.toHex());

        expect(new Uint8Array(publicKeyBack.toBytes())).toEqual(new Uint8Array(publicKey.toBytes()));
        expect(new Uint8Array(signingKeyBack.bytes)).toEqual(new Uint8Array(signingKey.bytes));
    });

    it("keygen rejects unknown schemes", async () => {
        await expect(sig.keygen(255)).rejects.toThrow("unknown signature scheme");
    });
});
