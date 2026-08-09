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

    it("public key / signature: toHex / fromHex (BCS) round-trip", async () => {
        const { publicKey, signingKey } = await sig.keygen();
        const message = new TextEncoder().encode("bcs round-trip");
        const signature = signingKey.sign(message);

        const publicKeyBack = sig.PublicKey.fromHex(publicKey.toHex()).unwrapOrThrow("pk fromHex");
        const signatureBack = sig.Signature.fromHex(signature.toHex()).unwrapOrThrow("sig fromHex");

        expect(new Uint8Array(publicKeyBack.toBytes())).toEqual(new Uint8Array(publicKey.toBytes()));
        expect(new Uint8Array(signatureBack.toBytes())).toEqual(new Uint8Array(signature.toBytes()));
        expect(sig.verify(message, signatureBack, publicKeyBack)).toBe(true);
    });

    it("signing key: BCS toHex / fromHex round-trip (scheme-tagged)", async () => {
        const { signingKey } = await sig.keygen();

        const signingKeyBack = sig.SigningKey.fromHex(signingKey.toHex()).unwrapOrThrow("sk fromHex");

        expect(signingKeyBack.scheme).toBe(signingKey.scheme);
        expect(new Uint8Array(signingKeyBack.bytes)).toEqual(new Uint8Array(signingKey.bytes));
        // Same key ⇒ same public key.
        expect(new Uint8Array(signingKeyBack.publicKey().toBytes())).toEqual(
            new Uint8Array(signingKey.publicKey().toBytes()),
        );
    });

    it("keygen rejects unknown schemes", async () => {
        await expect(sig.keygen(255)).rejects.toThrow("unknown signature scheme");
    });
});
