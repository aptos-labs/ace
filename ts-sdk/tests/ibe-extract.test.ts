// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import * as tibe from "../src/t-ibe";

// Mirrors the `ibe encrypt → admin-extract → admin-decrypt` validation loop:
// with the correct master secret, extracting the IDK for an identity and
// decrypting reproduces the plaintext; a wrong secret does not.
describe("tibe.extract (admin/disaster-recovery)", () => {
    it("encrypt → extract(msk) → decrypt round-trips", () => {
        const msk = tibe.keygenForTesting(tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD)
            .unwrapOrThrow("keygen");
        const mpk = tibe.derivePublicKey(msk).unwrapOrThrow("derivePublicKey");
        const mskScalar: bigint = (msk.inner as { scalar: bigint }).scalar;

        const id = new TextEncoder().encode("0xalice/file1.txt");
        const message = new TextEncoder().encode("Hello, Aptos!");

        const ct = tibe.encrypt({ mpk, id, plaintext: message }).unwrapOrThrow("encrypt");
        const idk = tibe.extract({ mskScalar, id }).unwrapOrThrow("extract");
        const out = tibe.decrypt({ idkShares: [idk], ciphertext: ct }).unwrapOrThrow("decrypt");

        expect(new TextDecoder().decode(out)).toBe("Hello, Aptos!");
    });

    it("wrong master secret fails to decrypt", () => {
        const msk = tibe.keygenForTesting(tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD).unwrapOrThrow("keygen");
        const mpk = tibe.derivePublicKey(msk).unwrapOrThrow("derivePublicKey");
        const id = new TextEncoder().encode("id");
        const ct = tibe.encrypt({ mpk, id, plaintext: new TextEncoder().encode("secret") }).unwrapOrThrow("encrypt");

        const wrongScalar: bigint = ((msk.inner as { scalar: bigint }).scalar) + 1n;
        const idk = tibe.extract({ mskScalar: wrongScalar, id }).unwrapOrThrow("extract");
        const res = tibe.decrypt({ idkShares: [idk], ciphertext: ct });
        expect(res.isOk).toBe(false); // AEAD tag mismatch
    });

    it("IDK serialization round-trips (file/hex artifact)", () => {
        const msk = tibe.keygenForTesting(tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD).unwrapOrThrow("keygen");
        const mskScalar: bigint = (msk.inner as { scalar: bigint }).scalar;
        const id = new TextEncoder().encode("id");
        const idk = tibe.extract({ mskScalar, id }).unwrapOrThrow("extract");

        const back = tibe.IdentityDecryptionKeyShare.fromBytes(idk.toBytes()).unwrapOrThrow("fromBytes");
        expect(new Uint8Array(back.toBytes())).toEqual(new Uint8Array(idk.toBytes()));
    });
});
