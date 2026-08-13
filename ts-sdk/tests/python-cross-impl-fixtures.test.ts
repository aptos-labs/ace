// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { hexToBytes } from "@noble/hashes/utils";
import * as pke from "../src/pke";
import * as tIbe from "../src/t-ibe";

type CrossImplFixture = {
    hpke: {
        plaintext_utf8: string;
        decryption_key_hex: string;
        encryption_key_hex: string;
        python_ciphertext_hex: string;
    };
    t_ibe_shortsig_aead: {
        identity_utf8: string;
        plaintext_utf8: string;
        master_public_key_hex: string;
        identity_decryption_key_hex: string;
        randomness_hex: string;
        python_ciphertext_hex: string;
    };
};

function fixture(): CrossImplFixture {
    const path = resolve(__dirname, "../../test-fixtures/python-sdk-cross-impl.json");
    return JSON.parse(readFileSync(path, "utf8"));
}

describe("Python SDK cross-implementation fixtures", () => {
    it("decrypts Python-produced default HPKE ciphertext bytes", async () => {
        const fx = fixture().hpke;
        const dk = pke.DecryptionKey.fromHex(fx.decryption_key_hex).unwrapOrThrow("hpke dk");
        const ek = await pke.deriveEncryptionKey(dk);
        const ct = pke.Ciphertext.fromHex(fx.python_ciphertext_hex).unwrapOrThrow("python hpke ct");

        expect(ek.toHex()).toBe(fx.encryption_key_hex);
        const plaintext = await pke.decrypt({ decryptionKey: dk, ciphertext: ct });

        expect(new TextDecoder().decode(plaintext.unwrapOrThrow("hpke decrypt"))).toBe(
            fx.plaintext_utf8,
        );
    });

    it("decrypts Python-produced t-IBE shortsig-aead ciphertext bytes", () => {
        const fx = fixture().t_ibe_shortsig_aead;
        const mpk = tIbe.MasterPublicKey.fromHex(fx.master_public_key_hex).unwrapOrThrow("mpk");
        const idk = tIbe.IdentityDecryptionKeyShare.fromHex(
            fx.identity_decryption_key_hex,
        ).unwrapOrThrow("idk");
        const expectedCt = tIbe.encryptWithRandomness({
            mpk,
            id: new TextEncoder().encode(fx.identity_utf8),
            plaintext: new TextEncoder().encode(fx.plaintext_utf8),
            randomness: hexToBytes(fx.randomness_hex),
        }).unwrapOrThrow("deterministic t-ibe ct");
        const ct = tIbe.Ciphertext.fromHex(fx.python_ciphertext_hex).unwrapOrThrow("python t-ibe ct");

        expect(expectedCt.toHex()).toBe(fx.python_ciphertext_hex);
        const plaintext = tIbe.decrypt({ idkShares: [idk], ciphertext: ct });

        expect(new TextDecoder().decode(plaintext.unwrapOrThrow("t-ibe decrypt"))).toBe(
            fx.plaintext_utf8,
        );
    });
});
