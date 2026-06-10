// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, expect, it } from "vitest";
import * as hybrid from "../src/pke/hybrid_x25519_mlkem768_chacha20poly1305";

const utf8 = (s: string) => new TextEncoder().encode(s);

describe("Hybrid-X25519-MLKEM768-HKDF-SHA256-ChaCha20Poly1305", () => {
    it("keygen, encrypt, decrypt round-trip", async () => {
        const { encryptionKey, decryptionKey } = await hybrid.keygen();
        const plaintext = utf8("hello hybrid pke");

        const ct = await hybrid.encrypt({ encryptionKey, plaintext });
        const r = await hybrid.decrypt(decryptionKey, ct);

        expect(r.isOk).toBe(true);
        expect(r.okValue).toEqual(plaintext);
    });

    it("derives public key from private key consistently", async () => {
        const { encryptionKey, decryptionKey } = await hybrid.keygen();
        const derived = hybrid.deriveEncryptionKey(decryptionKey);
        expect(derived.hpkeX25519.pk).toEqual(encryptionKey.hpkeX25519.pk);
        expect(derived.mlkem768Ek).toEqual(encryptionKey.mlkem768Ek);
    });

    it("encrypts and decrypts a 64KB plaintext", async () => {
        const { encryptionKey, decryptionKey } = await hybrid.keygen();
        const plaintext = new Uint8Array(64 * 1024);
        for (let i = 0; i < plaintext.length; i++) plaintext[i] = i & 0xff;
        const ct = await hybrid.encrypt({ encryptionKey, plaintext });
        const r = await hybrid.decrypt(decryptionKey, ct);
        expect(r.isOk).toBe(true);
        expect(r.okValue).toEqual(plaintext);
    });

    it("AAD must match", async () => {
        const { encryptionKey, decryptionKey } = await hybrid.keygen();
        const ct = await hybrid.encrypt({
            encryptionKey,
            plaintext: utf8("msg"),
            aad: utf8("ctx-A"),
        });

        const ok = await hybrid.decrypt(decryptionKey, ct, utf8("ctx-A"));
        expect(ok.isOk).toBe(true);
        expect(ok.okValue).toEqual(utf8("msg"));

        const bad = await hybrid.decrypt(decryptionKey, ct, utf8("ctx-B"));
        expect(bad.isOk).toBe(false);
    });

    it("rejects tampered outer AEAD ciphertext", async () => {
        const { encryptionKey, decryptionKey } = await hybrid.keygen();
        const ct = await hybrid.encrypt({ encryptionKey, plaintext: utf8("secret") });
        const bad = new hybrid.Ciphertext(
            ct.mlkem768Ct,
            ct.aeadNonce,
            new Uint8Array(ct.aeadCt),
        );
        bad.aeadCt[0] ^= 1;
        const r = await hybrid.decrypt(decryptionKey, bad);
        expect(r.isOk).toBe(false);
    });

    it("rejects tampered ML-KEM ciphertext via outer AEAD", async () => {
        const { encryptionKey, decryptionKey } = await hybrid.keygen();
        const ct = await hybrid.encrypt({ encryptionKey, plaintext: utf8("secret") });
        const badMlkemCt = new Uint8Array(ct.mlkem768Ct);
        badMlkemCt[0] ^= 1;
        const bad = new hybrid.Ciphertext(badMlkemCt, ct.aeadNonce, ct.aeadCt);
        const r = await hybrid.decrypt(decryptionKey, bad);
        expect(r.isOk).toBe(false);
    });

    it("decryption with the wrong private key fails", async () => {
        const { encryptionKey } = await hybrid.keygen();
        const { decryptionKey: wrongDk } = await hybrid.keygen();
        const ct = await hybrid.encrypt({ encryptionKey, plaintext: utf8("secret") });
        const r = await hybrid.decrypt(wrongDk, ct);
        expect(r.isOk).toBe(false);
    });

    it("BCS round-trips and checks lengths", async () => {
        const { encryptionKey, decryptionKey } = await hybrid.keygen();

        const ekBytes = encryptionKey.toBytes();
        // HPKE key: 1 + 32, then ML-KEM-768 ek: ULEB128(1184) + 1184.
        expect(ekBytes.length).toBe(33 + 2 + 1184);
        expect(ekBytes[0]).toBe(0x20);
        expect(ekBytes[33]).toBe(0xa0);
        expect(ekBytes[34]).toBe(0x09);
        expect(hybrid.EncryptionKey.fromBytes(ekBytes).unwrapOrThrow("ek").toBytes())
            .toEqual(ekBytes);

        const dkBytes = decryptionKey.toBytes();
        expect(dkBytes.length).toBe(33 + 1 + 64);
        expect(dkBytes[0]).toBe(0x20);
        expect(dkBytes[33]).toBe(0x40);
        expect(hybrid.DecryptionKey.fromBytes(dkBytes).unwrapOrThrow("dk").toBytes())
            .toEqual(dkBytes);

        const ct = await hybrid.encrypt({ encryptionKey, plaintext: utf8("xyzzy") });
        const ctBytes = ct.toBytes();
        expect(ctBytes[0]).toBe(0xc0);
        expect(ctBytes[1]).toBe(0x08);
        expect(ctBytes[2 + 1088]).toBe(0x0c);
        expect(hybrid.Ciphertext.fromBytes(ctBytes).unwrapOrThrow("ct").toBytes())
            .toEqual(ctBytes);
    });

    it("rejects invalid lengths", async () => {
        const { encryptionKey, decryptionKey } = await hybrid.keygen();
        expect(() => new hybrid.EncryptionKey(
            encryptionKey.hpkeX25519,
            encryptionKey.mlkem768Ek.slice(0, 1183),
        )).toThrow();
        expect(() => new hybrid.DecryptionKey(
            decryptionKey.hpkeX25519,
            decryptionKey.mlkem768Seed.slice(0, 63),
        )).toThrow();
        const ct = await hybrid.encrypt({ encryptionKey, plaintext: utf8("secret") });
        expect(() => new hybrid.Ciphertext(
            ct.mlkem768Ct.slice(0, 1087),
            ct.aeadNonce,
            ct.aeadCt,
        )).toThrow();
    });

    it("rejects trailing bytes", async () => {
        const { encryptionKey } = await hybrid.keygen();
        const bytes = encryptionKey.toBytes();
        const trailing = new Uint8Array([...bytes, 0xff]);
        expect(hybrid.EncryptionKey.fromBytes(trailing).isOk).toBe(false);
    });
});
