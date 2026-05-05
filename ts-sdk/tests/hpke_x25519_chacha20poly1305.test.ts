// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { Deserializer } from "@aptos-labs/ts-sdk";
import * as hpke from "../src/pke/hpke_x25519_chacha20poly1305";

const utf8 = (s: string) => new TextEncoder().encode(s);

describe("HPKE-X25519-HKDF-SHA256-ChaCha20Poly1305", () => {
    it("keygen, encrypt, decrypt round-trip", async () => {
        const { encryptionKey, decryptionKey } = await hpke.keygen();
        const plaintext = utf8("hello hpke");

        const ct = await hpke.encrypt({ encryptionKey, plaintext });
        const r = await hpke.decrypt(decryptionKey, ct);

        expect(r.isOk).toBe(true);
        expect(r.okValue).toEqual(plaintext);
    });

    it("derives public key from private key consistently", async () => {
        const { encryptionKey, decryptionKey } = await hpke.keygen();
        const derived = hpke.deriveEncryptionKey(decryptionKey);
        expect(derived.pk).toEqual(encryptionKey.pk);
    });

    it("encrypts and decrypts an empty plaintext", async () => {
        const { encryptionKey, decryptionKey } = await hpke.keygen();
        const ct = await hpke.encrypt({ encryptionKey, plaintext: new Uint8Array(0) });
        const r = await hpke.decrypt(decryptionKey, ct);
        expect(r.isOk).toBe(true);
        expect(r.okValue!.length).toBe(0);
    });

    it("encrypts and decrypts a 64KB plaintext", async () => {
        const { encryptionKey, decryptionKey } = await hpke.keygen();
        const plaintext = new Uint8Array(64 * 1024);
        for (let i = 0; i < plaintext.length; i++) plaintext[i] = i & 0xff;
        const ct = await hpke.encrypt({ encryptionKey, plaintext });
        const r = await hpke.decrypt(decryptionKey, ct);
        expect(r.isOk).toBe(true);
        expect(r.okValue).toEqual(plaintext);
    });

    it("AAD must match: open with wrong AAD fails", async () => {
        const { encryptionKey, decryptionKey } = await hpke.keygen();
        const ct = await hpke.encrypt({ encryptionKey, plaintext: utf8("msg"), aad: utf8("ctx-A") });

        const ok = await hpke.decrypt(decryptionKey, ct, utf8("ctx-A"));
        expect(ok.isOk).toBe(true);
        expect(ok.okValue).toEqual(utf8("msg"));

        const bad = await hpke.decrypt(decryptionKey, ct, utf8("ctx-B"));
        expect(bad.isOk).toBe(false);
    });

    it("rejects tampered AEAD ciphertext", async () => {
        const { encryptionKey, decryptionKey } = await hpke.keygen();
        const ct = await hpke.encrypt({ encryptionKey, plaintext: utf8("hello hpke") });

        const bad = new hpke.Ciphertext(ct.enc, new Uint8Array(ct.aeadCt));
        bad.aeadCt[0] ^= 0x01;
        const r = await hpke.decrypt(decryptionKey, bad);
        expect(r.isOk).toBe(false);
    });

    it("rejects tampered enc (encapsulated key)", async () => {
        const { encryptionKey, decryptionKey } = await hpke.keygen();
        const ct = await hpke.encrypt({ encryptionKey, plaintext: utf8("hello hpke") });

        const bad = new hpke.Ciphertext(new Uint8Array(ct.enc), ct.aeadCt);
        bad.enc[0] ^= 0x01;
        const r = await hpke.decrypt(decryptionKey, bad);
        expect(r.isOk).toBe(false);
    });

    it("decryption with the wrong private key fails", async () => {
        const { encryptionKey } = await hpke.keygen();
        const { decryptionKey: wrongDk } = await hpke.keygen();
        const ct = await hpke.encrypt({ encryptionKey, plaintext: utf8("secret") });
        const r = await hpke.decrypt(wrongDk, ct);
        expect(r.isOk).toBe(false);
    });

    it("EncryptionKey BCS round-trip and length checks", async () => {
        const { encryptionKey } = await hpke.keygen();
        const bytes = encryptionKey.toBytes();
        // [ULEB128(32) = 0x20] [32B pk]
        expect(bytes.length).toBe(33);
        expect(bytes[0]).toBe(0x20);

        const back = hpke.EncryptionKey.fromBytes(bytes);
        expect(back.isOk).toBe(true);
        expect(back.okValue!.pk).toEqual(encryptionKey.pk);

        const hex = encryptionKey.toHex();
        const fromHex = hpke.EncryptionKey.fromHex(hex);
        expect(fromHex.isOk).toBe(true);
        expect(fromHex.okValue!.pk).toEqual(encryptionKey.pk);

        // Trailing bytes rejected.
        const trailing = new Uint8Array([...bytes, 0xff]);
        expect(hpke.EncryptionKey.fromBytes(trailing).isOk).toBe(false);

        // Wrong length pk rejected.
        const wrongLen = new Uint8Array([0x10, ...new Uint8Array(16)]); // ULEB128(16) + 16B
        expect(hpke.EncryptionKey.fromBytes(wrongLen).isOk).toBe(false);
    });

    it("DecryptionKey BCS round-trip", async () => {
        const { decryptionKey } = await hpke.keygen();
        const bytes = decryptionKey.toBytes();
        expect(bytes.length).toBe(33);
        expect(bytes[0]).toBe(0x20);

        const back = hpke.DecryptionKey.fromBytes(bytes);
        expect(back.isOk).toBe(true);
        expect(back.okValue!.sk).toEqual(decryptionKey.sk);
    });

    it("Ciphertext BCS round-trip and length checks", async () => {
        const { encryptionKey } = await hpke.keygen();
        const ct = await hpke.encrypt({ encryptionKey, plaintext: utf8("xyzzy") });
        const bytes = ct.toBytes();

        // 1 (ULEB len)+32 enc + 1 (ULEB len)+ (5+16=21) ct = 55 bytes for "xyzzy"
        expect(bytes.length).toBe(1 + 32 + 1 + 5 + 16);
        expect(bytes[0]).toBe(0x20);                 // enc length prefix
        expect(bytes[33]).toBe(5 + 16);              // ULEB128(21)

        const back = hpke.Ciphertext.fromBytes(bytes);
        expect(back.isOk).toBe(true);
        expect(back.okValue!.enc).toEqual(ct.enc);
        expect(back.okValue!.aeadCt).toEqual(ct.aeadCt);

        // Trailing bytes rejected.
        const trailing = new Uint8Array([...bytes, 0x00]);
        expect(hpke.Ciphertext.fromBytes(trailing).isOk).toBe(false);
    });

    it("Deserializer.deserialize returns Result", () => {
        // Build a minimal valid wire: 33-byte EncryptionKey [0x20, 32B zeros].
        // We allow zero-bytes here because EncryptionKey only validates length (HPKE will validate
        // the X25519 point itself when the key is used).
        const wire = new Uint8Array([0x20, ...new Uint8Array(32)]);
        const d = new Deserializer(wire);
        const r = hpke.EncryptionKey.deserialize(d);
        expect(r.isOk).toBe(true);
    });
});
