// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { Deserializer } from "@aptos-labs/ts-sdk";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import * as pke from "../src/pke";

/** BCS bytes for {@link GOLDEN_DEC_KEY_HEX} (scheme 0 + Simple ElGamal Ristretto255 dec key). */
const GOLDEN_DEC_KEY_BYTES = hexToBytes(
    "0020f84e5c1c19630f29093c84052819f02bc2158dbad8590e9121fa4c59d20e174120d2874c3b7e5d7576c64b8a346b84159100ad978864319e880c249a54ae5d3708",
);

const GOLDEN_DEC_KEY_HEX = bytesToHex(GOLDEN_DEC_KEY_BYTES);

/** Encryption key derived from {@link GOLDEN_DEC_KEY_BYTES} via ElGamal key derivation. */
const GOLDEN_ENC_KEY_HEX =
    "0020f84e5c1c19630f29093c84052819f02bc2158dbad8590e9121fa4c59d20e1741209e441d841f1c37c7104a3eb43f51447306c8cb2294cc6ac1be23f32f23c72b71";

/** Ciphertext bytes that decrypt under {@link GOLDEN_DEC_KEY_BYTES} to `"golden-plaintext"`. */
const GOLDEN_CIPHERTEXT_BYTES = hexToBytes(
    "0020ec9d964805902bc6966b04ef1d54e655bb4356ad67029958e4af28b3dab4956320fe2416a85535cbd637b93487527a6427a0c632d6c66d3b3f71d82d625f3ba07e107b7b4a4ec372436a02589fe86b5d0eff2080b95f09e629565a296a7dcaadba6648f8f286633c9747774e453f5b2427540d",
);

const GOLDEN_CIPHERTEXT_HEX = bytesToHex(GOLDEN_CIPHERTEXT_BYTES);

describe("PKE (ElGamal OTP Ristretto255)", () => {
    it("keygen, encrypt, decrypt round-trip", () => {
        const { encryptionKey, decryptionKey } = pke.keygen();
        const plaintext = new TextEncoder().encode("hello pke");

        const ciphertext = pke.encrypt({ encryptionKey, plaintext });
        const result = pke.decrypt({ decryptionKey, ciphertext });

        expect(result.isOk).toBe(true);
        expect(new Uint8Array(result.okValue!)).toEqual(plaintext);
    });

    /**
     * Golden vectors pin BCS layout (scheme byte + inner) and MAC behavior.
     * Generated once with deterministic `crypto.getRandomValues` (repeating pool)
     * against the built SDK; do not change vectors unless the wire format is
     * intentionally versioned.
     */
    it("deserialization compatibility: fixed dec key + fixed ciphertext -> fixed plaintext", () => {
        const decryptionKey = pke.DecryptionKey.fromBytes(GOLDEN_DEC_KEY_BYTES).unwrapOrThrow("golden dk");
        const ciphertext = pke.Ciphertext.fromBytes(GOLDEN_CIPHERTEXT_BYTES).unwrapOrThrow("golden ct");
        const expectedPlaintext = new TextEncoder().encode("golden-plaintext");

        const result = pke.decrypt({ decryptionKey, ciphertext });

        expect(result.isOk).toBe(true);
        expect(new Uint8Array(result.okValue!)).toEqual(expectedPlaintext);
    });

    it("golden bytes: DecryptionKey toHex / fromHex round-trip", () => {
        const dk = pke.DecryptionKey.fromBytes(GOLDEN_DEC_KEY_BYTES).unwrapOrThrow("golden dk");
        expect(dk.toHex()).toBe(GOLDEN_DEC_KEY_HEX);

        const parsed = pke.DecryptionKey.fromHex(GOLDEN_DEC_KEY_HEX);
        expect(parsed.isOk).toBe(true);
        expect(new Uint8Array(parsed.okValue!.toBytes())).toEqual(GOLDEN_DEC_KEY_BYTES);

        const with0x = pke.DecryptionKey.fromHex(`0x${GOLDEN_DEC_KEY_HEX}`);
        expect(with0x.isOk).toBe(true);
        expect(new Uint8Array(with0x.okValue!.toBytes())).toEqual(GOLDEN_DEC_KEY_BYTES);
    });

    it("golden bytes: EncryptionKey toHex / fromHex round-trip (derived from golden DK)", () => {
        const dk = pke.DecryptionKey.fromBytes(GOLDEN_DEC_KEY_BYTES).unwrapOrThrow("golden dk");
        const ek = pke.deriveEncryptionKey(dk);
        expect(ek.toHex()).toBe(GOLDEN_ENC_KEY_HEX);

        const parsed = pke.EncryptionKey.fromHex(GOLDEN_ENC_KEY_HEX);
        expect(parsed.isOk).toBe(true);
        expect(new Uint8Array(parsed.okValue!.toBytes())).toEqual(hexToBytes(GOLDEN_ENC_KEY_HEX));
    });

    it("golden bytes: Ciphertext toHex / fromHex round-trip", () => {
        const c = pke.Ciphertext.fromBytes(GOLDEN_CIPHERTEXT_BYTES).unwrapOrThrow("golden ct");
        expect(c.toHex()).toBe(GOLDEN_CIPHERTEXT_HEX);

        const parsed = pke.Ciphertext.fromHex(GOLDEN_CIPHERTEXT_HEX);
        expect(parsed.isOk).toBe(true);
        expect(new Uint8Array(parsed.okValue!.toBytes())).toEqual(GOLDEN_CIPHERTEXT_BYTES);
    });

    it("keygen keys: toHex / fromHex round-trip", () => {
        const { encryptionKey, decryptionKey } = pke.keygen();

        const dkBack = pke.DecryptionKey.fromHex(decryptionKey.toHex()).unwrapOrThrow("dk fromHex");
        expect(new Uint8Array(dkBack.toBytes())).toEqual(new Uint8Array(decryptionKey.toBytes()));

        const ekBack = pke.EncryptionKey.fromHex(encryptionKey.toHex()).unwrapOrThrow("ek fromHex");
        expect(new Uint8Array(ekBack.toBytes())).toEqual(new Uint8Array(encryptionKey.toBytes()));
    });

    it("deserialize returns Result (golden DK)", () => {
        const deserializer = new Deserializer(GOLDEN_DEC_KEY_BYTES);
        const parsed = pke.DecryptionKey.deserialize(deserializer);
        expect(parsed.isOk).toBe(true);
        expect(new Uint8Array(parsed.okValue!.toBytes())).toEqual(GOLDEN_DEC_KEY_BYTES);
    });

    it("fromBytes rejects trailing bytes (fromHex inherits)", () => {
        const withJunk = new Uint8Array([...GOLDEN_DEC_KEY_BYTES, 0x00]);
        expect(pke.DecryptionKey.fromBytes(withJunk).isOk).toBe(false);

        const cJunk = new Uint8Array([...GOLDEN_CIPHERTEXT_BYTES, 0xff]);
        expect(pke.Ciphertext.fromBytes(cJunk).isOk).toBe(false);

        expect(pke.DecryptionKey.fromHex(`${GOLDEN_DEC_KEY_HEX}00`).isOk).toBe(false);
    });
});
