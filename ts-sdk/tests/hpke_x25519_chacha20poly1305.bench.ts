// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Microbenchmarks for HPKE-X25519-HKDF-SHA256-ChaCha20-Poly1305.
 *
 * Run with:    pnpm vitest bench --run hpke_x25519_chacha20poly1305.bench
 *
 * vitest reports ops/sec and mean time. Numbers depend on machine and Node version,
 * but relative cost should be: keygen ≈ encrypt > decrypt ≫ (AEAD body, which scales
 * linearly with plaintext size).
 */
import { bench, describe } from "vitest";
import * as hpke from "../src/pke/hpke_x25519_chacha20poly1305";

const SIZES = [
    { label: "32B", bytes: 32 },
    { label: "1KB", bytes: 1024 },
    { label: "64KB", bytes: 64 * 1024 },
];

describe("HPKE bench: keygen", () => {
    bench("keygen", async () => {
        await hpke.keygen();
    });
});

for (const { label, bytes } of SIZES) {
    describe(`HPKE bench: encrypt ${label}`, () => {
        let pinned: { ek: hpke.EncryptionKey; pt: Uint8Array };

        bench(
            `encrypt ${label}`,
            async () => {
                await hpke.encrypt({ encryptionKey: pinned.ek, plaintext: pinned.pt });
            },
            {
                setup: async () => {
                    const { encryptionKey } = await hpke.keygen();
                    const pt = new Uint8Array(bytes);
                    for (let i = 0; i < bytes; i++) pt[i] = i & 0xff;
                    pinned = { ek: encryptionKey, pt };
                },
            },
        );
    });

    describe(`HPKE bench: decrypt ${label}`, () => {
        let pinned: { dk: hpke.DecryptionKey; ct: hpke.Ciphertext };

        bench(
            `decrypt ${label}`,
            async () => {
                await hpke.decrypt(pinned.dk, pinned.ct);
            },
            {
                setup: async () => {
                    const { encryptionKey, decryptionKey } = await hpke.keygen();
                    const pt = new Uint8Array(bytes);
                    for (let i = 0; i < bytes; i++) pt[i] = i & 0xff;
                    const ct = await hpke.encrypt({ encryptionKey, plaintext: pt });
                    pinned = { dk: decryptionKey, ct };
                },
            },
        );
    });
}
