// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Microbenchmarks for Hybrid-X25519-MLKEM768-HKDF-SHA256-ChaCha20Poly1305.
 *
 * Run with:    pnpm vitest bench --run hybrid_x25519_mlkem768_chacha20poly1305.bench
 */
import { bench, describe } from "vitest";
import * as hybrid from "../src/pke/hybrid_x25519_mlkem768_chacha20poly1305";

const SIZES = [
    { label: "32B", bytes: 32 },
    { label: "1KB", bytes: 1024 },
    { label: "64KB", bytes: 64 * 1024 },
];

describe("Hybrid PKE bench: keygen", () => {
    bench("keygen", async () => {
        await hybrid.keygen();
    });
});

for (const { label, bytes } of SIZES) {
    describe(`Hybrid PKE bench: encrypt ${label}`, () => {
        let pinned: { ek: hybrid.EncryptionKey; pt: Uint8Array };

        bench(
            `encrypt ${label}`,
            async () => {
                await hybrid.encrypt({ encryptionKey: pinned.ek, plaintext: pinned.pt });
            },
            {
                setup: async () => {
                    const { encryptionKey } = await hybrid.keygen();
                    const pt = new Uint8Array(bytes);
                    for (let i = 0; i < bytes; i++) pt[i] = i & 0xff;
                    pinned = { ek: encryptionKey, pt };
                },
            },
        );
    });

    describe(`Hybrid PKE bench: decrypt ${label}`, () => {
        let pinned: { dk: hybrid.DecryptionKey; ct: hybrid.Ciphertext };

        bench(
            `decrypt ${label}`,
            async () => {
                await hybrid.decrypt(pinned.dk, pinned.ct);
            },
            {
                setup: async () => {
                    const { encryptionKey, decryptionKey } = await hybrid.keygen();
                    const pt = new Uint8Array(bytes);
                    for (let i = 0; i < bytes; i++) pt[i] = i & 0xff;
                    const ct = await hybrid.encrypt({ encryptionKey, plaintext: pt });
                    pinned = { dk: decryptionKey, ct };
                },
            },
        );
    });
}
