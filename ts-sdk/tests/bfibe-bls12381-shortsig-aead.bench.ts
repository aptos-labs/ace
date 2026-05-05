// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Microbenchmarks for BF-IBE bls12381-shortsig-aead.
 *
 * Run with:    pnpm vitest bench --run bfibe-bls12381-shortsig-aead.bench
 *
 * Reports ops/sec for keygen, encrypt, and decrypt (1-of-1 share). Pairing dominates
 * encrypt/decrypt; the AEAD body scales linearly with plaintext size but is far cheaper.
 */
import { bench, describe } from "vitest";
import { bls12_381 } from "@noble/curves/bls12-381";
import {
    keygenForTesting,
    derivePublicKey,
    encrypt,
    decrypt,
    IdentityDecryptionKeyShare,
} from "../src/t-ibe/bfibe-bls12381-shortsig-aead";

const utf8 = (s: string) => new TextEncoder().encode(s);
const ID = utf8("bench-identity");
const DST = utf8("BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/HASH_ID_TO_CURVE");

const SIZES = [
    { label: "32B", bytes: 32 },
    { label: "1KB", bytes: 1024 },
    { label: "64KB", bytes: 64 * 1024 },
];

describe("BF-IBE shortsig-aead: keygen + derive", () => {
    bench("keygen + derivePublicKey", () => {
        const msk = keygenForTesting();
        derivePublicKey(msk);
    });
});

for (const { label, bytes } of SIZES) {
    describe(`BF-IBE shortsig-aead: encrypt ${label}`, () => {
        let pinned: { mpk: ReturnType<typeof derivePublicKey>; pt: Uint8Array };
        bench(
            `encrypt ${label}`,
            () => {
                encrypt({ mpk: pinned.mpk, id: ID, plaintext: pinned.pt }).unwrapOrThrow("encrypt");
            },
            {
                setup: () => {
                    const msk = keygenForTesting();
                    const mpk = derivePublicKey(msk);
                    const pt = new Uint8Array(bytes);
                    for (let i = 0; i < bytes; i++) pt[i] = i & 0xff;
                    pinned = { mpk, pt };
                },
            },
        );
    });

    describe(`BF-IBE shortsig-aead: decrypt ${label}`, () => {
        let pinned: { share: IdentityDecryptionKeyShare; ct: ReturnType<typeof encrypt> extends infer R ? any : never };
        bench(
            `decrypt ${label}`,
            () => {
                decrypt({ idkShares: [pinned.share], ciphertext: pinned.ct }).unwrapOrThrow("decrypt");
            },
            {
                setup: () => {
                    const msk = keygenForTesting();
                    const mpk = derivePublicKey(msk);
                    const pt = new Uint8Array(bytes);
                    for (let i = 0; i < bytes; i++) pt[i] = i & 0xff;
                    const ct = encrypt({ mpk, id: ID, plaintext: pt }).unwrapOrThrow("encrypt");
                    const idPoint = bls12_381.G1.hashToCurve(ID, { DST });
                    const idkFull = (idPoint as any).multiply(msk.scalar);
                    const share = new IdentityDecryptionKeyShare(1n, idkFull, undefined);
                    pinned = { share, ct };
                },
            },
        );
    });
}
