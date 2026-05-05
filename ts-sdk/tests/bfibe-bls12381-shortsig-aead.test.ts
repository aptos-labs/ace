// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Unit tests for the bfibe-bls12381-shortsig-aead t-ibe variant.
 *
 * Mirrors what the existing t-ibe.test.ts covers for shortpk-otp-hmac, but
 * targets the new variant: master pk in G2, identity hash in G1, IDK shares in G1,
 * AEAD-based DEM (HKDF-SHA256 + ChaCha20-Poly1305).
 */

import { describe, it, expect } from "vitest";
import { bls12_381 } from "@noble/curves/bls12-381";
import { numberToBytesLE, bytesToNumberLE } from "@noble/curves/utils";
import { randomBytes } from "@noble/hashes/utils";
import {
    MasterPrivateKey,
    MasterPublicKey,
    IdentityDecryptionKeyShare,
    Ciphertext,
    keygenForTesting,
    derivePublicKey,
    encrypt,
    encryptWithRandomness,
    verifyShare,
    decrypt,
} from "../src/t-ibe/bfibe-bls12381-shortsig-aead";
import { frMod } from "../src/group/bls12381fr";

const utf8 = (s: string) => new TextEncoder().encode(s);

/** Naive Shamir split over Fr: returns `n` shares y_i = f(i) for a degree-(t-1) polynomial
 *  with f(0) = secret. */
function shamirShares(secret: bigint, t: number, n: number): { x: bigint; y: bigint }[] {
    const coeffs: bigint[] = [secret];
    for (let i = 1; i < t; i++) coeffs.push(frMod(bytesToNumberLE(randomBytes(32))));
    const out: { x: bigint; y: bigint }[] = [];
    for (let i = 1; i <= n; i++) {
        let y = 0n;
        let xPow = 1n;
        const x = BigInt(i);
        for (const c of coeffs) {
            y = frMod(y + c * xPow);
            xPow = frMod(xPow * x);
        }
        out.push({ x, y });
    }
    return out;
}

describe("BF-IBE bls12381-shortsig-aead", () => {
    it("end-to-end encrypt/decrypt with full master sk (degenerate threshold = 1-of-1)", () => {
        const msk = keygenForTesting();
        const mpk = derivePublicKey(msk);
        const id = utf8("alice@example.com");
        const plaintext = utf8("hello, BF-IBE shortsig");

        const ct = encrypt({ mpk, id, plaintext }).unwrapOrThrow("encrypt");

        // The full identity decryption key is s · H_G1(id). We package it as a single
        // share at evalPoint=1 so Lagrange recovers it as-is.
        const idPoint = bls12_381.G1.hashToCurve(id, {
            DST: utf8("BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/HASH_ID_TO_CURVE"),
        });
        const idkFull = (idPoint as any).multiply(msk.scalar);
        const single = new IdentityDecryptionKeyShare(1n, idkFull, undefined);

        const recovered = decrypt({ idkShares: [single], ciphertext: ct }).unwrapOrThrow("decrypt");
        expect(recovered).toEqual(plaintext);
    });

    it("threshold reconstruction: t-of-n IDK shares Lagrange-combine and decrypt", () => {
        const msk = keygenForTesting();
        const mpk = derivePublicKey(msk);
        const id = utf8("bob@example.com");
        const plaintext = utf8("threshold-recoverable plaintext");

        const ct = encrypt({ mpk, id, plaintext }).unwrapOrThrow("encrypt");

        const t = 3;
        const n = 5;
        const points = shamirShares(msk.scalar, t, n);

        // Each share holder computes idk_i = s_i · H_G1(id).
        const idPoint = bls12_381.G1.hashToCurve(id, {
            DST: utf8("BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/HASH_ID_TO_CURVE"),
        });
        const allShares = points.map(p =>
            new IdentityDecryptionKeyShare(p.x, (idPoint as any).multiply(p.y), undefined)
        );

        // Pick an arbitrary t-subset (3 shares: indices 0, 2, 4).
        const subset = [allShares[0], allShares[2], allShares[4]];
        const recovered = decrypt({ idkShares: subset, ciphertext: ct }).unwrapOrThrow("decrypt");
        expect(recovered).toEqual(plaintext);
    });

    it("encrypt is randomised: repeated calls give different ciphertexts but same decryption", () => {
        const msk = keygenForTesting();
        const mpk = derivePublicKey(msk);
        const id = utf8("carol@example.com");
        const plaintext = utf8("plaintext");

        const ct1 = encrypt({ mpk, id, plaintext }).unwrapOrThrow("encrypt-1");
        const ct2 = encrypt({ mpk, id, plaintext }).unwrapOrThrow("encrypt-2");
        expect(ct1.toBytes()).not.toEqual(ct2.toBytes());

        const idPoint = bls12_381.G1.hashToCurve(id, {
            DST: utf8("BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/HASH_ID_TO_CURVE"),
        });
        const idkFull = (idPoint as any).multiply(msk.scalar);
        const share = new IdentityDecryptionKeyShare(1n, idkFull, undefined);

        expect(decrypt({ idkShares: [share], ciphertext: ct1 }).unwrapOrThrow("dec-1")).toEqual(plaintext);
        expect(decrypt({ idkShares: [share], ciphertext: ct2 }).unwrapOrThrow("dec-2")).toEqual(plaintext);
    });

    it("encryptWithRandomness is deterministic in the randomness", () => {
        const msk = keygenForTesting();
        const mpk = derivePublicKey(msk);
        const id = utf8("dave@example.com");
        const plaintext = utf8("deterministic");
        const r = numberToBytesLE(123456789n, 32);

        const ct1 = encryptWithRandomness(mpk, id, plaintext, r);
        const ct2 = encryptWithRandomness(mpk, id, plaintext, r);
        expect(ct1.toBytes()).toEqual(ct2.toBytes());
    });

    it("AEAD rejects tampered ciphertext", () => {
        const msk = keygenForTesting();
        const mpk = derivePublicKey(msk);
        const id = utf8("erin@example.com");
        const ct = encrypt({ mpk, id, plaintext: utf8("nope") }).unwrapOrThrow("encrypt");

        const id_pt = bls12_381.G1.hashToCurve(id, {
            DST: utf8("BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/HASH_ID_TO_CURVE"),
        });
        const idkFull = (id_pt as any).multiply(msk.scalar);
        const share = new IdentityDecryptionKeyShare(1n, idkFull, undefined);

        const tamperedAead = new Uint8Array(ct.aeadCt);
        tamperedAead[0] ^= 0x01;
        const tampered = new Ciphertext(ct.c0, tamperedAead);

        const r = decrypt({ idkShares: [share], ciphertext: tampered });
        expect(r.isOk).toBe(false);
    });

    it("decryption with wrong identity fails (AEAD tag mismatch)", () => {
        const msk = keygenForTesting();
        const mpk = derivePublicKey(msk);
        const ct = encrypt({ mpk, id: utf8("right-id"), plaintext: utf8("secret") }).unwrapOrThrow("encrypt");

        const wrongIdPoint = bls12_381.G1.hashToCurve(utf8("wrong-id"), {
            DST: utf8("BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/HASH_ID_TO_CURVE"),
        });
        const wrongShare = new IdentityDecryptionKeyShare(1n, (wrongIdPoint as any).multiply(msk.scalar), undefined);

        const r = decrypt({ idkShares: [wrongShare], ciphertext: ct });
        expect(r.isOk).toBe(false);
    });

    it("verifyShare accepts well-formed shares and rejects shares for a different evaluation point", () => {
        const msk = keygenForTesting();
        const mpk = derivePublicKey(msk);
        const id = utf8("frank@example.com");

        const t = 2;
        const n = 3;
        const points = shamirShares(msk.scalar, t, n);

        const idPoint = bls12_381.G1.hashToCurve(id, {
            DST: utf8("BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/HASH_ID_TO_CURVE"),
        });

        // share_pks[i] = s_i · basePoint (in G2)
        const sharePks = points.map(p => mpk.basePoint.multiply(p.y));
        const idkShares = points.map(p =>
            new IdentityDecryptionKeyShare(p.x, (idPoint as any).multiply(p.y), undefined)
        );

        // Each share should verify against its own sharePk.
        for (let i = 0; i < n; i++) {
            expect(verifyShare({
                basePoint: mpk.basePoint,
                sharePk: sharePks[i],
                id,
                share: idkShares[i],
            })).toBe(true);
        }

        // Share i must NOT verify against share j's pk (i ≠ j).
        expect(verifyShare({
            basePoint: mpk.basePoint,
            sharePk: sharePks[1],
            id,
            share: idkShares[0],
        })).toBe(false);
    });

    it("MasterPublicKey BCS round-trip", () => {
        const msk = keygenForTesting();
        const mpk = derivePublicKey(msk);
        const back = MasterPublicKey.fromBytes(mpk.toBytes()).unwrapOrThrow("MasterPublicKey round-trip");
        expect(back.toBytes()).toEqual(mpk.toBytes());
    });

    it("MasterPrivateKey BCS round-trip", () => {
        const msk = keygenForTesting();
        const back = MasterPrivateKey.fromBytes(msk.toBytes()).unwrapOrThrow("MasterPrivateKey round-trip");
        expect(back.toBytes()).toEqual(msk.toBytes());
    });

    it("Ciphertext BCS round-trip", () => {
        const msk = keygenForTesting();
        const mpk = derivePublicKey(msk);
        const ct = encrypt({ mpk, id: utf8("xyz"), plaintext: utf8("payload") }).unwrapOrThrow("encrypt");
        const back = Ciphertext.fromBytes(ct.toBytes()).unwrapOrThrow("Ciphertext round-trip");
        expect(back.toBytes()).toEqual(ct.toBytes());
    });

    it("IdentityDecryptionKeyShare BCS round-trip", () => {
        const msk = keygenForTesting();
        const id = utf8("share-roundtrip");
        const idPoint = bls12_381.G1.hashToCurve(id, {
            DST: utf8("BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/HASH_ID_TO_CURVE"),
        });
        const share = new IdentityDecryptionKeyShare(7n, (idPoint as any).multiply(msk.scalar), undefined);
        const back = IdentityDecryptionKeyShare.fromBytes(share.toBytes()).unwrapOrThrow("share round-trip");
        expect(back.toBytes()).toEqual(share.toBytes());
        expect(back.evalPoint).toBe(7n);
    });

    it("Ciphertext c0 is in G2 (96B compressed) — confirms 'shortsig' wire shape", () => {
        const msk = keygenForTesting();
        const mpk = derivePublicKey(msk);
        const ct = encrypt({ mpk, id: utf8("id"), plaintext: utf8("p") }).unwrapOrThrow("encrypt");
        const c0Bytes = (ct.c0 as any).toBytes();
        expect(c0Bytes.length).toBe(96);
    });

    it("IDK share is in G1 (48B compressed) — confirms 'shortsig' wire shape", () => {
        const msk = keygenForTesting();
        const idPoint = bls12_381.G1.hashToCurve(utf8("id"), {
            DST: utf8("BONEH_FRANKLIN_BLS12381_SHORTSIG_AEAD/HASH_ID_TO_CURVE"),
        });
        const share = new IdentityDecryptionKeyShare(1n, (idPoint as any).multiply(msk.scalar), undefined);
        const shareBytes = (share.idkShare as any).toBytes();
        expect(shareBytes.length).toBe(48);
    });
});
