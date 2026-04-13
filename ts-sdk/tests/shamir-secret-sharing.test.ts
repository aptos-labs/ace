// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { bls12_381 } from "@noble/curves/bls12-381";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
import { numberToBytesLE } from "@noble/curves/utils";
import { describe, expect, it } from "vitest";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { deriveDealingFrs, evalPoly, xInAllowedSet } from "../src/vss/dealing";
import * as g1 from "../src/vss/bls12381g1";
import * as g2 from "../src/vss/bls12381g2";
import * as facade from "../src/vss/index";
import { FR_MODULUS } from "../src/shamir_fr";

const TEST_SCALAR = 1234567890123456789012345678901n;
const TEST_SEED_HEX = "07".repeat(32);

/** Pinned BCS: SSS_WIRE_VERSION=4; unified dealing KDF `sha3_512` per slot; share wire u64 n/t (fixtures: generator, TEST_SCALAR, seed 0x07, n=4, t=3). */
const GOLDEN_G1_SECRET_HEX =
    "04356c760e4fc986a2a39f1a950f0000000000000000000000000000000000000097f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
const GOLDEN_G1_PUBLIC_COMMITMENT_HEX =
    "0497f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bba82600c8f0681b4b9bf0fcbfc698e9e3b742c1f3b3c136c5b49ec4c54feee1ff065a26821d0e0a5a56eb7b7f0348a6f7";
const GOLDEN_G1_SECRET_SHARE0_HEX =
    "040400000000000000030000000000000007070707070707070707070707070707070707070707070707070707070707071f12295cacb647396cca055a39ab38714369413fb72dc80a3b78f5774d7c5d5f6a9a76348654b92d3444b5aedfaca57e783130690b1b903ea5ef3f6385f6314697f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";

const GOLDEN_G2_SECRET_HEX =
    "04356c760e4fc986a2a39f1a950f0000000000000000000000000000000000000093e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";
const GOLDEN_G2_PUBLIC_COMMITMENT_HEX =
    "0493e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb882988228795bf6ec4c7335b19049d9b95b9aa5eaa61677719ba43620c283e95fe4071b8272e84ae563b02f255d2e0d0015f6de4412d44333de873401416a70f7adfb1f6808a457c9891313b07f8254028b2d8f59fc6a1cdf05506dee44e4daa1";
const GOLDEN_G2_SECRET_SHARE0_HEX =
    "04040000000000000003000000000000000707070707070707070707070707070707070707070707070707070707070707c0285564159369152ef86ff5c387ded4e6c634dc76eb4e6a412b3960e649d32aba566daac0b819a1d0a1ec3716064a10f4279174817580e3f015ac33f7d41e5393e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8";

function g1GeneratorSecret(): g1.Secret {
    const G = bls12_381.G1.Point.BASE as unknown as WeierstrassPoint<bigint>;
    return new g1.Secret(G, TEST_SCALAR);
}

function g2GeneratorSecret(): g2.Secret {
    const G = bls12_381.G2.Point.BASE as unknown as WeierstrassPoint<bigint>;
    return new g2.Secret(G, TEST_SCALAR);
}

/** `version` + `n:u64` + `t:u64` + `seed` + `x` + `y` — same prefix for G1/G2 shares; compressed `B` follows. */
const SHARE_OFFSET_X = 1 + 8 + 8 + 32;
const SHARE_OFFSET_Y = SHARE_OFFSET_X + 32;
const SHARE_OFFSET_B_G1 = SHARE_OFFSET_Y + 32;

function cloneBytes(bytes: Uint8Array): Uint8Array {
    return Uint8Array.from(bytes);
}

function flipByte(bytes: Uint8Array, index: number): Uint8Array {
    const c = cloneBytes(bytes);
    c[index] ^= 0xff;
    return c;
}

/** Unified wire: `scheme` (0 = G1) + inner BCS. */
function withG1Scheme(inner: Uint8Array): Uint8Array {
    const out = new Uint8Array(1 + inner.length);
    out[0] = 0;
    out.set(inner, 1);
    return out;
}

describe("shamir-secret-sharing G1", () => {
    it("rejects Secret with non-canonical Fr scalar (s >= FR_MODULUS)", () => {
        const golden = hexToBytes(GOLDEN_G1_SECRET_HEX);
        const bad = Uint8Array.from(golden);
        bad.set(numberToBytesLE(FR_MODULUS, 32), 1);
        expect(g1.Secret.fromBytes(bad).isOk).toBe(false);
    });

    it("rejects Secret.fromBytes when G1 base B is invalid", () => {
        const golden = hexToBytes(GOLDEN_G1_SECRET_HEX);
        expect(g1.Secret.fromBytes(flipByte(golden, 1 + 32)).isOk).toBe(false);
    });

    it("rejects PublicCommitment.fromBytes when G1 base B is invalid", () => {
        const golden = hexToBytes(GOLDEN_G1_PUBLIC_COMMITMENT_HEX);
        expect(g1.PublicCommitment.fromBytes(flipByte(golden, 1)).isOk).toBe(false);
    });

    it("rejects PublicCommitment.fromBytes when G1 s·B is invalid", () => {
        const golden = hexToBytes(GOLDEN_G1_PUBLIC_COMMITMENT_HEX);
        expect(g1.PublicCommitment.fromBytes(flipByte(golden, 1 + 48)).isOk).toBe(false);
    });

    it("rejects SecretShare.fromBytes when x is not canonical Fr", () => {
        const golden = hexToBytes(GOLDEN_G1_SECRET_SHARE0_HEX);
        const bad = cloneBytes(golden);
        bad.set(numberToBytesLE(FR_MODULUS, 32), SHARE_OFFSET_X);
        expect(g1.SecretShare.fromBytes(bad).isOk).toBe(false);
    });

    it("rejects SecretShare.fromBytes when y is not canonical Fr", () => {
        const golden = hexToBytes(GOLDEN_G1_SECRET_SHARE0_HEX);
        const bad = cloneBytes(golden);
        bad.set(numberToBytesLE(FR_MODULUS, 32), SHARE_OFFSET_Y);
        expect(g1.SecretShare.fromBytes(bad).isOk).toBe(false);
    });

    it("rejects SecretShare.fromBytes when G1 base B is invalid", () => {
        const golden = hexToBytes(GOLDEN_G1_SECRET_SHARE0_HEX);
        expect(g1.SecretShare.fromBytes(flipByte(golden, SHARE_OFFSET_B_G1)).isOk).toBe(false);
    });

    it("compatibility: Secret, PublicCommitment, SecretShare toBytes match pinned layout", () => {
        const secret = g1GeneratorSecret();
        expect(bytesToHex(secret.toBytes())).toBe(GOLDEN_G1_SECRET_HEX);
        const pc = g1.derivePublicCommitment({ secret });
        expect(bytesToHex(pc.toBytes())).toBe(GOLDEN_G1_PUBLIC_COMMITMENT_HEX);
        const seed = hexToBytes(TEST_SEED_HEX);
        const shares = g1.splitWithSeed({ secret, n: 4, t: 3, seed }).unwrapOrThrow("unwrap");
        expect(bytesToHex(shares[0].toBytes())).toBe(GOLDEN_G1_SECRET_SHARE0_HEX);
    });

    it("fromBytes round-trips toBytes for Secret, PublicCommitment, SecretShare", () => {
        const secret = g1.Secret.fromBytes(hexToBytes(GOLDEN_G1_SECRET_HEX)).unwrapOrThrow("secret parse");
        expect(bytesToHex(secret.toBytes())).toBe(GOLDEN_G1_SECRET_HEX);
        const pc = g1.PublicCommitment.fromBytes(hexToBytes(GOLDEN_G1_PUBLIC_COMMITMENT_HEX)).unwrapOrThrow("pc parse");
        expect(bytesToHex(pc.toBytes())).toBe(GOLDEN_G1_PUBLIC_COMMITMENT_HEX);
        const sh = g1.SecretShare.fromBytes(hexToBytes(GOLDEN_G1_SECRET_SHARE0_HEX)).unwrapOrThrow("share parse");
        expect(bytesToHex(sh.toBytes())).toBe(GOLDEN_G1_SECRET_SHARE0_HEX);
    });

    it("G1 submodule: toHex/fromHex and serialize/deserialize round-trip", () => {
        const secret = g1.Secret.fromBytes(hexToBytes(GOLDEN_G1_SECRET_HEX)).unwrapOrThrow("unwrap");
        expect(g1.Secret.fromHex(secret.toHex()).unwrapOrThrow("unwrap").toHex()).toBe(secret.toHex());
        const ser = new Serializer();
        secret.serialize(ser);
        const s2 = g1.Secret.deserialize(new Deserializer(ser.toUint8Array())).unwrapOrThrow("unwrap");
        expect(bytesToHex(s2.toBytes())).toBe(GOLDEN_G1_SECRET_HEX);
    });

    it("completeness: honest dealing — all x in derived set, y = f(x), every t-subset reconstructs", () => {
        const secret = g1GeneratorSecret();
        const seed = hexToBytes(TEST_SEED_HEX);
        const n = 4;
        const t = 3;
        const shares = g1.splitWithSeed({ secret, n, t, seed }).unwrapOrThrow("unwrap");
        const Bc = shares[0].base.toBytes(true) as Uint8Array;
        const draws = deriveDealingFrs({ splitConfig: { n: BigInt(n), t: BigInt(t) }, seed, baseCompressed: Bc });
        const coeffs = [TEST_SCALAR, ...draws.slice(0, t - 1)];
        const allowed = draws.slice(t - 1);
        for (const sh of shares) {
            expect(xInAllowedSet(sh.x, allowed)).toBe(true);
            expect(evalPoly(coeffs, sh.x)).toBe(sh.y);
        }
        const expectedPc = g1.derivePublicCommitment({ secret });
        const subsets = [
            [0, 1, 2],
            [0, 1, 3],
            [0, 2, 3],
            [1, 2, 3],
        ];
        for (const idx of subsets) {
            const sub = idx.map((i) => shares[i]);
            const rec = g1.reconstruct({ secretShares: sub }).unwrapOrThrow("reconstruct");
            expect(rec.scalar).toBe(TEST_SCALAR);
            expect(bytesToHex(rec.base.toBytes(true) as Uint8Array)).toBe(
                bytesToHex(secret.base.toBytes(true) as Uint8Array),
            );
            expect(bytesToHex(g1.derivePublicCommitment({ secret: rec }).toBytes())).toBe(bytesToHex(expectedPc.toBytes()));
        }
    });

    it("reconstruct fails with fewer than t distinct x", () => {
        const secret = g1GeneratorSecret();
        const seed = hexToBytes(TEST_SEED_HEX);
        const shares = g1.splitWithSeed({ secret, n: 4, t: 3, seed }).unwrapOrThrow("unwrap");
        const r = g1.reconstruct({ secretShares: [shares[0], shares[1]] });
        expect(r.isOk).toBe(false);
    });

    it("keygen → split → reconstruct round-trip", () => {
        const { secret } = g1.keygen();
        const shares = g1.split({ secret, n: 5, t: 3 }).unwrapOrThrow("unwrap");
        const rec = g1.reconstruct({ secretShares: [shares[0], shares[2], shares[4]] }).unwrapOrThrow("unwrap");
        expect(rec.scalar).toBe(secret.scalar);
        expect(bytesToHex(rec.base.toBytes(true) as Uint8Array)).toBe(bytesToHex(secret.base.toBytes(true) as Uint8Array));
    });

    it("rejects SplitConfig / seed / B mismatch across shares", () => {
        const secret = g1GeneratorSecret();
        const seed = hexToBytes(TEST_SEED_HEX);
        const a = g1.splitWithSeed({ secret, n: 4, t: 3, seed }).unwrapOrThrow("unwrap");
        const b = g1.splitWithSeed({ secret, n: 4, t: 3, seed: hexToBytes("08".repeat(32)) }).unwrapOrThrow("unwrap");
        const r = g1.reconstruct({ secretShares: [a[0], b[1], a[2]] });
        expect(r.isOk).toBe(false);
    });

    it("rejects x not in derived evaluation set", () => {
        const secret = g1GeneratorSecret();
        const seed = hexToBytes(TEST_SEED_HEX);
        const shares = g1.splitWithSeed({ secret, n: 4, t: 3, seed }).unwrapOrThrow("unwrap");
        const bad = new g1.SecretShare(
            shares[0].splitConfig,
            shares[0].seed,
            0n,
            shares[0].y,
            shares[0].base,
        );
        const r = g1.reconstruct({ secretShares: [shares[0], shares[1], bad] });
        expect(r.isOk).toBe(false);
    });

    it("rejects inconsistent y (polynomial check)", () => {
        const secret = g1GeneratorSecret();
        const seed = hexToBytes(TEST_SEED_HEX);
        const shares = g1.splitWithSeed({ secret, n: 4, t: 3, seed }).unwrapOrThrow("unwrap");
        const bad = new g1.SecretShare(
            shares[0].splitConfig,
            shares[0].seed,
            shares[0].x,
            shares[0].y + 1n,
            shares[0].base,
        );
        const r = g1.reconstruct({ secretShares: [shares[0], shares[1], bad] });
        expect(r.isOk).toBe(false);
    });
});

describe("shamir-secret-sharing G2", () => {
    it("rejects Secret with non-canonical Fr scalar (s >= FR_MODULUS)", () => {
        const golden = hexToBytes(GOLDEN_G2_SECRET_HEX);
        const bad = cloneBytes(golden);
        bad.set(numberToBytesLE(FR_MODULUS, 32), 1);
        expect(g2.Secret.fromBytes(bad).isOk).toBe(false);
    });

    it("rejects Secret.fromBytes when G2 base B is invalid", () => {
        const golden = hexToBytes(GOLDEN_G2_SECRET_HEX);
        expect(g2.Secret.fromBytes(flipByte(golden, 1 + 32)).isOk).toBe(false);
    });

    it("rejects PublicCommitment.fromBytes when first G2 point is invalid", () => {
        const golden = hexToBytes(GOLDEN_G2_PUBLIC_COMMITMENT_HEX);
        expect(g2.PublicCommitment.fromBytes(flipByte(golden, 1)).isOk).toBe(false);
    });

    it("rejects PublicCommitment.fromBytes when second G2 point is invalid", () => {
        const golden = hexToBytes(GOLDEN_G2_PUBLIC_COMMITMENT_HEX);
        expect(g2.PublicCommitment.fromBytes(flipByte(golden, 1 + 96)).isOk).toBe(false);
    });

    it("rejects SecretShare.fromBytes when x or y is not canonical Fr", () => {
        const golden = hexToBytes(GOLDEN_G2_SECRET_SHARE0_HEX);
        const badX = cloneBytes(golden);
        badX.set(numberToBytesLE(FR_MODULUS, 32), SHARE_OFFSET_X);
        expect(g2.SecretShare.fromBytes(badX).isOk).toBe(false);
        const badY = cloneBytes(golden);
        badY.set(numberToBytesLE(FR_MODULUS, 32), SHARE_OFFSET_Y);
        expect(g2.SecretShare.fromBytes(badY).isOk).toBe(false);
    });

    it("rejects SecretShare.fromBytes when G2 base B is invalid", () => {
        const golden = hexToBytes(GOLDEN_G2_SECRET_SHARE0_HEX);
        expect(g2.SecretShare.fromBytes(flipByte(golden, SHARE_OFFSET_B_G1)).isOk).toBe(false);
    });

    it("compatibility: Secret, PublicCommitment, SecretShare toBytes match pinned layout", () => {
        const secret = g2GeneratorSecret();
        expect(bytesToHex(secret.toBytes())).toBe(GOLDEN_G2_SECRET_HEX);
        const pc = g2.derivePublicCommitment({ secret });
        expect(bytesToHex(pc.toBytes())).toBe(GOLDEN_G2_PUBLIC_COMMITMENT_HEX);
        const seed = hexToBytes(TEST_SEED_HEX);
        const shares = g2.splitWithSeed({ secret, n: 4, t: 3, seed }).unwrapOrThrow("unwrap");
        expect(bytesToHex(shares[0].toBytes())).toBe(GOLDEN_G2_SECRET_SHARE0_HEX);
    });

    it("fromBytes round-trips toBytes", () => {
        const secret = g2.Secret.fromBytes(hexToBytes(GOLDEN_G2_SECRET_HEX)).unwrapOrThrow("unwrap");
        expect(bytesToHex(secret.toBytes())).toBe(GOLDEN_G2_SECRET_HEX);
        const pc = g2.PublicCommitment.fromBytes(hexToBytes(GOLDEN_G2_PUBLIC_COMMITMENT_HEX)).unwrapOrThrow("unwrap");
        expect(bytesToHex(pc.toBytes())).toBe(GOLDEN_G2_PUBLIC_COMMITMENT_HEX);
        const sh = g2.SecretShare.fromBytes(hexToBytes(GOLDEN_G2_SECRET_SHARE0_HEX)).unwrapOrThrow("unwrap");
        expect(bytesToHex(sh.toBytes())).toBe(GOLDEN_G2_SECRET_SHARE0_HEX);
    });

    it("completeness and round-trip with G2", () => {
        const secret = g2GeneratorSecret();
        const seed = hexToBytes(TEST_SEED_HEX);
        const shares = g2.splitWithSeed({ secret, n: 4, t: 3, seed }).unwrapOrThrow("unwrap");
        const Bc = shares[0].base.toBytes(true) as Uint8Array;
        const draws = deriveDealingFrs({ splitConfig: { n: 4n, t: 3n }, seed, baseCompressed: Bc });
        const coeffs = [TEST_SCALAR, ...draws.slice(0, 2)];
        const allowed = draws.slice(2);
        for (const sh of shares) {
            expect(xInAllowedSet(sh.x, allowed)).toBe(true);
            expect(evalPoly(coeffs, sh.x)).toBe(sh.y);
        }
        const rec = g2.reconstruct({ secretShares: [shares[0], shares[1], shares[2]] }).unwrapOrThrow("unwrap");
        expect(rec.scalar).toBe(TEST_SCALAR);
    });

    it("G2 submodule: toHex/fromHex round-trip on Secret", () => {
        const secret = g2.Secret.fromBytes(hexToBytes(GOLDEN_G2_SECRET_HEX)).unwrapOrThrow("unwrap");
        expect(g2.Secret.fromHex(secret.toHex()).unwrapOrThrow("unwrap").toHex()).toBe(secret.toHex());
    });
});

describe("shamir-secret-sharing unified index", () => {
    it("keygenBLS12381G1 → split → reconstruct round-trip", () => {
        const { secret } = facade.keygenBLS12381G1();
        const shares = facade.split({ secret, numShares: 5, threshold: 3 }).unwrapOrThrow("unwrap");
        const rec = facade.reconstruct({ secretShares: [shares[0], shares[2], shares[4]] }).unwrapOrThrow("unwrap");
        expect(rec.inner.scalar).toBe(secret.inner.scalar);
        expect(bytesToHex(rec.inner.base.toBytes(true) as Uint8Array)).toBe(
            bytesToHex(secret.inner.base.toBytes(true) as Uint8Array),
        );
    });

    it("unified Secret/PublicCommitment/SecretShare fromBytes ↔ toBytes", () => {
        const inner = g1.Secret.fromBytes(hexToBytes(GOLDEN_G1_SECRET_HEX)).unwrapOrThrow("unwrap");
        const u = facade.Secret.fromG1(inner);
        const back = facade.Secret.fromBytes(u.toBytes()).unwrapOrThrow("unwrap");
        expect(back.scheme).toBe(u.scheme);
        expect(bytesToHex(back.inner.toBytes())).toBe(GOLDEN_G1_SECRET_HEX);

        const innerPc = g1.PublicCommitment.fromBytes(hexToBytes(GOLDEN_G1_PUBLIC_COMMITMENT_HEX)).unwrapOrThrow("unwrap");
        const upc = facade.PublicCommitment.fromG1(innerPc);
        expect(bytesToHex(facade.PublicCommitment.fromBytes(upc.toBytes()).unwrapOrThrow("unwrap").inner.toBytes())).toBe(
            GOLDEN_G1_PUBLIC_COMMITMENT_HEX,
        );

        const innerSh = g1.SecretShare.fromBytes(hexToBytes(GOLDEN_G1_SECRET_SHARE0_HEX)).unwrapOrThrow("unwrap");
        const ush = facade.SecretShare.fromG1(innerSh);
        expect(bytesToHex(facade.SecretShare.fromBytes(ush.toBytes()).unwrapOrThrow("unwrap").inner.toBytes())).toBe(
            GOLDEN_G1_SECRET_SHARE0_HEX,
        );
    });

    it("unified fromHex and deserialize round-trip for Secret", () => {
        const inner = g1.Secret.fromBytes(hexToBytes(GOLDEN_G1_SECRET_HEX)).unwrapOrThrow("unwrap");
        const u = facade.Secret.fromG1(inner);
        const u2 = facade.Secret.fromHex(u.toHex()).unwrapOrThrow("unwrap");
        expect(bytesToHex(u2.toBytes())).toBe(bytesToHex(u.toBytes()));
        const ser = new Serializer();
        u.serialize(ser);
        const u3 = facade.Secret.deserialize(new Deserializer(ser.toUint8Array())).unwrapOrThrow("unwrap");
        expect(bytesToHex(u3.toBytes())).toBe(bytesToHex(u.toBytes()));
    });

    it("derivePublicCommitment on unified secret matches wrapped inner", () => {
        const inner = g1.Secret.fromBytes(hexToBytes(GOLDEN_G1_SECRET_HEX)).unwrapOrThrow("unwrap");
        const u = facade.Secret.fromG1(inner);
        const pc = facade.derivePublicCommitment({ secret: u });
        expect(bytesToHex(pc.inner.toBytes())).toBe(GOLDEN_G1_PUBLIC_COMMITMENT_HEX);
    });

    it("rejects mixed scheme shares on reconstruct", () => {
        const g1s = g1.splitWithSeed({
            secret: g1GeneratorSecret(),
            n: 3,
            t: 2,
            seed: hexToBytes(TEST_SEED_HEX),
        }).unwrapOrThrow("unwrap");
        const g2s = g2.splitWithSeed({
            secret: g2GeneratorSecret(),
            n: 3,
            t: 2,
            seed: hexToBytes(TEST_SEED_HEX),
        }).unwrapOrThrow("unwrap");
        const r = facade.reconstruct({
            secretShares: [facade.SecretShare.fromG1(g1s[0]), facade.SecretShare.fromG2(g2s[1])],
        });
        expect(r.isOk).toBe(false);
    });

    it("rejects unified Secret.fromBytes when inner G1 base is invalid", () => {
        const inner = hexToBytes(GOLDEN_G1_SECRET_HEX);
        expect(facade.Secret.fromBytes(withG1Scheme(flipByte(inner, 1 + 32))).isOk).toBe(false);
    });

    it("rejects unified PublicCommitment.fromBytes when inner G1 point is invalid", () => {
        const inner = hexToBytes(GOLDEN_G1_PUBLIC_COMMITMENT_HEX);
        expect(facade.PublicCommitment.fromBytes(withG1Scheme(flipByte(inner, 1 + 48))).isOk).toBe(false);
    });

    it("rejects unified SecretShare.fromBytes when inner G1 base is invalid", () => {
        const inner = hexToBytes(GOLDEN_G1_SECRET_SHARE0_HEX);
        expect(facade.SecretShare.fromBytes(withG1Scheme(flipByte(inner, SHARE_OFFSET_B_G1))).isOk).toBe(false);
    });
});
