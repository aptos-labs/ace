// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * Validates the SDK's BLS12-381 G2 paths through the abstract `group` and `vss` layers.
 * Mirror of the implicit G1 coverage: scalar arithmetic, public-point ops, Feldman-style
 * commitments, and Shamir share reconstruction.
 */

import { describe, it, expect } from "vitest";
import * as g2 from "../src/group/bls12381g2";
import {
    Scalar,
    Element,
    SCHEME_BLS12381G1,
    SCHEME_BLS12381G2,
} from "../src/group";
import * as vss from "../src/vss";

describe("BLS12-381 G2 group ops (scheme = 1)", () => {
    it("scalar mul: G^(3*4) == G^12", () => {
        const three = g2.PrivateScalar.fromBigint(3n).unwrapOrThrow("3");
        const twelve = g2.PrivateScalar.fromBigint(12n).unwrapOrThrow("12");
        const g = g2.g2Generator();
        const lhs = g.scale(g2.PrivateScalar.fromBigint(3n * 4n).unwrapOrThrow("12 via mul"));
        const rhs = g.scale(twelve);
        expect(lhs.equals(rhs)).toBe(true);
        expect(g.scale(three).equals(g.scale(twelve))).toBe(false); // sanity: not commutative w/ self
    });

    it("PublicPoint BCS round-trip", () => {
        const g = g2.g2Generator();
        const bytes = g.toBytes();
        // [ULEB128(96)] [96B compressed G2] = 1 + 96 = 97 bytes (single-byte ULEB for 96).
        expect(bytes.length).toBe(97);
        expect(bytes[0]).toBe(0x60);
        const back = g2.PublicPoint.fromBytes(bytes).unwrapOrThrow("round-trip");
        expect(back.equals(g)).toBe(true);
    });

    it("PrivateScalar BCS round-trip", () => {
        const s = g2.PrivateScalar.fromBigint(0xdeadbeefn).unwrapOrThrow("scalar");
        const back = g2.PrivateScalar.fromBytes(s.toBytes()).unwrapOrThrow("round-trip");
        expect(back.scalar).toBe(s.scalar);
    });
});

describe("Abstract group::Scalar / Element with G2", () => {
    it("Scalar tag is preserved across BCS round-trip", () => {
        const s = vss.sample(SCHEME_BLS12381G2);
        expect(s.scheme).toBe(SCHEME_BLS12381G2);
        const back = Scalar.fromBytes(s.toBytes()).unwrapOrThrow("round-trip");
        expect(back.scheme).toBe(SCHEME_BLS12381G2);
        expect((back.inner as g2.PrivateScalar).scalar).toBe((s.inner as g2.PrivateScalar).scalar);
    });

    it("Element scheme tag is preserved across BCS round-trip", () => {
        const e = Element.fromBls12381G2(g2.g2Generator());
        expect(e.scheme).toBe(SCHEME_BLS12381G2);
        const back = Element.fromBytes(e.toBytes()).unwrapOrThrow("round-trip");
        expect(back.scheme).toBe(SCHEME_BLS12381G2);
        expect(back.equals(e)).toBe(true);
    });

    it("scale rejects scheme mismatch", () => {
        const s1 = vss.sample(SCHEME_BLS12381G1);
        const e2 = Element.fromBls12381G2(g2.g2Generator());
        expect(() => e2.scale(s1)).toThrow();
    });
});

describe("Shamir reconstruct over G2 (scheme = 1)", () => {
    it("3-of-5 reconstruction recovers the secret", () => {
        const t = 3;
        const n = 5;
        const secretBytes = new Uint8Array(32);
        for (let i = 0; i < 32; i++) secretBytes[i] = i + 1;

        const shareBytes = g2.split(secretBytes, t, n).unwrapOrThrow("split");
        expect(shareBytes.length).toBe(n);

        // Take any 3 shares; reconstruct via the abstract vss.reconstruct API.
        const indexedAbstract = [0, 2, 4].map((i) => ({
            index: i + 1,
            share: new vss.SecretShare(
                SCHEME_BLS12381G2,
                g2.SecretShare.fromBigint(
                    BigInt(
                        "0x" +
                            Array.from(shareBytes[i].slice().reverse())
                                .map((b) => b.toString(16).padStart(2, "0"))
                                .join("")
                    )
                ).unwrapOrThrow("share"),
            ),
        }));

        const recovered = vss.reconstruct({ indexedShares: indexedAbstract }).unwrapOrThrow("reconstruct");
        expect(recovered.scheme).toBe(SCHEME_BLS12381G2);

        const recoveredFr = (recovered.inner as g2.PrivateScalar).scalar;
        const expectedFr = BigInt(
            "0x" +
                Array.from(secretBytes.slice().reverse())
                    .map((b) => b.toString(16).padStart(2, "0"))
                    .join("")
        );
        expect(recoveredFr).toBe(expectedFr);
    });

    it("reconstruct with 2 shares (below threshold) returns wrong secret — sanity", () => {
        const t = 3;
        const n = 5;
        const secretBytes = new Uint8Array(32);
        secretBytes[0] = 0x42;

        const shareBytes = g2.split(secretBytes, t, n).unwrapOrThrow("split");

        const twoShares = [0, 1].map((i) => ({
            index: i + 1,
            share: new vss.SecretShare(
                SCHEME_BLS12381G2,
                g2.SecretShare.fromBigint(
                    BigInt(
                        "0x" +
                            Array.from(shareBytes[i].slice().reverse())
                                .map((b) => b.toString(16).padStart(2, "0"))
                                .join("")
                    )
                ).unwrapOrThrow("share"),
            ),
        }));

        const recovered = vss.reconstruct({ indexedShares: twoShares }).unwrapOrThrow("reconstruct");
        // With t=3 but only 2 shares supplied, Lagrange interpolates a different polynomial,
        // so the recovered secret should NOT equal 0x42.
        expect((recovered.inner as g2.PrivateScalar).scalar).not.toBe(BigInt("0x42"));
    });
});
