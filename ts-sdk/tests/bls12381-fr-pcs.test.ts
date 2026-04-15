// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { bls12_381 } from "@noble/curves/bls12-381";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
import { PcsCommitment, PublicPoint } from "../src/vss/bls12381-fr";

// ── Golden hex constants (pin the exact BCS wire format) ─────────────────────

/** PcsCommitment { vValues: [G1 generator] } */
const GOLDEN_PCS_COMMITMENT_HEX =
    "013097f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac5" +
    "86c55e83ff97a1aeffb3af00adb22c6bb";

// ── Helpers ──────────────────────────────────────────────────────────────────

function g1Gen(): WeierstrassPoint<bigint> {
    return bls12_381.G1.ProjectivePoint.BASE as unknown as WeierstrassPoint<bigint>;
}

// ── PcsCommitment ────────────────────────────────────────────────────────────

describe("PcsCommitment serde", () => {
    it("round-trip: single G1 point", () => {
        const c = new PcsCommitment([g1Gen()]);
        const c2 = PcsCommitment.fromBytes(c.toBytes()).unwrapOrThrow("round-trip");
        expect(c2.vValues.length).toBe(1);
        expect(c2.vValues[0].toBytes()).toEqual(c.vValues[0].toBytes());
    });

    it("round-trip: multiple G1 points", () => {
        const pts = [g1Gen(), g1Gen().double(), g1Gen().negate()];
        const c = new PcsCommitment(pts);
        const c2 = PcsCommitment.fromBytes(c.toBytes()).unwrapOrThrow("round-trip multi");
        expect(c2.vValues.length).toBe(3);
        for (let i = 0; i < 3; i++) {
            expect(c2.vValues[i].toBytes()).toEqual(pts[i].toBytes());
        }
    });

    it("round-trip: empty commitment", () => {
        const c = new PcsCommitment([]);
        const c2 = PcsCommitment.fromBytes(c.toBytes()).unwrapOrThrow("round-trip empty");
        expect(c2.vValues.length).toBe(0);
    });

    it("golden hex: pins BCS wire format", () => {
        const c = new PcsCommitment([g1Gen()]);
        expect(c.toHex()).toBe(GOLDEN_PCS_COMMITMENT_HEX);
    });

    it("golden deserialization: fromHex yields G1 generator", () => {
        const c = PcsCommitment.fromHex(GOLDEN_PCS_COMMITMENT_HEX).unwrapOrThrow("golden");
        expect(c.vValues.length).toBe(1);
        expect(c.vValues[0].toBytes()).toEqual(g1Gen().toBytes());
    });

    it("rejects invalid G1 point bytes", () => {
        const bad = "01" + "30" + "00".repeat(48);
        expect(PcsCommitment.fromHex(bad).isOk).toBe(false);
    });
});

// ── PublicPoint ──────────────────────────────────────────────────────────────

describe("PublicPoint serde", () => {
    it("round-trip: G1 generator", () => {
        const pt = new PublicPoint(g1Gen());
        const pt2 = PublicPoint.fromBytes(pt.toBytes()).unwrapOrThrow("round-trip");
        expect(pt2.toBytes()).toEqual(pt.toBytes());
    });

    it("golden hex: 48-byte compressed G1 generator", () => {
        const pt = new PublicPoint(g1Gen());
        const expected = "30" + "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb";
        expect(pt.toHex()).toBe(expected);
    });

    it("rejects non-48-byte input", () => {
        expect(PublicPoint.fromBytes(new Uint8Array(32)).isOk).toBe(false);
    });
});
