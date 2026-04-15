// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { AccountAddress } from "@aptos-labs/ts-sdk";
import { hexToBytes } from "@noble/hashes/utils";
import { bls12_381 } from "@noble/curves/bls12-381";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
import * as Bls12381Fr from "../src/vss/bls12381-fr";
import * as pke from "../src/pke";
import {
    PcsCommitment,
    PrivateShareMessage,
    DealerContribution0,
    DealerContribution1,
    Session,
    SecretShare,
    PrivateScalar,
    PublicPoint,
    SCHEME_BLS12381G1,
} from "../src/vss/index";

// ── Helpers ──────────────────────────────────────────────────────────────────

function g1Gen(): WeierstrassPoint<bigint> {
    return bls12_381.G1.ProjectivePoint.BASE as unknown as WeierstrassPoint<bigint>;
}

/** A deterministic pke.Ciphertext for golden tests (from pke.test.ts golden). */
const GOLDEN_CIPHERTEXT_BYTES = hexToBytes(
    "00209664c19dd000f772c25ec65b4b4fccda7233a11b19c9c6ba9df43e55cd5ad06520f64f3d4419543d892e967726e831315da6dc52753b2db562e050e743fd38717b10f99cfbfd1a4a73d75e272be8a9682907206dffa55ba1c65e7ed865bd02b15bf58933139a4bd1022b94b99fe18ac7938d59",
);

function goldenCiphertext(): pke.Ciphertext {
    return pke.Ciphertext.fromBytes(GOLDEN_CIPHERTEXT_BYTES).unwrapOrThrow("golden ciphertext");
}

/** Known AccountAddress constants */
const ADDR_1 = AccountAddress.fromString("0x0000000000000000000000000000000000000000000000000000000000000001");
const ADDR_2 = AccountAddress.fromString("0x0000000000000000000000000000000000000000000000000000000000000002");

// ── Goldens ──────────────────────────────────────────────────────────────────

// PcsCommitment (no scheme prefix): [01]=len1, [30]=uleb128(48), [48-byte G1 gen]
const GOLDEN_PCS_COMMITMENT =
    "013097f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac5" +
    "86c55e83ff97a1aeffb3af00adb22c6bb";

// DealerContribution1: vector<Option<Fr>> = [Some(Fr(1)), None]
// [02]=len2, [01]=Some, [20]=uleb128(32), Fr(1) LE (01 + 31 zero bytes), [00]=None
const GOLDEN_DC1 =
    "020120010000000000000000000000000000000000000000000000000000000000000000";

// ── PcsCommitment ─────────────────────────────────────────────────────────────

describe("PcsCommitment serde", () => {
    function makeCommitment(): PcsCommitment {
        return PcsCommitment.fromBls12381G1(new Bls12381Fr.PcsCommitment([g1Gen()]));
    }

    it("round-trip: single G1 point", () => {
        const c = makeCommitment();
        const c2 = PcsCommitment.fromBytes(c.toBytes(), SCHEME_BLS12381G1).unwrapOrThrow("round-trip");
        expect(c2.toHex()).toBe(c.toHex());
    });

    it("golden hex: pins wire format (no scheme prefix)", () => {
        const c = makeCommitment();
        expect(c.toHex()).toBe(GOLDEN_PCS_COMMITMENT);
    });

    it("golden deserialization: fromHex round-trips", () => {
        const c = PcsCommitment.fromHex(GOLDEN_PCS_COMMITMENT, SCHEME_BLS12381G1).unwrapOrThrow("golden");
        expect(c.toHex()).toBe(GOLDEN_PCS_COMMITMENT);
    });

    it("rejects trailing bytes", () => {
        expect(PcsCommitment.fromHex(GOLDEN_PCS_COMMITMENT + "00", SCHEME_BLS12381G1).isOk).toBe(false);
    });
});

// ── PublicPoint ───────────────────────────────────────────────────────────────

describe("PublicPoint serde", () => {
    function makePt(): PublicPoint {
        return PublicPoint.fromBls12381G1(new Bls12381Fr.PublicPoint(g1Gen()));
    }

    it("round-trip", () => {
        const pt = makePt();
        const pt2 = PublicPoint.fromBytes(pt.toBytes()).unwrapOrThrow("round-trip");
        expect(pt2.toHex()).toBe(pt.toHex());
    });

    it("golden hex: scheme=0 prefix + 48-byte G1 generator", () => {
        const pt = makePt();
        // [00] scheme + [30] uleb128(48) + 48 bytes
        expect(pt.toHex()).toBe("00" + "30" + "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb");
    });
});

// ── PrivateShareMessage ───────────────────────────────────────────────────────

describe("PrivateShareMessage serde", () => {
    function makeShare(): SecretShare {
        const inner = new Bls12381Fr.SecretShare(2n);
        return new SecretShare(SCHEME_BLS12381G1, inner);
    }

    it("round-trip", () => {
        const msg = new PrivateShareMessage(makeShare());
        const msg2 = PrivateShareMessage.fromBytes(msg.toBytes()).unwrapOrThrow("round-trip");
        expect(msg2.toHex()).toBe(msg.toHex());
    });

    it("golden hex: [scheme] [uleb128(32)] [Fr(2) LE]", () => {
        const msg = new PrivateShareMessage(makeShare());
        // scheme=0, then 32-byte Fr(2) LE
        const expected = "00" + "20" + "0200000000000000000000000000000000000000000000000000000000000000";
        expect(msg.toHex()).toBe(expected);
    });

    it("rejects trailing bytes", () => {
        const msg = new PrivateShareMessage(makeShare());
        expect(PrivateShareMessage.fromHex(msg.toHex() + "00").isOk).toBe(false);
    });
});

// ── DealerContribution0 ───────────────────────────────────────────────────────

describe("DealerContribution0 serde", () => {
    function makeCommitment(): PcsCommitment {
        return PcsCommitment.fromBls12381G1(new Bls12381Fr.PcsCommitment([g1Gen()]));
    }

    it("round-trip: with share messages", () => {
        const commitment = makeCommitment();
        const ct = goldenCiphertext();
        const dc0 = new DealerContribution0({ sharingPolyCommitment: commitment, privateShareMessages: [ct, ct], dealerState: ct });
        const dc0b = DealerContribution0.fromBytes(dc0.toBytes()).unwrapOrThrow("round-trip");
        expect(dc0b.toHex()).toBe(dc0.toHex());
    });

    it("round-trip: empty share messages", () => {
        const commitment = makeCommitment();
        const ct = goldenCiphertext();
        const dc0 = new DealerContribution0({ sharingPolyCommitment: commitment, privateShareMessages: [], dealerState: ct });
        const dc0b = DealerContribution0.fromBytes(dc0.toBytes()).unwrapOrThrow("round-trip empty");
        expect(dc0b.toHex()).toBe(dc0.toHex());
    });

    it("rejects trailing bytes", () => {
        const commitment = makeCommitment();
        const ct = goldenCiphertext();
        const dc0 = new DealerContribution0({ sharingPolyCommitment: commitment, privateShareMessages: [], dealerState: ct });
        expect(DealerContribution0.fromHex(dc0.toHex() + "00").isOk).toBe(false);
    });
});

// ── DealerContribution1 ───────────────────────────────────────────────────────

describe("DealerContribution1 serde", () => {
    function makeDC1(): DealerContribution1 {
        // [Some(Fr(1)), None]
        return new DealerContribution1([1n, undefined]);
    }

    it("round-trip", () => {
        const dc1 = makeDC1();
        const dc1b = DealerContribution1.fromBytes(dc1.toBytes()).unwrapOrThrow("round-trip");
        expect(dc1b.toHex()).toBe(dc1.toHex());
    });

    it("golden hex: pins wire format", () => {
        const dc1 = makeDC1();
        expect(dc1.toHex()).toBe(GOLDEN_DC1);
    });

    it("round-trip: all None", () => {
        const dc1 = new DealerContribution1([undefined, undefined, undefined]);
        const dc1b = DealerContribution1.fromBytes(dc1.toBytes()).unwrapOrThrow("all-None round-trip");
        expect(dc1b.toHex()).toBe(dc1.toHex());
    });

    it("rejects trailing bytes", () => {
        const dc1 = makeDC1();
        expect(DealerContribution1.fromHex(dc1.toHex() + "00").isOk).toBe(false);
    });
});

// ── Session ──────────────────────────────────────────────────────────────────

describe("Session serde", () => {
    it("round-trip: no optional fields", () => {
        const session = Session.fromBytes(makeMinimalSessionBytes()).unwrapOrThrow("round-trip");
        const session2 = Session.fromBytes(session.toBytes()).unwrapOrThrow("double round-trip");
        expect(session2.toHex()).toBe(session.toHex());
    });

    it("round-trip: with optional fields set", () => {
        const commitment = PcsCommitment.fromBls12381G1(new Bls12381Fr.PcsCommitment([g1Gen()]));
        const ct = goldenCiphertext();
        const dc0 = new DealerContribution0({ sharingPolyCommitment: commitment, privateShareMessages: [], dealerState: ct });
        const dc1 = new DealerContribution1([1n, undefined]);
        const withOptionals = buildSession({ dc0, dc1 });
        const withOptionals2 = Session.fromBytes(withOptionals.toBytes()).unwrapOrThrow("with-optionals round-trip");
        expect(withOptionals2.toHex()).toBe(withOptionals.toHex());
    });

    it("golden hex: minimal session (no optional fields)", () => {
        const session = Session.fromBytes(makeMinimalSessionBytes()).unwrapOrThrow("golden");
        expect(session.toBytes()).toEqual(makeMinimalSessionBytes());
    });

    it("rejects trailing bytes", () => {
        const bytes = makeMinimalSessionBytes();
        const extra = new Uint8Array(bytes.length + 1);
        extra.set(bytes);
        expect(Session.fromBytes(extra).isOk).toBe(false);
    });

    it("rejects bad option tag", () => {
        const bytes = makeMinimalSessionBytes();
        // dc0Tag at offset 83
        const bad = new Uint8Array(bytes);
        bad[83] = 2;
        expect(Session.fromBytes(bad).isOk).toBe(false);
    });
});

// ── Helpers for Session tests ─────────────────────────────────────────────────

function makeMinimalSessionBytes(): Uint8Array {
    const { Serializer } = require("@aptos-labs/ts-sdk");
    const s = new Serializer();
    ADDR_1.serialize(s);
    s.serializeU32AsUleb128(1);
    ADDR_2.serialize(s);
    s.serializeU64(2);
    s.serializeU8(0);                       // secretScheme = 0
    s.serializeU8(0);
    s.serializeU64(0);
    s.serializeU8(0);                       // dealerContribution0 = None
    s.serializeU32AsUleb128(1);
    s.serializeBool(false);
    s.serializeU8(0);                       // dealerContribution1 = None
    return s.toUint8Array();
}

function buildSession({ dc0, dc1 }: { dc0?: DealerContribution0; dc1?: DealerContribution1 }): Session {
    const { Serializer } = require("@aptos-labs/ts-sdk");
    const s = new Serializer();
    ADDR_1.serialize(s);
    s.serializeU32AsUleb128(1);
    ADDR_2.serialize(s);
    s.serializeU64(3);
    s.serializeU8(0);
    s.serializeU8(1);
    s.serializeU64(1700000000000000);
    if (dc0 === undefined) {
        s.serializeU8(0);
    } else {
        s.serializeU8(1);
        dc0.serialize(s);
    }
    s.serializeU32AsUleb128(1);
    s.serializeBool(true);
    if (dc1 === undefined) {
        s.serializeU8(0);
    } else {
        s.serializeU8(1);
        dc1.serialize(s);
    }
    return Session.fromBytes(s.toUint8Array()).unwrapOrThrow("buildSession");
}
