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
    PcsOpening,
    PcsBatchOpening,
    PrivateShareMessage,
    DealerContribution0,
    DealerContribution1,
    Session,
    SecretShare,
    Secret,
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

/** Bls12381Fr inner types */
const INNER_OPENING_1_2 = new Bls12381Fr.PcsOpening(1n, 2n);
const INNER_BATCH_12_34 = new Bls12381Fr.PcsBatchOpening([1n, 2n], [3n, 4n]);
const INNER_COMMITMENT_GEN = new Bls12381Fr.PcsCommitment([g1Gen()]);

// ── Goldens from bls12381-fr.ts tests (already pinned) ──────────────────────
const INNER_GOLDEN_PCS_OPENING =
    "200100000000000000000000000000000000000000000000000000000000000000" +
    "200200000000000000000000000000000000000000000000000000000000000000";

const INNER_GOLDEN_PCS_BATCH_OPENING =
    "0220010000000000000000000000000000000000000000000000000000000000000020020000000000000000000000000000000000000000000000000000000000000002200300000000000000000000000000000000000000000000000000000000000000200400000000000000000000000000000000000000000000000000000000000000";

const INNER_GOLDEN_PCS_COMMITMENT =
    "013097f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac5" +
    "86c55e83ff97a1aeffb3af00adb22c6bb";

// Wrapper goldens: prepend scheme byte 0x00
const GOLDEN_PCS_OPENING_WRAPPER = "00" + INNER_GOLDEN_PCS_OPENING;
const GOLDEN_PCS_BATCH_OPENING_WRAPPER = "00" + INNER_GOLDEN_PCS_BATCH_OPENING;
const GOLDEN_PCS_COMMITMENT_WRAPPER = "00" + INNER_GOLDEN_PCS_COMMITMENT;

// ── PcsCommitment (wrapper) ──────────────────────────────────────────────────

describe("PcsCommitment wrapper serde", () => {
    it("round-trip: single G1 point", () => {
        const c = PcsCommitment.fromBls12381Fr(INNER_COMMITMENT_GEN);
        const c2 = PcsCommitment.fromBytes(c.toBytes()).unwrapOrThrow("round-trip");
        expect(c2.toHex()).toBe(c.toHex());
    });

    it("golden hex: pins wire format", () => {
        const c = PcsCommitment.fromBls12381Fr(INNER_COMMITMENT_GEN);
        expect(c.toHex()).toBe(GOLDEN_PCS_COMMITMENT_WRAPPER);
    });

    it("golden deserialization: fromHex round-trips", () => {
        const c = PcsCommitment.fromHex(GOLDEN_PCS_COMMITMENT_WRAPPER).unwrapOrThrow("golden");
        expect(c.toHex()).toBe(GOLDEN_PCS_COMMITMENT_WRAPPER);
    });

    it("rejects trailing bytes", () => {
        expect(PcsCommitment.fromHex(GOLDEN_PCS_COMMITMENT_WRAPPER + "00").isOk).toBe(false);
    });

    it("rejects unknown scheme", () => {
        const bad = "01" + INNER_GOLDEN_PCS_COMMITMENT;
        expect(PcsCommitment.fromHex(bad).isOk).toBe(false);
    });
});

// ── PcsOpening (wrapper) ─────────────────────────────────────────────────────

describe("PcsOpening wrapper serde", () => {
    it("round-trip", () => {
        const o = PcsOpening.fromBls12381Fr(INNER_OPENING_1_2);
        const o2 = PcsOpening.fromBytes(o.toBytes()).unwrapOrThrow("round-trip");
        expect(o2.toHex()).toBe(o.toHex());
    });

    it("golden hex: pins wire format", () => {
        const o = PcsOpening.fromBls12381Fr(INNER_OPENING_1_2);
        expect(o.toHex()).toBe(GOLDEN_PCS_OPENING_WRAPPER);
    });

    it("golden deserialization: fromHex round-trips", () => {
        const o = PcsOpening.fromHex(GOLDEN_PCS_OPENING_WRAPPER).unwrapOrThrow("golden");
        expect(o.toHex()).toBe(GOLDEN_PCS_OPENING_WRAPPER);
    });

    it("rejects trailing bytes", () => {
        expect(PcsOpening.fromHex(GOLDEN_PCS_OPENING_WRAPPER + "00").isOk).toBe(false);
    });
});

// ── PcsBatchOpening (wrapper) ────────────────────────────────────────────────

describe("PcsBatchOpening wrapper serde", () => {
    it("round-trip", () => {
        const b = PcsBatchOpening.fromBls12381Fr(INNER_BATCH_12_34);
        const b2 = PcsBatchOpening.fromBytes(b.toBytes()).unwrapOrThrow("round-trip");
        expect(b2.toHex()).toBe(b.toHex());
    });

    it("golden hex: pins wire format", () => {
        const b = PcsBatchOpening.fromBls12381Fr(INNER_BATCH_12_34);
        expect(b.toHex()).toBe(GOLDEN_PCS_BATCH_OPENING_WRAPPER);
    });

    it("golden deserialization: fromHex round-trips", () => {
        const b = PcsBatchOpening.fromHex(GOLDEN_PCS_BATCH_OPENING_WRAPPER).unwrapOrThrow("golden");
        expect(b.toHex()).toBe(GOLDEN_PCS_BATCH_OPENING_WRAPPER);
    });
});

// ── PrivateShareMessage ──────────────────────────────────────────────────────

describe("PrivateShareMessage serde", () => {
    function makeShare(): SecretShare {
        // SecretShare(scheme=0, Bls12381Fr.SecretShare(x=1n, y=2n))
        const innerHex = new Bls12381Fr.SecretShare(1n, 2n).toHex();
        return SecretShare.fromHex("00" + innerHex).unwrapOrThrow("make share");
    }

    function makeProof(): PcsOpening {
        return PcsOpening.fromBls12381Fr(INNER_OPENING_1_2);
    }

    it("round-trip", () => {
        const msg = new PrivateShareMessage(makeShare(), makeProof());
        const msg2 = PrivateShareMessage.fromBytes(msg.toBytes()).unwrapOrThrow("round-trip");
        expect(msg2.toHex()).toBe(msg.toHex());
    });

    it("golden hex: pins wire format", () => {
        const msg = new PrivateShareMessage(makeShare(), makeProof());
        // share bytes: "00" + inner_SecretShare(1n,2n) hex
        // proof bytes: "00" + inner_PcsOpening(1n,2n) hex
        const shareHex = "00" + new Bls12381Fr.SecretShare(1n, 2n).toHex();
        const proofHex = GOLDEN_PCS_OPENING_WRAPPER;
        expect(msg.toHex()).toBe(shareHex + proofHex);
    });

    it("golden deserialization: fromHex round-trips", () => {
        const msg = new PrivateShareMessage(makeShare(), makeProof());
        const hex = msg.toHex();
        const msg2 = PrivateShareMessage.fromHex(hex).unwrapOrThrow("golden");
        expect(msg2.toHex()).toBe(hex);
    });

    it("rejects trailing bytes", () => {
        const msg = new PrivateShareMessage(makeShare(), makeProof());
        expect(PrivateShareMessage.fromHex(msg.toHex() + "00").isOk).toBe(false);
    });
});

// ── DealerContribution0 ──────────────────────────────────────────────────────

describe("DealerContribution0 serde", () => {
    it("round-trip: with share messages", () => {
        const commitment = PcsCommitment.fromBls12381Fr(INNER_COMMITMENT_GEN);
        const ct = goldenCiphertext();
        const dc0 = new DealerContribution0({ sharingPolyCommitment: commitment, privateShareMessages: [ct, ct], dealerState: ct });
        const dc0b = DealerContribution0.fromBytes(dc0.toBytes()).unwrapOrThrow("round-trip");
        expect(dc0b.toHex()).toBe(dc0.toHex());
    });

    it("round-trip: empty share messages", () => {
        const commitment = PcsCommitment.fromBls12381Fr(INNER_COMMITMENT_GEN);
        const ct = goldenCiphertext();
        const dc0 = new DealerContribution0({ sharingPolyCommitment: commitment, privateShareMessages: [], dealerState: ct });
        const dc0b = DealerContribution0.fromBytes(dc0.toBytes()).unwrapOrThrow("round-trip empty");
        expect(dc0b.toHex()).toBe(dc0.toHex());
    });

    it("rejects trailing bytes", () => {
        const commitment = PcsCommitment.fromBls12381Fr(INNER_COMMITMENT_GEN);
        const ct = goldenCiphertext();
        const dc0 = new DealerContribution0({ sharingPolyCommitment: commitment, privateShareMessages: [], dealerState: ct });
        expect(DealerContribution0.fromHex(dc0.toHex() + "00").isOk).toBe(false);
    });
});

// ── DealerContribution1 ──────────────────────────────────────────────────────

describe("DealerContribution1 serde", () => {
    it("round-trip", () => {
        const dc1 = new DealerContribution1(PcsBatchOpening.fromBls12381Fr(INNER_BATCH_12_34));
        const dc1b = DealerContribution1.fromBytes(dc1.toBytes()).unwrapOrThrow("round-trip");
        expect(dc1b.toHex()).toBe(dc1.toHex());
    });

    it("golden hex: pins wire format", () => {
        const dc1 = new DealerContribution1(PcsBatchOpening.fromBls12381Fr(INNER_BATCH_12_34));
        // DealerContribution1 just serializes pcsBatchOpening (the outer wrapper)
        expect(dc1.toHex()).toBe(GOLDEN_PCS_BATCH_OPENING_WRAPPER);
    });

    it("rejects trailing bytes", () => {
        const dc1 = new DealerContribution1(PcsBatchOpening.fromBls12381Fr(INNER_BATCH_12_34));
        expect(DealerContribution1.fromHex(dc1.toHex() + "00").isOk).toBe(false);
    });
});

// ── Session ──────────────────────────────────────────────────────────────────

describe("Session serde", () => {
    function makeSecret(): Secret {
        // Secret(scheme=0, Bls12381Fr.Secret(scalar=1n))
        const innerHex = new Bls12381Fr.Secret(1n).toHex();
        return Secret.fromHex("00" + innerHex).unwrapOrThrow("make secret");
    }

    it("round-trip: no optional fields", () => {
        const session = Session.fromBytes(makeMinimalSessionBytes()).unwrapOrThrow("round-trip");
        const session2 = Session.fromBytes(session.toBytes()).unwrapOrThrow("double round-trip");
        expect(session2.toHex()).toBe(session.toHex());
    });

    it("round-trip: with optional fields set", () => {
        const commitment = PcsCommitment.fromBls12381Fr(INNER_COMMITMENT_GEN);
        const ct = goldenCiphertext();
        const dc0 = new DealerContribution0({ sharingPolyCommitment: commitment, privateShareMessages: [], dealerState: ct });
        const dc1 = new DealerContribution1(PcsBatchOpening.fromBls12381Fr(INNER_BATCH_12_34));

        // Build a session by hand with fromBytes, then mutate via round-trip
        const base = Session.fromBytes(makeMinimalSessionBytes()).unwrapOrThrow("base");
        // We can't mutate the private constructor, so serialize directly
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
        // Craft bytes with dc0Tag=2 (invalid)
        const bytes = makeMinimalSessionBytes();
        // The dc0Tag is at offset: 32(dealer) + 1+32(holders) + 8(threshold) + 1(secretScheme) + 1(stateCode) + 8(dealTimeMicros) = 83
        const bad = new Uint8Array(bytes);
        bad[83] = 2; // corrupt dc0 option tag
        expect(Session.fromBytes(bad).isOk).toBe(false);
    });
});

// ── Helpers for Session tests ─────────────────────────────────────────────────

/**
 * Builds the minimal valid BCS bytes for a Session:
 *   dealer=ADDR_1, shareHolders=[ADDR_2], threshold=2, secretScheme=0, stateCode=0,
 *   dealTimeMicros=0, dealerContribution0=None, shareHolderAcks=[false], dealerContribution1=None
 */
function makeMinimalSessionBytes(): Uint8Array {
    // We build it by constructing a Session via deserialize from a manually crafted byte array
    // Alternatively, use the serializer directly:
    const { Serializer } = require("@aptos-labs/ts-sdk");
    const s = new Serializer();
    ADDR_1.serialize(s);                    // dealer: 32 bytes
    s.serializeU32AsUleb128(1);             // shareHolders length = 1
    ADDR_2.serialize(s);                    // shareHolders[0]: 32 bytes
    s.serializeU64(2);                      // threshold = 2
    s.serializeU8(0);                       // secretScheme = 0
    s.serializeU8(0);                       // stateCode = 0
    s.serializeU64(0);                      // dealTimeMicros = 0
    s.serializeU8(0);                       // dealerContribution0 = None
    s.serializeU32AsUleb128(1);             // shareHolderAcks length = 1
    s.serializeBool(false);                 // shareHolderAcks[0] = false
    s.serializeU8(0);                       // dealerContribution1 = None
    return s.toUint8Array();
}

function buildSession({ dc0, dc1 }: { dc0?: DealerContribution0; dc1?: DealerContribution1 }): Session {
    const { Serializer, Deserializer } = require("@aptos-labs/ts-sdk");
    const s = new Serializer();
    ADDR_1.serialize(s);
    s.serializeU32AsUleb128(1);
    ADDR_2.serialize(s);
    s.serializeU64(3);
    s.serializeU8(0);
    s.serializeU8(1); // stateCode = 1 (RECIPIENT_ACK)
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
