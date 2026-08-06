// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { AccountAddress, Serializer } from "@aptos-labs/ts-sdk";
import { bytesToHex } from "@noble/hashes/utils";
import * as group from "../src/group";
import * as pke from "../src/pke";
import { DiscoveryViewV0, DiscoveryChainReader } from "../src/_internal/discovery";

// Encryption key derived from a golden ElGamal Ristretto255 decryption key (see tests/pke.test.ts).
const GOLDEN_ENC_KEY_HEX =
    "0020f84e5c1c19630f29093c84052819f02bc2158dbad8590e9121fa4c59d20e1741209e441d841f1c37c7104a3eb43f51447306c8cb2294cc6ac1be23f32f23c72b71";

const ENC_KEY = pke.EncryptionKey.fromHex(GOLDEN_ENC_KEY_HEX).unwrapOrThrow("golden enc key");
// A valid G2 element (the generator); reused for base/result/share — validity is what matters here.
const EL = group.Element.fromBls12381G2(group.bls12381G2.g2Generator());

interface NodeFixture { addr: string; endpoint?: string; encKey: pke.EncryptionKey }
interface SessionFixture { addr: string; basePoint: group.Element; resultPk: group.Element; sharePks: group.Element[] }

// Build the BCS of ace::network::DiscoveryViewV0 the way Move's `bcs::to_bytes` would: an inline
// (empty) StateViewV0, then the nodes vector, then the sessions vector.
function buildBlob(nodes: NodeFixture[], sessions: SessionFixture[]): Uint8Array {
    const s = new Serializer();
    // StateViewV0: epoch, start, duration, cur_nodes[], cur_threshold, secrets[], proposals[], epoch_change_info?
    s.serializeU64(0n);
    s.serializeU64(0n);
    s.serializeU64(0n);
    s.serializeU32AsUleb128(0);
    s.serializeU64(0n);
    s.serializeU32AsUleb128(0);
    s.serializeU32AsUleb128(0);
    s.serializeU8(0);

    s.serializeU32AsUleb128(nodes.length);
    for (const n of nodes) {
        AccountAddress.fromString(n.addr).serialize(s);
        if (n.endpoint === undefined) {
            s.serializeU8(0);
        } else {
            s.serializeU8(1);
            s.serializeStr(n.endpoint);
        }
        n.encKey.serialize(s);
    }

    s.serializeU32AsUleb128(sessions.length);
    for (const ses of sessions) {
        AccountAddress.fromString(ses.addr).serialize(s);
        ses.basePoint.serialize(s);
        ses.resultPk.serialize(s);
        s.serializeU32AsUleb128(ses.sharePks.length);
        for (const sp of ses.sharePks) sp.serialize(s);
    }
    return s.toUint8Array();
}

const NODE_A = "0x000000000000000000000000000000000000000000000000000000000000000a";
const NODE_B = "0x000000000000000000000000000000000000000000000000000000000000000b";
const SESSION = "0x00000000000000000000000000000000000000000000000000000000000000c1";

const fixtureNodes: NodeFixture[] = [
    { addr: NODE_A, endpoint: "https://node-a.example/", encKey: ENC_KEY },
    { addr: NODE_B, endpoint: undefined, encKey: ENC_KEY }, // no endpoint registered
];
const fixtureSessions: SessionFixture[] = [
    { addr: SESSION, basePoint: EL, resultPk: EL, sharePks: [EL, EL] },
];
const blob = () => buildBlob(fixtureNodes, fixtureSessions);

const long = (a: string) => AccountAddress.fromString(a).toStringLong();

describe("DiscoveryViewV0.fromBytes", () => {
    it("round-trips the typed Move BCS layout", () => {
        const view = DiscoveryViewV0.fromBytes(blob());

        expect(view.state.epoch).toBe(0);
        expect(view.state.curNodes).toEqual([]);

        const a = view.nodes.get(long(NODE_A))!;
        expect(a.endpoint).toBe("https://node-a.example/");
        expect(a.encKey.toHex()).toBe(ENC_KEY.toHex());

        const b = view.nodes.get(long(NODE_B))!;
        expect(b.endpoint).toBeUndefined();

        const ses = view.sessions.get(long(SESSION))!;
        expect(ses.basePoint.equals(EL)).toBe(true);
        expect(ses.resultPk!.equals(EL)).toBe(true);
        expect(ses.sharePks).toHaveLength(2);
        expect(ses.sharePks[0].equals(EL)).toBe(true);
    });

    it("rejects trailing bytes", () => {
        const b = blob();
        const bad = new Uint8Array(b.length + 1);
        bad.set(b);
        expect(() => DiscoveryViewV0.fromBytes(bad)).toThrow(/trailing bytes/);
    });
});

describe("DiscoveryChainReader", () => {
    afterEach(() => vi.unstubAllGlobals());

    // The server returns the plain hex body; the SDK also tolerates a legacy JSON envelope.
    function stubFetch(mode: "hex" | "json" = "hex") {
        const hex = "0x" + bytesToHex(blob());
        const body = mode === "hex" ? hex : JSON.stringify({ discoveryViewV0Bcs: hex });
        const fetchMock = vi.fn(async () => ({ ok: true, status: 200, text: async () => body }));
        vi.stubGlobal("fetch", fetchMock);
        return fetchMock;
    }

    it("answers every typed read from a single fetch", async () => {
        const fetchMock = stubFetch();
        const reader = new DiscoveryChainReader("https://discovery.example/");

        expect((await reader.networkState()).epoch).toBe(0);
        expect(await reader.workerEndpoint(NODE_A)).toBe("https://node-a.example/");
        expect((await reader.workerEncKey(NODE_A)).toHex()).toBe(ENC_KEY.toHex());

        const s = await reader.session(SESSION, true);
        expect(s.basePoint.equals(EL)).toBe(true);
        expect(s.resultPk!.equals(EL)).toBe(true);
        expect(s.sharePks).toHaveLength(2);

        // Snapshot fetched exactly once for the whole operation.
        expect(fetchMock).toHaveBeenCalledTimes(1);
    });

    it("also accepts a JSON-enveloped body", async () => {
        stubFetch("json");
        const reader = new DiscoveryChainReader("https://discovery.example/");
        expect((await reader.networkState()).epoch).toBe(0);
    });

    it("throws for a node missing its endpoint", async () => {
        stubFetch();
        const reader = new DiscoveryChainReader("https://discovery.example/");
        await expect(reader.workerEndpoint(NODE_B)).rejects.toThrow(/no registered endpoint/);
    });

    it("throws for an unknown session address", async () => {
        stubFetch();
        const reader = new DiscoveryChainReader("https://discovery.example/");
        const unknown = "0x0000000000000000000000000000000000000000000000000000000000000099";
        await expect(reader.session(unknown, true)).rejects.toThrow(/not in snapshot/);
    });
});
