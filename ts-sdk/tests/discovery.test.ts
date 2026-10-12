// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { afterEach, describe, expect, it, vi } from "vitest";
import { AccountAddress, Ed25519PublicKey, Ed25519Signature, Serializer } from "@aptos-labs/ts-sdk";
import { bytesToHex } from "@noble/hashes/utils";
import * as group from "../src/group";
import * as pke from "../src/pke";
import { DiscoveryViewV0, DiscoveryChainReader } from "../src/_internal/discovery";
import { AceDeployment, ContractID } from "../src/_internal/common";
import { fetchIdentityKeySharesCustomFlow } from "../src/ibe-for-aptos/decrypt-custom-flow";
import { BasicDecryptionSession } from "../src/ibe-for-aptos/basic-decryption-session";
import { DerivationSession } from "../src/vrf-for-aptos";

// Encryption key derived from a golden ElGamal Ristretto255 decryption key (see tests/pke.test.ts).
const GOLDEN_ENC_KEY_HEX =
    "0020f84e5c1c19630f29093c84052819f02bc2158dbad8590e9121fa4c59d20e1741209e441d841f1c37c7104a3eb43f51447306c8cb2294cc6ac1be23f32f23c72b71";

const ENC_KEY = pke.EncryptionKey.fromHex(GOLDEN_ENC_KEY_HEX).unwrapOrThrow("golden enc key");
// A valid G2 element (the generator); reused for base/result/share — validity is what matters here.
const EL = group.Element.fromBls12381G2(group.bls12381G2.g2Generator());

interface NodeFixture { addr: string; endpoint?: string; encKey: pke.EncryptionKey }
interface SessionFixture { addr: string; basePoint: group.Element; resultPk: group.Element; sharePks: group.Element[] }
interface StateFixture {
    epoch: number;
    curNodes: string[];
    threshold: number;
    secrets: { keypairId: string; currentSession: string }[];
}

// Build the BCS of ace::network::DiscoveryViewV0 the way Move's `bcs::to_bytes` would: an inline
// StateViewV0, then the nodes vector, then the sessions vector.
function buildBlob(nodes: NodeFixture[], sessions: SessionFixture[], state?: StateFixture): Uint8Array {
    const s = new Serializer();
    // StateViewV0: epoch, start, duration, cur_nodes[], cur_threshold, secrets[], proposals[], epoch_change_info?
    s.serializeU64(BigInt(state?.epoch ?? 0));
    s.serializeU64(0n);
    s.serializeU64(0n);
    s.serializeU32AsUleb128(state?.curNodes.length ?? 0);
    for (const addr of state?.curNodes ?? []) AccountAddress.fromString(addr).serialize(s);
    s.serializeU64(BigInt(state?.threshold ?? 0));
    s.serializeU32AsUleb128(state?.secrets.length ?? 0);
    for (const secret of state?.secrets ?? []) {
        AccountAddress.fromString(secret.currentSession).serialize(s);
        AccountAddress.fromString(secret.keypairId).serialize(s);
        s.serializeU8(1); // BF-IBE G2
        s.serializeU64(2n); // expected usage
        s.serializeStr("");
    }
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
const NEXT_SESSION = "0x00000000000000000000000000000000000000000000000000000000000000c2";
const KEYPAIR = "0x00000000000000000000000000000000000000000000000000000000000000d1";

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

        // Snapshot fetched exactly once for the whole operation, from the base URL + /bcs
        // (trailing slash collapsed).
        expect(fetchMock).toHaveBeenCalledTimes(1);
        expect(fetchMock.mock.calls[0][0]).toBe("https://discovery.example/bcs");
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

// Reproduce the SDK's epoch-boundary race without depending on localnet timing: the first
// discovery GET contains epoch 10/session C1, while every later GET contains epoch 11/session C2.
// Each test drives a real SDK flow and checks that it reaches the worker using only the first
// snapshot. The worker deliberately returns 503; reaching it proves the SDK did not fail earlier
// with "session C1 not in snapshot". The test-epoch-buffer scenario also replays an epoch-2
// signed request after real discovery and workers reach epoch 3; these tests isolate the
// cross-GET consistency rule without relying on the timing of a live epoch change.
describe("SDK discovery reads across a simulated epoch change", () => {
    afterEach(() => {
        vi.unstubAllGlobals();
        vi.restoreAllMocks();
    });

    const deployment = new AceDeployment({
        apiEndpoint: "https://fullnode.example/v1",
        contractAddr: AccountAddress.fromString("0x1"),
        discoveryUrl: "https://discovery.example",
    });
    const oldBlob = buildBlob(
        [{ addr: NODE_A, endpoint: "https://node-a.example/", encKey: ENC_KEY }],
        [{ addr: SESSION, basePoint: EL, resultPk: EL, sharePks: [EL] }],
        { epoch: 10, curNodes: [NODE_A], threshold: 1, secrets: [{ keypairId: KEYPAIR, currentSession: SESSION }] },
    );
    const newBlob = buildBlob(
        [{ addr: NODE_A, endpoint: "https://node-a.example/", encKey: ENC_KEY }],
        [{ addr: NEXT_SESSION, basePoint: EL, resultPk: EL, sharePks: [EL] }],
        { epoch: 11, curNodes: [NODE_A], threshold: 1, secrets: [{ keypairId: KEYPAIR, currentSession: NEXT_SESSION }] },
    );

    function switchEpochAfterFirstRead() {
        let discoveryReads = 0;
        let workerReads = 0;
        vi.stubGlobal("fetch", vi.fn(async (url: string) => {
            if (url === "https://discovery.example/bcs") {
                const blob = discoveryReads++ === 0 ? oldBlob : newBlob;
                return { ok: true, status: 200, text: async () => "0x" + bytesToHex(blob) };
            }
            if (url === "https://node-a.example/") {
                workerReads++;
                return { ok: false, status: 503, text: async () => "test worker unavailable" };
            }
            throw new Error(`unexpected URL ${url}`);
        }));
        return { discoveryReads: () => discoveryReads, workerReads: () => workerReads };
    }

    it("keeps the Aptos custom-flow request, session and nodes on the original epoch", async () => {
        const reads = switchEpochAfterFirstRead();
        vi.spyOn(console, "log").mockImplementation(() => {});
        const caller = await pke.keygen();

        const result = await fetchIdentityKeySharesCustomFlow({
            label: new Uint8Array([1]),
            encPk: caller.encryptionKey.toBytes(),
            encSk: caller.decryptionKey.toBytes(),
            payload: new Uint8Array([2]),
            aceDeployment: deployment,
            keypairId: AccountAddress.fromString(KEYPAIR),
            chainId: 1,
            moduleAddr: AccountAddress.fromString("0x1"),
            moduleName: "test",
        });

        expect(result.isOk).toBe(false); // The test worker returns 503, after all snapshot lookups succeed.
        expect(String(result.errValue)).toContain("need 1 identity key shares");
        expect(reads.discoveryReads()).toBe(1);
        expect(reads.workerReads()).toBe(1);
    });

    it("keeps a two-phase basic request on its signing snapshot", async () => {
        const reads = switchEpochAfterFirstRead();
        vi.spyOn(console, "log").mockImplementation(() => {});
        const session = await BasicDecryptionSession.create({
            aceDeployment: deployment,
            keypairId: AccountAddress.fromString(KEYPAIR),
            chainId: 1,
            moduleAddr: AccountAddress.fromString("0x1"),
            moduleName: "test",
            label: new Uint8Array([1]),
            primitive: 1,
        });
        await session.getRequestToSign();
        const proof = {
            userAddr: AccountAddress.fromString("0x2"),
            publicKey: new Ed25519PublicKey(new Uint8Array(32)),
            signature: new Ed25519Signature(new Uint8Array(64)),
            fullMessage: "test",
        };
        const request = await session.buildPerNodeRequest({
            ...proof,
            targetEndpoint: "https://node-a.example/",
        });
        expect(request.isOk).toBe(true);
        expect(request.okValue?.epoch).toBe(10);

        const shares = await session.fetchIdentityKeySharesWithProof(proof);
        expect(shares.isOk).toBe(false); // The test worker returns 503 after the session lookup succeeds.
        expect(String(shares.errValue)).toContain("need 1 identity key shares");
        expect(reads.discoveryReads()).toBe(1);
        expect(reads.workerReads()).toBe(1);

        await session.getRequestToSign();
        expect(session.networkState?.epoch).toBe(11); // A new request sees the new epoch.
        expect(reads.discoveryReads()).toBe(2);
    });

    it("keeps a two-phase VRF request on its signing snapshot", async () => {
        const reads = switchEpochAfterFirstRead();
        vi.spyOn(console, "log").mockImplementation(() => {});
        const session = await DerivationSession.create({
            aceDeployment: deployment,
            keypairId: AccountAddress.fromString(KEYPAIR),
            contractId: ContractID.newAptos({
                chainId: 1,
                moduleAddr: AccountAddress.fromString("0x1"),
                moduleName: "test",
            }),
            label: new Uint8Array([1]),
            accountAddress: AccountAddress.fromString("0x2"),
        });
        await session.getRequestToSign();
        await expect(session.deriveWithSignature({
            pubKey: new Ed25519PublicKey(new Uint8Array(32)),
            signature: new Ed25519Signature(new Uint8Array(64)),
            fullMessage: "test",
        })).rejects.toThrow(/need 1 valid shares/); // The test worker returns 503.

        expect(reads.discoveryReads()).toBe(1);
        expect(reads.workerReads()).toBe(1);
    });
});
