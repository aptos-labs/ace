// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, Deserializer } from "@aptos-labs/ts-sdk";
import { Element as GroupElement } from "../group";
import * as pke from "../pke";
import { State as NetworkState } from "../network";

/** Human-readable projection of `DiscoveryViewV0` (all crypto material hex-encoded). */
export interface DiscoveryReadableV0 {
    epoch: number;
    epochChanging: boolean;
    threshold: number;
    epochStartTimeMicros: string;
    epochDurationMicros: string;
    nodes: { address: string; endpoint: string | null; pkeEncKey: string | null }[];
    keypairs: {
        keypairId: string;
        currentSession: string;
        scheme: number;
        note: string;
        masterPublicKey: string | null;
        basePoint: string | null;
        sharePks: string[];
    }[];
}

/** The base point, master public key, and per-holder share PKs of a secret's session. */
export interface SessionPks {
    basePoint: GroupElement;
    sharePks: GroupElement[];
    /** Master public key. Present for DKG sessions (used for the encryption key); may be omitted for DKR. */
    resultPk?: GroupElement;
}

/**
 * Typed, read-only view over the ACE on-chain state the SDK needs. Two implementations:
 * a fullnode-backed one (`FullnodeChainReader` in common.ts, one view call per method) and the
 * discovery-backed `DiscoveryChainReader` below (all methods answered from one aggregated
 * snapshot). `getChainReader` (common.ts) picks between them per `AceDeployment`.
 */
export interface ChainReader {
    networkState(): Promise<NetworkState>;
    /** `isDkg` selects the session module for the fullnode path; discovery ignores it (uniform). */
    session(addr: string, isDkg: boolean): Promise<SessionPks>;
    workerEndpoint(addr: string): Promise<string>;
    workerEncKey(addr: string): Promise<pke.EncryptionKey>;
}

/** Decoded `ace::network::DiscoveryViewV0` (see contracts/network/sources/network.move). */
export class DiscoveryViewV0 {
    constructor(
        readonly state: NetworkState,
        /** node address (long form) -> { endpoint?, encKey }. */
        readonly nodes: Map<string, { endpoint?: string; encKey: pke.EncryptionKey }>,
        /** session address (long form) -> SessionPks. */
        readonly sessions: Map<string, SessionPks>,
    ) {}

    /**
     * A plain, JSON-serializable, human-readable projection — all crypto material as hex, epoch
     * timers as decimal strings (bigint isn't JSON-serializable). Intended for the discovery
     * service's `/json` debug endpoint and for eyeballing; the SDK itself decodes the BCS directly.
     */
    toReadable(): DiscoveryReadableV0 {
        const nodes = this.state.curNodes.map((addr) => {
            const key = addr.toStringLong();
            const n = this.nodes.get(key);
            return { address: key, endpoint: n?.endpoint ?? null, pkeEncKey: n ? n.encKey.toHex() : null };
        });
        const keypairs = this.state.secrets.map((s) => {
            const keypairId = s.keypairId.toStringLong();
            const currentSession = s.currentSession.toStringLong();
            const cur = this.sessions.get(currentSession);
            const origin = this.sessions.get(keypairId); // keypairId is always the origin DKG session
            return {
                keypairId,
                currentSession,
                scheme: s.scheme,
                note: s.note,
                masterPublicKey: origin?.resultPk?.toHex() ?? null,
                basePoint: cur?.basePoint.toHex() ?? null,
                sharePks: cur ? cur.sharePks.map((p) => p.toHex()) : [],
            };
        });
        return {
            epoch: this.state.epoch,
            epochChanging: this.state.isEpochChanging(),
            threshold: this.state.curThreshold,
            epochStartTimeMicros: this.state.epochStartTimeMicros.toString(),
            epochDurationMicros: this.state.epochDurationMicros.toString(),
            nodes,
            keypairs,
        };
    }

    static fromBytes(bytes: Uint8Array): DiscoveryViewV0 {
        const d = new Deserializer(bytes);

        // state_view: an inline StateViewV0, byte-identical to state_view_v0_bcs() — reuse State's decoder.
        const state = NetworkState.deserialize(d).unwrapOrThrow("DiscoveryViewV0: parse state_view");

        const nodes = new Map<string, { endpoint?: string; encKey: pke.EncryptionKey }>();
        const nodesLen = d.deserializeUleb128AsU32();
        for (let i = 0; i < nodesLen; i++) {
            const addr = AccountAddress.deserialize(d).toStringLong();
            const tag = d.deserializeU8(); // Option<String>
            let endpoint: string | undefined;
            if (tag === 1) {
                endpoint = d.deserializeStr();
            } else if (tag !== 0) {
                throw new Error(`DiscoveryViewV0: node endpoint option tag must be 0 or 1, got ${tag}`);
            }
            const encKey = pke.EncryptionKey.deserialize(d).unwrapOrThrow(`DiscoveryViewV0: parse enc_key for ${addr}`);
            nodes.set(addr, { endpoint, encKey });
        }

        const sessions = new Map<string, SessionPks>();
        const sessionsLen = d.deserializeUleb128AsU32();
        for (let i = 0; i < sessionsLen; i++) {
            const addr = AccountAddress.deserialize(d).toStringLong();
            const basePoint = GroupElement.deserialize(d).unwrapOrThrow(`DiscoveryViewV0: parse base_point for ${addr}`);
            const resultPk = GroupElement.deserialize(d).unwrapOrThrow(`DiscoveryViewV0: parse result_pk for ${addr}`);
            const sharePksLen = d.deserializeUleb128AsU32();
            const sharePks: GroupElement[] = [];
            for (let j = 0; j < sharePksLen; j++) {
                sharePks.push(GroupElement.deserialize(d).unwrapOrThrow(`DiscoveryViewV0: parse share_pks[${j}] for ${addr}`));
            }
            sessions.set(addr, { basePoint, sharePks, resultPk });
        }

        if (d.remaining() !== 0) throw new Error("DiscoveryViewV0: trailing bytes");
        return new DiscoveryViewV0(state, nodes, sessions);
    }
}

/** GET the aggregated snapshot from the discovery service and decode it. */
async function fetchDiscoveryView(discoveryUrl: string): Promise<DiscoveryViewV0> {
    const resp = await fetch(discoveryUrl);
    if (!resp.ok) {
        throw new Error(`ACE discovery: GET ${discoveryUrl} -> HTTP ${resp.status}`);
    }
    let hex = (await resp.text()).trim();
    // The server serves the plain 0x hex body; also tolerate a { discoveryViewV0Bcs } JSON envelope.
    if (hex.startsWith("{")) {
        const obj = JSON.parse(hex) as { discoveryViewV0Bcs?: string };
        if (!obj.discoveryViewV0Bcs) throw new Error("ACE discovery: response JSON missing 'discoveryViewV0Bcs'");
        hex = obj.discoveryViewV0Bcs;
    }
    hex = hex.replace(/^0x/, "");
    const bytes = Uint8Array.from(hex.match(/.{1,2}/g)?.map((b) => parseInt(b, 16)) ?? []);
    return DiscoveryViewV0.fromBytes(bytes);
}

function addrKey(addr: string): string {
    return AccountAddress.fromString(addr).toStringLong();
}

/** Answers the typed reads from a single lazily-fetched discovery snapshot. */
export class DiscoveryChainReader implements ChainReader {
    private snapshot?: Promise<DiscoveryViewV0>;

    constructor(private readonly discoveryUrl: string) {}

    private view0(): Promise<DiscoveryViewV0> {
        // Fetch once per reader instance (i.e. once per operation phase). No cross-op cache: a
        // fresh reader is created per call site, so state stays current across epoch changes.
        if (this.snapshot === undefined) this.snapshot = fetchDiscoveryView(this.discoveryUrl);
        return this.snapshot;
    }

    async networkState(): Promise<NetworkState> {
        return (await this.view0()).state;
    }

    async session(addr: string): Promise<SessionPks> {
        const s = (await this.view0()).sessions.get(addrKey(addr));
        if (s === undefined) throw new Error(`ACE discovery: session ${addrKey(addr)} not in snapshot`);
        return s;
    }

    async workerEndpoint(addr: string): Promise<string> {
        const n = (await this.view0()).nodes.get(addrKey(addr));
        if (n === undefined) throw new Error(`ACE discovery: node ${addrKey(addr)} not in snapshot`);
        if (n.endpoint === undefined) throw new Error(`ACE discovery: node ${addrKey(addr)} has no registered endpoint`);
        return n.endpoint;
    }

    async workerEncKey(addr: string): Promise<pke.EncryptionKey> {
        const n = (await this.view0()).nodes.get(addrKey(addr));
        if (n === undefined) throw new Error(`ACE discovery: node ${addrKey(addr)} not in snapshot`);
        return n.encKey;
    }
}
