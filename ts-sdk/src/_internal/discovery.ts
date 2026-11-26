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
    /** Resolve a request already bound to an epoch that may now be in grace. */
    networkStateForEpoch?(epoch: number): Promise<NetworkState>;
    /** Original committee indices of nodes that confirmed their shares were installed. */
    readyNodeIndices?(epoch: number): Promise<number[]>;
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

    static deserialize(d: Deserializer): DiscoveryViewV0 {
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

        return new DiscoveryViewV0(state, nodes, sessions);
    }

    static fromBytes(bytes: Uint8Array): DiscoveryViewV0 {
        const d = new Deserializer(bytes);
        const view = DiscoveryViewV0.deserialize(d);
        if (d.remaining() !== 0) throw new Error("DiscoveryViewV0: trailing bytes");
        return view;
    }
}

/** Versioned view, with old and new committees available across the grace period. */
export class DiscoveryViewV1 {
    constructor(
        readonly serving: DiscoveryViewV0,
        readonly servingFeatures: bigint,
        readonly servingReadyNodes: boolean[],
        readonly grace: DiscoveryViewV0 | null,
        readonly graceFeatures: bigint | null,
        readonly graceReadyNodes: boolean[] | null,
        readonly graceUntilMicros: bigint | null,
    ) {}

    networkStateForEpoch(epoch: number): NetworkState {
        if (this.serving.state.epoch === epoch) return this.serving.state;
        if (this.grace?.state.epoch === epoch
            && this.graceUntilMicros !== null
            && BigInt(Date.now()) * 1000n < this.graceUntilMicros) {
            return this.grace.state;
        }
        throw new Error(`ACE discovery: epoch ${epoch} is neither serving nor in its grace period`);
    }

    readyNodeIndices(epoch: number): number[] {
        const state = this.networkStateForEpoch(epoch);
        const bitmap = this.serving.state.epoch === epoch ? this.servingReadyNodes : this.graceReadyNodes!;
        if (bitmap.length !== state.curNodes.length) {
            throw new Error(`ACE discovery: epoch ${epoch} readiness bitmap differs from committee`);
        }
        return bitmap.flatMap((ready, index) => ready ? [index] : []);
    }

    toReadable() {
        return {
            serving: this.serving.toReadable(),
            servingFeatures: this.servingFeatures.toString(),
            servingReadyNodes: this.servingReadyNodes,
            grace: this.grace?.toReadable() ?? null,
            graceFeatures: this.graceFeatures?.toString() ?? null,
            graceReadyNodes: this.graceReadyNodes,
            graceUntilMicros: this.graceUntilMicros?.toString() ?? null,
        };
    }

    static fromBytes(bytes: Uint8Array): DiscoveryViewV1 {
        const d = new Deserializer(bytes);
        const serving = DiscoveryViewV0.deserialize(d);
        const servingFeatures = d.deserializeU64();
        const servingReadyNodes = Array.from({ length: d.deserializeUleb128AsU32() }, () => d.deserializeBool());
        const graceTag = d.deserializeU8();
        if (graceTag !== 0 && graceTag !== 1) throw new Error(`DiscoveryViewV1: invalid grace tag ${graceTag}`);
        const grace = graceTag === 1 ? DiscoveryViewV0.deserialize(d) : null;
        const featureTag = d.deserializeU8();
        if (featureTag !== 0 && featureTag !== 1) throw new Error(`DiscoveryViewV1: invalid grace features tag ${featureTag}`);
        const graceFeatures = featureTag === 1 ? d.deserializeU64() : null;
        const readinessTag = d.deserializeU8();
        if (readinessTag !== 0 && readinessTag !== 1) throw new Error(`DiscoveryViewV1: invalid grace readiness tag ${readinessTag}`);
        const graceReadyNodes = readinessTag === 1
            ? Array.from({ length: d.deserializeUleb128AsU32() }, () => d.deserializeBool())
            : null;
        const deadlineTag = d.deserializeU8();
        if (deadlineTag !== 0 && deadlineTag !== 1) throw new Error(`DiscoveryViewV1: invalid grace deadline tag ${deadlineTag}`);
        const graceUntilMicros = deadlineTag === 1 ? d.deserializeU64() : null;
        if ((grace === null) !== (graceFeatures === null)
            || (grace === null) !== (graceReadyNodes === null)
            || (grace === null) !== (graceUntilMicros === null)) {
            throw new Error("DiscoveryViewV1: inconsistent grace fields");
        }
        if (d.remaining() !== 0) throw new Error("DiscoveryViewV1: trailing bytes");
        if (servingReadyNodes.length !== serving.state.curNodes.length
            || (grace !== null && graceReadyNodes!.length !== grace.state.curNodes.length)) {
            throw new Error("DiscoveryViewV1: readiness bitmap differs from committee");
        }
        return new DiscoveryViewV1(serving, servingFeatures, servingReadyNodes,
            grace, graceFeatures, graceReadyNodes, graceUntilMicros);
    }
}

type DiscoverySnapshot = DiscoveryViewV0 | DiscoveryViewV1;

async function fetchHex(url: string): Promise<string> {
    const resp = await fetch(url);
    if (!resp.ok) {
        const error = new Error(`ACE discovery: GET ${url} -> HTTP ${resp.status}`) as Error & { status: number };
        error.status = resp.status;
        throw error;
    }
    let hex = (await resp.text()).trim();
    // The server normally serves plain 0x hex; tolerate the existing JSON envelope as well.
    if (hex.startsWith("{")) {
        const obj = JSON.parse(hex) as { discoveryViewV0Bcs?: string; discoveryViewV1Bcs?: string };
        hex = obj.discoveryViewV1Bcs ?? obj.discoveryViewV0Bcs ?? "";
        if (!hex) throw new Error("ACE discovery: response JSON missing a discovery BCS blob");
    }
    hex = hex.replace(/^0x/, "");
    if (!/^(?:[0-9a-fA-F]{2})+$/.test(hex)) throw new Error(`ACE discovery: invalid BCS hex from ${url}`);
    return hex;
}

/** Prefer the v6 snapshot; old discovery deployments retain their V0 endpoint. */
async function fetchDiscoveryView(discoveryUrl: string): Promise<DiscoverySnapshot> {
    const base = discoveryUrl.replace(/\/+$/, "");
    try {
        const hex = await fetchHex(base + "/bcs/v1");
        return DiscoveryViewV1.fromBytes(Uint8Array.from(hex.match(/.{2}/g)!.map((b) => parseInt(b, 16))));
    } catch (error) {
        const status = (error as { status?: number }).status;
        if (status !== 404 && status !== 501 && status !== 502) throw error;
    }
    const hex = await fetchHex(base + "/bcs");
    return DiscoveryViewV0.fromBytes(Uint8Array.from(hex.match(/.{2}/g)!.map((b) => parseInt(b, 16))));
}

function addrKey(addr: string): string {
    return AccountAddress.fromString(addr).toStringLong();
}

/** Answers the typed reads from a single lazily-fetched discovery snapshot. */
export class DiscoveryChainReader implements ChainReader {
    private snapshot?: Promise<DiscoverySnapshot>;

    constructor(private readonly discoveryUrl: string) {}

    private view(): Promise<DiscoverySnapshot> {
        // Fetch once per reader instance. One reader is passed through each request from its
        // network-state read to its session and worker lookups. The next request gets a fresh
        // reader, so it can observe an epoch change without mixing snapshots within a request.
        if (this.snapshot === undefined) this.snapshot = fetchDiscoveryView(this.discoveryUrl);
        return this.snapshot;
    }

    async networkState(): Promise<NetworkState> {
        const view = await this.view();
        return view instanceof DiscoveryViewV1 ? view.serving.state : view.state;
    }

    async networkStateForEpoch(epoch: number): Promise<NetworkState> {
        const view = await this.view();
        if (view instanceof DiscoveryViewV1) return view.networkStateForEpoch(epoch);
        if (view.state.epoch === epoch) return view.state;
        throw new Error(`ACE discovery: epoch ${epoch} is unavailable in V0 snapshot`);
    }

    async readyNodeIndices(epoch: number): Promise<number[]> {
        const view = await this.view();
        if (view instanceof DiscoveryViewV1) return view.readyNodeIndices(epoch);
        if (view.state.epoch === epoch) return view.state.curNodes.map((_, index) => index);
        throw new Error(`ACE discovery: epoch ${epoch} is unavailable in V0 snapshot`);
    }

    async session(addr: string): Promise<SessionPks> {
        const view = await this.view();
        const s = view instanceof DiscoveryViewV1
            ? view.serving.sessions.get(addrKey(addr)) ?? view.grace?.sessions.get(addrKey(addr))
            : view.sessions.get(addrKey(addr));
        if (s === undefined) throw new Error(`ACE discovery: session ${addrKey(addr)} not in snapshot`);
        return s;
    }

    async workerEndpoint(addr: string): Promise<string> {
        const view = await this.view();
        const n = view instanceof DiscoveryViewV1
            ? view.serving.nodes.get(addrKey(addr)) ?? view.grace?.nodes.get(addrKey(addr))
            : view.nodes.get(addrKey(addr));
        if (n === undefined) throw new Error(`ACE discovery: node ${addrKey(addr)} not in snapshot`);
        if (n.endpoint === undefined) throw new Error(`ACE discovery: node ${addrKey(addr)} has no registered endpoint`);
        return n.endpoint;
    }

    async workerEncKey(addr: string): Promise<pke.EncryptionKey> {
        const view = await this.view();
        const n = view instanceof DiscoveryViewV1
            ? view.serving.nodes.get(addrKey(addr)) ?? view.grace?.nodes.get(addrKey(addr))
            : view.nodes.get(addrKey(addr));
        if (n === undefined) throw new Error(`ACE discovery: node ${addrKey(addr)} not in snapshot`);
        return n.encKey;
    }
}
