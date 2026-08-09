// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Disaster-recovery master-secret reconstruction (admin-side client).
//!
//! A trusted reconstructor (holding the deployment's dedicated `sig` signing key
//! whose public counterpart was pushed to every node as `--reconstructor-pk`)
//! collects ≥ t raw Shamir scalar shares directly from the committee nodes and
//! Lagrange-interpolates the master secret `s`. Intended to be run **right after
//! each DKG** and the result stored in cold storage; a chain wipe or a below-
//! threshold node loss then can't render data undecryptable.
//!
//! Wire types mirror `worker-components/network-node/src/verify/mod.rs`
//! (`ReconstructionRequest*` / `ReconstructionResponse`) and go through the
//! standard encrypted `POST /` channel via `WorkerRequest` variant 3.

import { AccountAddress, Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils";

import * as pke from "../pke";
import * as sig from "../sig";
import * as tibe from "../t-ibe";
import { lagrangeAtZero } from "../vss/dealing";
import {
    AceDeployment,
    WorkerRequest,
    getChainReader,
    fetchTibePublicKey,
} from "../_internal/common";

/** Fields the reconstructor signs over. BCS layout must match the Rust
 *  `ReconstructionRequestPayload` (field order: chain_id, ace_addr, keypair_id,
 *  epoch, eph_pke_ek). `ace_addr`/`keypair_id` serialize as 32 raw bytes. */
export class ReconstructionRequestPayload {
    constructor(
        readonly chainId: number,
        readonly aceAddr: AccountAddress,
        readonly keypairId: AccountAddress,
        readonly epoch: number,
        readonly ephPkeEk: pke.EncryptionKey,
    ) {}

    serialize(s: Serializer): void {
        s.serializeU8(this.chainId);
        this.aceAddr.serialize(s); // 32 raw bytes (matches Rust [u8; 32])
        this.keypairId.serialize(s); // 32 raw bytes
        s.serializeU64(BigInt(this.epoch));
        this.ephPkeEk.serialize(s);
    }

    toBytes(): Uint8Array {
        const s = new Serializer();
        this.serialize(s);
        return s.toUint8Array();
    }
}

/** `{ payload, sig }` — the inner body of `WorkerRequest::Reconstruction`. */
export class ReconstructionRequest {
    constructor(
        readonly payload: ReconstructionRequestPayload,
        readonly signature: sig.Signature,
    ) {}

    serialize(s: Serializer): void {
        this.payload.serialize(s);
        this.signature.serialize(s);
    }
}

export interface ReconstructionResponse {
    evalPoint: bigint;
    groupScheme: number;
    ct: pke.Ciphertext;
}

export function parseReconstructionResponse(bytes: Uint8Array): ReconstructionResponse {
    const d = new Deserializer(bytes);
    const evalPoint = d.deserializeU64();
    const groupScheme = d.deserializeU8();
    const ct = pke.Ciphertext.deserialize(d).unwrapOrThrow(
        "parseReconstructionResponse: ciphertext",
    );
    if (d.remaining() !== 0) throw new Error("parseReconstructionResponse: trailing bytes");
    return { evalPoint, groupScheme, ct };
}

export interface ReconstructResult {
    /** Master secret `s` as 0x-prefixed 32-byte little-endian hex. */
    secretHex: string;
    /** The epoch the shares were collected from. */
    epoch: number;
    /** Number of shares collected (≥ threshold). */
    sharesUsed: number;
    /** `true` if `s·basePoint == masterPk` was checked and held; `false` if the
     *  check failed; `undefined` if it couldn't run (e.g. master pk unavailable). */
    verified: boolean | undefined;
}

/**
 * Reconstruct the master secret for `keypairId` by collecting raw scalar shares
 * from the committee. Requires the deployment's reconstructor `signingKey` and
 * that nodes were launched with the matching `--reconstructor-pk`.
 */
export async function reconstructSecret({
    aceDeployment,
    keypairId,
    signingKey,
    chainId,
    tibeScheme,
    perNodeTimeoutMs = 8000,
    log = () => {},
}: {
    aceDeployment: AceDeployment;
    keypairId: AccountAddress;
    signingKey: sig.SigningKey;
    chainId: number;
    tibeScheme?: number;
    perNodeTimeoutMs?: number;
    log?: (msg: string) => void;
}): Promise<ReconstructResult> {
    const reader = getChainReader(aceDeployment);
    const networkState = await reader.networkState();
    const { epoch, curThreshold, curNodes } = networkState;

    const aceAddr = aceDeployment.contractAddr;
    const eph = await pke.keygen();
    const payload = new ReconstructionRequestPayload(
        chainId,
        aceAddr,
        keypairId,
        epoch,
        eph.encryptionKey,
    );
    const signature = signingKey.sign(payload.toBytes());
    const reqBytes = WorkerRequest.newReconstruction(
        new ReconstructionRequest(payload, signature),
    ).toBytes();

    log(`Requesting shares for keypair ${keypairId.toStringLong()} at epoch ${epoch} from ${curNodes.length} nodes (threshold ${curThreshold})…`);

    const points = (
        await Promise.all(
            curNodes.map(async (nodeAddr) => {
                const addrStr = nodeAddr.toStringLong();
                try {
                    const [endpoint, nodeEncKey] = await Promise.all([
                        reader.workerEndpoint(addrStr),
                        reader.workerEncKey(addrStr),
                    ]);
                    const encReqHex = (
                        await pke.encrypt({ encryptionKey: nodeEncKey, plaintext: reqBytes })
                    ).toHex();
                    const ctrl = new AbortController();
                    const tid = setTimeout(() => ctrl.abort(), perNodeTimeoutMs);
                    const resp = await fetch(endpoint, {
                        method: "POST",
                        body: encReqHex,
                        signal: ctrl.signal,
                    });
                    clearTimeout(tid);
                    if (!resp.ok) {
                        const body = await resp.text().catch(() => "");
                        log(`  node ${addrStr} (${endpoint}): HTTP ${resp.status} — ${body.trim().slice(0, 120)}`);
                        return null;
                    }
                    // Body is hex(BCS(ReconstructionResponse)); the raw scalar is inside `ct`.
                    const r = parseReconstructionResponse(hexToBytes((await resp.text()).trim()));
                    const scalarBytes = (
                        await pke.decrypt({ decryptionKey: eph.decryptionKey, ciphertext: r.ct })
                    ).okValue;
                    if (!scalarBytes) {
                        log(`  node ${addrStr}: share decryption failed`);
                        return null;
                    }
                    log(`  node ${addrStr}: OK (eval_point=${r.evalPoint})`);
                    // The share is 32-byte little-endian Fr.
                    return { x: r.evalPoint, y: bytesToNumberLE(scalarBytes) };
                } catch (e) {
                    log(`  node ${addrStr}: error — ${e}`);
                    return null;
                }
            }),
        )
    ).filter((p): p is { x: bigint; y: bigint } => p !== null);

    // Deduplicate by eval point (defensive; each node has a distinct point).
    const byX = new Map<string, { x: bigint; y: bigint }>();
    for (const p of points) byX.set(p.x.toString(), p);
    const uniquePoints = [...byX.values()];

    if (uniquePoints.length < curThreshold) {
        throw new Error(
            `reconstructSecret: collected ${uniquePoints.length} shares, need threshold ${curThreshold}`,
        );
    }

    const s = lagrangeAtZero(uniquePoints);
    const secretHex = "0x" + bytesToHex(numberToBytesLE(s, 32));

    let verified: boolean | undefined = undefined;
    try {
        const scheme = tibeScheme ?? tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD;
        const mpk = (await fetchTibePublicKey({ aceDeployment, keypairId, tibeScheme: scheme, context: "reconstructSecret" })).okValue;
        if (mpk) {
            // `mpk.inner` is the concrete scheme MasterPublicKey holding the noble points.
            const inner = (mpk as any).inner;
            verified = inner.basePoint.multiply(s).equals(inner.pk);
        }
    } catch {
        verified = undefined;
    }

    return { secretHex, epoch, sharesUsed: uniquePoints.length, verified };
}
