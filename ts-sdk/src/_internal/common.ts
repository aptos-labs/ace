// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, Aptos, AptosConfig, Deserializer, Network, Serializer } from "@aptos-labs/ts-sdk";
import { sha3_256 } from "@noble/hashes/sha3";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { Result } from "../result";
import * as pke from "../pke";
import * as tibe from "../t-ibe";
import * as dkg from "../dkg";
import * as dkr from "../dkr";
import * as workerConfig from "../worker-config";
import { Element as GroupElement } from "../group";
import { State as NetworkState } from "../network";
export { NetworkState };
import { ContractID as AptosContractID, ProofOfPermission as AptosProofOfPermission } from "./aptos";
import {
    buildWorkerNodeRequestBody,
    readWorkerNodeResponseCiphertext,
} from "./node-request";
import { postWithTimeout } from "./post-with-timeout";
import { settleUntilThreshold } from "./settle-until-threshold";
import {
    assertWorkerCustomPayloadLimit,
    assertWorkerLabelLimit,
    assertWorkerRequestPlaintextLimit,
} from "./worker-request-limits";

export type WorkerNodeInfo = {
    nodeAddr: string;
    endpoint: string;
    nodeEncKey: pke.EncryptionKey;
};

export class AceDeployment {
    apiEndpoint: string;
    contractAddr: AccountAddress;
    apiKey?: string;

    constructor({apiEndpoint, contractAddr, apiKey}: {apiEndpoint: string, contractAddr: AccountAddress, apiKey?: string}) {
        this.apiEndpoint = apiEndpoint;
        this.contractAddr = contractAddr;
        this.apiKey = apiKey;
    }

    withApiKey(apiKey?: string): AceDeployment {
        return new AceDeployment({
            apiEndpoint: this.apiEndpoint,
            contractAddr: this.contractAddr,
            apiKey,
        });
    }
}

export class ContractID {
    static readonly SCHEME_APTOS = 0;

    scheme: number;
    inner: AptosContractID;

    private constructor(scheme: number, inner: AptosContractID) {
        this.scheme = scheme;
        this.inner = inner;
    }

    static newAptos({ chainId, moduleAddr, moduleName }: { chainId: number, moduleAddr: AccountAddress, moduleName: string }) {
        return new ContractID(ContractID.SCHEME_APTOS, new AptosContractID(chainId, moduleAddr, moduleName));
    }

    static dummy(): ContractID {
        return new ContractID(ContractID.SCHEME_APTOS, AptosContractID.dummy());
    }

    static deserialize(deserializer: Deserializer): Result<ContractID> {
        const task = (extra: Record<string, any>) => {
            const scheme = deserializer.deserializeU8();
            extra['scheme'] = scheme;
            if (scheme === ContractID.SCHEME_APTOS) {
                return new ContractID(ContractID.SCHEME_APTOS, AptosContractID.deserialize(deserializer).unwrapOrThrow('ACE.ContractID.deserialize failed in aptos case'));
            }
            throw 'ACE.ContractID.deserialize failed with unknown scheme';
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<ContractID> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            const result = ContractID.deserialize(deserializer).unwrapOrThrow('ACE.ContractID.fromBytes failed with deserialization error');
            if (deserializer.remaining() !== 0) {
                throw 'ACE.ContractID.fromBytes failed with trailing bytes';
            }
            return result;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<ContractID> {
        const task = (_extra: Record<string, any>) => {
            return ContractID.fromBytes(hexToBytes(hex)).unwrapOrThrow('ACE.ContractID.fromHex failed with fromBytes error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        if (this.scheme !== ContractID.SCHEME_APTOS) throw 'ACE.ContractID.serialize failed with unknown scheme';
        this.inner.serialize(serializer);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

}

export class FullDecryptionDomain {
    keypairId: AccountAddress;
    contractId: ContractID;
    label: Uint8Array;

    constructor({keypairId, contractId, label}: {keypairId: AccountAddress, contractId: ContractID, label: Uint8Array}) {
        assertWorkerLabelLimit("FullDecryptionDomain.label", label);
        this.keypairId = keypairId;
        this.contractId = contractId;
        this.label = label;
    }

    static dummy(): FullDecryptionDomain {
        return new FullDecryptionDomain({
            keypairId: AccountAddress.ZERO,
            contractId: ContractID.dummy(),
            label: new Uint8Array(0),
        });
    }

    static deserialize(deserializer: Deserializer): Result<FullDecryptionDomain> {
        const task = (_extra: Record<string, any>) => {
            const keypairId = AccountAddress.deserialize(deserializer);
            const contractId = ContractID.deserialize(deserializer).unwrapOrThrow('ACE.FullDecryptionDomain.deserialize failed with ContractID deserialization error');
            const label = deserializer.deserializeBytes();
            return new FullDecryptionDomain({keypairId, contractId, label});
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<FullDecryptionDomain> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            const ret = FullDecryptionDomain.deserialize(deserializer).unwrapOrThrow('ACE.FullDecryptionDomain.fromBytes failed with deserialization error');
            if (deserializer.remaining() !== 0) {
                throw 'ACE.FullDecryptionDomain.fromBytes failed with trailing bytes';
            }
            return ret;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<FullDecryptionDomain> {
        const task = (_extra: Record<string, any>) => {
            return FullDecryptionDomain.fromBytes(hexToBytes(hex)).unwrapOrThrow('ACE.FullDecryptionDomain.fromHex failed with fromBytes error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        this.keypairId.serialize(serializer);
        this.contractId.serialize(serializer);
        serializer.serializeBytes(this.label);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    getAptosContractID(): AptosContractID {
        if (this.contractId.scheme !== ContractID.SCHEME_APTOS) {
            throw 'ACE.FullDecryptionDomain.getAptosContractID failed with wrong scheme';
        }
        return this.contractId.inner as AptosContractID;
    }
}

export class ProofOfPermission {
    static readonly SCHEME_APTOS = 0;

    scheme: number;
    inner: AptosProofOfPermission;

    private constructor(scheme: number, inner: AptosProofOfPermission) {
        this.scheme = scheme;
        this.inner = inner;
    }

    static createAptos({ userAddr, publicKey, signature, fullMessage }: { userAddr: AccountAddress, publicKey: any, signature: any, fullMessage: string }) {
        return new ProofOfPermission(ProofOfPermission.SCHEME_APTOS, new AptosProofOfPermission({userAddr, publicKey, signature, fullMessage}));
    }

    static deserialize(deserializer: Deserializer): Result<ProofOfPermission> {
        const task = (extra: Record<string, any>) => {
            const scheme = deserializer.deserializeU8();
            extra['scheme'] = scheme;
            if (scheme === ProofOfPermission.SCHEME_APTOS) {
                return new ProofOfPermission(ProofOfPermission.SCHEME_APTOS, AptosProofOfPermission.deserialize(deserializer).unwrapOrThrow('ACE.ProofOfPermission.deserialize failed in aptos case'));
            }
            throw 'ACE.ProofOfPermission.deserialize failed with unknown scheme';
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<ProofOfPermission> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            return ProofOfPermission.deserialize(deserializer).unwrapOrThrow('ACE.ProofOfPermission.fromBytes failed with deserialization error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<ProofOfPermission> {
        const task = (_extra: Record<string, any>) => {
            return ProofOfPermission.fromBytes(hexToBytes(hex)).unwrapOrThrow('ACE.ProofOfPermission.fromHex failed with fromBytes error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        if (this.scheme !== ProofOfPermission.SCHEME_APTOS) throw 'ACE.ProofOfPermission.serialize failed with unknown scheme';
        this.inner.serialize(serializer);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }
}

export class DecryptionRequestPayload {
    keypairId: AccountAddress;
    epoch: number;
    contractId: ContractID;
    domain: Uint8Array;
    ephemeralEncKey: pke.EncryptionKey;

    constructor({keypairId, epoch, contractId, domain, ephemeralEncKey}: {keypairId: AccountAddress, epoch: number, contractId: ContractID, domain: Uint8Array, ephemeralEncKey: pke.EncryptionKey}) {
        assertWorkerLabelLimit("DecryptionRequestPayload.domain", domain);
        this.keypairId = keypairId;
        this.epoch = epoch;
        this.contractId = contractId;
        this.domain = domain;
        this.ephemeralEncKey = ephemeralEncKey;
    }

    static deserialize(deserializer: Deserializer): Result<DecryptionRequestPayload> {
        const task = (_extra: Record<string, any>) => {
            const keypairId = AccountAddress.deserialize(deserializer);
            const epoch = Number(deserializer.deserializeU64());
            const contractId = ContractID.deserialize(deserializer).unwrapOrThrow('ACE.DecryptionRequestPayload.deserialize failed with ContractID deserialization error');
            const domain = deserializer.deserializeBytes();
            const ephemeralEncKey = pke.EncryptionKey.deserialize(deserializer).unwrapOrThrow('ACE.DecryptionRequestPayload.deserialize failed with ephemeralEncKey deserialization error');
            return new DecryptionRequestPayload({keypairId, epoch, contractId, domain, ephemeralEncKey});
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromBytes(bytes: Uint8Array): Result<DecryptionRequestPayload> {
        const task = (_extra: Record<string, any>) => {
            const deserializer = new Deserializer(bytes);
            const ret = DecryptionRequestPayload.deserialize(deserializer).unwrapOrThrow('ACE.DecryptionRequestPayload.fromBytes failed with deserialization error');
            if (deserializer.remaining() !== 0) {
                throw 'ACE.DecryptionRequestPayload.fromBytes failed with trailing bytes';
            }
            return ret;
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    static fromHex(hex: string): Result<DecryptionRequestPayload> {
        const task = (_extra: Record<string, any>) => {
            return DecryptionRequestPayload.fromBytes(hexToBytes(hex)).unwrapOrThrow('ACE.DecryptionRequestPayload.fromHex failed with fromBytes error');
        };
        return Result.capture({task, recordsExecutionTimeMs: false});
    }

    serialize(serializer: Serializer): void {
        this.keypairId.serialize(serializer);
        serializer.serializeU64(BigInt(this.epoch));
        this.contractId.serialize(serializer);
        serializer.serializeBytes(this.domain);
        this.ephemeralEncKey.serialize(serializer);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    /**
     * Returns the 32-byte WebAuthn challenge bytes for this payload:
     *
     *   `SHA3-256( SHA3-256(b"ACE::DecryptionRequestPayload") || BCS(payload) )`
     *
     * Mirrors aptos-core's `CryptoHasher` pattern (`SHA3-256(b"APTOS::" || TypeName)`
     * seed, then `SHA3-256(seed || BCS(value))` for the final digest) — see
     * `aptos-crypto/src/hash.rs::prefixed_hash`. The worker-side verifier
     * (`worker-components/network-node/src/verify/aptos/any/secp256r1.rs`)
     * recomputes the same value to bind `clientDataJSON.challenge` to the
     * application-layer request.
     *
     * A wallet base64url-encodes the result and passes it as the `challenge`
     * field to `navigator.credentials.get(...)`. Only used by the
     * `AnyPublicKey<Secp256r1Ecdsa>+AnySignature<WebAuthn>` (passkeys) path.
     */
    toWebAuthnChallenge(): Uint8Array {
        const seed = sha3_256(new TextEncoder().encode("ACE::DecryptionRequestPayload"));
        const body = this.toBytes();
        const preimage = new Uint8Array(seed.length + body.length);
        preimage.set(seed, 0);
        preimage.set(body, seed.length);
        return sha3_256(preimage);
    }
}

// ── Custom-flow proof ─────────────────────────────────────────────────────────

export class CustomFlowProof {
    static readonly SCHEME_APTOS = 0;

    scheme: number;
    private _aptosPayload?: Uint8Array;

    private constructor(scheme: number) { this.scheme = scheme; }

    static createAptos(payload: Uint8Array): CustomFlowProof {
        assertWorkerCustomPayloadLimit("CustomFlowProof.aptosPayload", payload);
        const p = new CustomFlowProof(CustomFlowProof.SCHEME_APTOS);
        p._aptosPayload = payload;
        return p;
    }

    serialize(serializer: Serializer): void {
        if (this.scheme !== CustomFlowProof.SCHEME_APTOS || this._aptosPayload === undefined) {
            throw 'ACE.CustomFlowProof.serialize failed with unknown scheme';
        }
        serializer.serializeU8(this.scheme);
        serializer.serializeBytes(this._aptosPayload);
    }

    toBytes(): Uint8Array {
        const s = new Serializer();
        this.serialize(s);
        return s.toUint8Array();
    }
}

// ── Custom-flow request ───────────────────────────────────────────────────────
//
// Unlike the basic flow, the user does not sign anything — the proof is an
// opaque `CustomFlowProof` payload (typically a Groth16 ZK proof) that the
// dapp's `on_ace_decryption_request_custom_flow` view function validates. No
// "bytes the wallet signs"
// concept here, so no nested payload type; the 6 fields sit flat in the
// envelope, mirroring `CustomFlowRequest` in
// `worker-components/network-node/src/verify/mod.rs`.

export class CustomFlowRequest {
    keypairId: AccountAddress;
    epoch: number;
    contractId: ContractID;
    label: Uint8Array;
    encPk: pke.EncryptionKey;
    proof: CustomFlowProof;

    constructor({keypairId, epoch, contractId, label, encPk, proof}: {
        keypairId: AccountAddress,
        epoch: number,
        contractId: ContractID,
        label: Uint8Array,
        encPk: pke.EncryptionKey,
        proof: CustomFlowProof,
    }) {
        assertWorkerLabelLimit("CustomFlowRequest.label", label);
        this.keypairId = keypairId;
        this.epoch = epoch;
        this.contractId = contractId;
        this.label = label;
        this.encPk = encPk;
        this.proof = proof;
    }

    serialize(s: Serializer): void {
        this.keypairId.serialize(s);
        s.serializeU64(BigInt(this.epoch));
        this.contractId.serialize(s);
        s.serializeBytes(this.label);
        this.encPk.serialize(s);
        this.proof.serialize(s);
    }

    toBytes(): Uint8Array {
        const s = new Serializer();
        this.serialize(s);
        return s.toUint8Array();
    }
}

export class DecryptionCustomFlowRequest {
    keypairId: AccountAddress;
    epoch: number;
    contractId: ContractID;
    label: Uint8Array;
    encPk: pke.EncryptionKey;
    proof: CustomFlowProof;
    /** Client-asserted t-IBE scheme the share should be formatted for. */
    tibeScheme: number;

    constructor(args: {
        keypairId: AccountAddress,
        epoch: number,
        contractId: ContractID,
        label: Uint8Array,
        encPk: pke.EncryptionKey,
        proof: CustomFlowProof,
        tibeScheme: number,
    }) {
        assertWorkerLabelLimit("DecryptionCustomFlowRequest.label", args.label);
        this.keypairId = args.keypairId;
        this.epoch = args.epoch;
        this.contractId = args.contractId;
        this.label = args.label;
        this.encPk = args.encPk;
        this.proof = args.proof;
        this.tibeScheme = args.tibeScheme;
    }

    serialize(s: Serializer): void {
        this.keypairId.serialize(s);
        s.serializeU64(BigInt(this.epoch));
        this.contractId.serialize(s);
        s.serializeBytes(this.label);
        this.encPk.serialize(s);
        this.proof.serialize(s);
        s.serializeU8(this.tibeScheme);
    }

    toBytes(): Uint8Array {
        const s = new Serializer();
        this.serialize(s);
        return s.toUint8Array();
    }
}

// ── Worker request envelope ───────────────────────────────────────────────────
//
// These classes mirror the worker-side Rust request structs in
// `worker-components/network-node/src/verify/mod.rs`. Discriminants are now
// 3.x-only: the decryption requests always carry `tibeScheme`.

export class DecryptionBasicFlowRequest {
    request: DecryptionRequestPayload;
    proof: ProofOfPermission;
    /** Client-asserted t-IBE scheme the share should be formatted for. The
     *  worker handler validates this against the share's group_scheme. */
    tibeScheme: number;

    constructor(args: { request: DecryptionRequestPayload, proof: ProofOfPermission, tibeScheme: number }) {
        this.request = args.request;
        this.proof = args.proof;
        this.tibeScheme = args.tibeScheme;
    }

    serialize(s: Serializer): void {
        this.request.serialize(s);
        this.proof.serialize(s);
        s.serializeU8(this.tibeScheme);
    }

    toBytes(): Uint8Array {
        const s = new Serializer();
        this.serialize(s);
        return s.toUint8Array();
    }
}

// ── WorkerRequest (outer enum with scheme byte) ───────────────────────────────
//
// Discriminants must match the worker-side Rust enum order:
//   0 = DecryptionBasicFlow
//   1 = DecryptionCustomFlow
//   2 = ThresholdVrf

interface SerializableWorkerRequest {
    serialize(serializer: Serializer): void;
}

export class WorkerRequest {
    static readonly SCHEME_DECRYPTION_BASIC_FLOW = 0;
    static readonly SCHEME_DECRYPTION_CUSTOM_FLOW = 1;
    static readonly SCHEME_THRESHOLD_VRF = 2;

    scheme: number;
    /** The scheme-specific request body. `scheme` discriminates which class
     *  instance lives here; all envelope types share a `serialize(s)`
     *  method so the outer enum just delegates polymorphically. */
    private inner: SerializableWorkerRequest;

    private constructor(
        scheme: number,
        inner: SerializableWorkerRequest,
    ) {
        this.scheme = scheme;
        this.inner = inner;
    }

    static newDecryptionBasicFlow(
        request: DecryptionRequestPayload,
        proof: ProofOfPermission,
        tibeScheme: number,
    ): WorkerRequest {
        return new WorkerRequest(
            WorkerRequest.SCHEME_DECRYPTION_BASIC_FLOW,
            new DecryptionBasicFlowRequest({ request, proof, tibeScheme }),
        );
    }

    static newDecryptionCustomFlow(
        customRequest: CustomFlowRequest,
        tibeScheme: number,
    ): WorkerRequest {
        return new WorkerRequest(
            WorkerRequest.SCHEME_DECRYPTION_CUSTOM_FLOW,
            new DecryptionCustomFlowRequest({
                keypairId: customRequest.keypairId,
                epoch: customRequest.epoch,
                contractId: customRequest.contractId,
                label: customRequest.label,
                encPk: customRequest.encPk,
                proof: customRequest.proof,
                tibeScheme,
            }),
        );
    }

    static newThresholdVrf(request: SerializableWorkerRequest): WorkerRequest {
        return new WorkerRequest(
            WorkerRequest.SCHEME_THRESHOLD_VRF,
            request,
        );
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        this.inner.serialize(serializer);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        const bytes = serializer.toUint8Array();
        assertWorkerRequestPlaintextLimit("WorkerRequest plaintext", bytes);
        return bytes;
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }
}

export async function fetchNetworkState(aceDeployment: AceDeployment): Promise<NetworkState> {
    const aptos = createAptos(aceDeployment.apiEndpoint, aceDeployment.apiKey);
    const aceContractAddr = aceDeployment.contractAddr.toStringLong();
    const [stateHex] = await aptos.view({
        payload: {
            function: `${aceContractAddr}::network::state_view_v0_bcs` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [],
        },
    });
    const stateBytes = hexToBytes((stateHex as string).replace(/^0x/, ''));
    return NetworkState.fromBytes(stateBytes).unwrapOrThrow('ACE: parse network state');
}

export async function fetchTibePublicKey({aceDeployment, keypairId, tibeScheme, context}: {
    aceDeployment: AceDeployment,
    keypairId: AccountAddress,
    tibeScheme?: number,
    context: string,
}): Promise<Result<tibe.MasterPublicKey>> {
    if (tibeScheme === undefined) tibeScheme = tibe.SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD;
    return Result.captureAsync({
        task: async (_extra) => {
            const aptos = createAptos(aceDeployment.apiEndpoint, aceDeployment.apiKey);
            const aceContractAddr = aceDeployment.contractAddr.toStringLong();
            const [hexBytes] = await aptos.view({
                payload: {
                    function: `${aceContractAddr}::dkg::get_session_bcs` as `${string}::${string}::${string}`,
                    typeArguments: [],
                    functionArguments: [keypairId.toStringLong()],
                },
            });
            const sessionBytes = hexToBytes((hexBytes as string).replace(/^0x/, ''));
            const session = dkg.Session.fromBytes(sessionBytes).unwrapOrThrow(`${context}: parse DKG session`);
            if (!session.resultPk) throw `${context}: DKG session has no resultPk (not yet finalized)`;

            return tibe.MasterPublicKey.fromGroupElements(tibeScheme, session.basePoint, session.resultPk)
                .unwrapOrThrow(`${context}: keypairId ${keypairId.toStringLong()} is incompatible with tibeScheme=${tibeScheme}`);
        },
        recordsExecutionTimeMs: true,
    });
}

export async function fetchNetworkStateAndBuildRequest(
    aceDeployment: AceDeployment,
    fullDecryptionDomain: FullDecryptionDomain,
    ephemeralEncryptionKey: pke.EncryptionKey,
): Promise<{networkState: NetworkState, request: DecryptionRequestPayload}> {
    const aptos = createAptos(aceDeployment.apiEndpoint, aceDeployment.apiKey);
    const aceContractAddr = aceDeployment.contractAddr.toStringLong();

    const [stateHex] = await aptos.view({
        payload: {
            function: `${aceContractAddr}::network::state_view_v0_bcs` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [],
        },
    });
    const stateBytes = hexToBytes((stateHex as string).replace(/^0x/, ''));
    const networkState = NetworkState.fromBytes(stateBytes).unwrapOrThrow('ACE: parse network state');

    const request = new DecryptionRequestPayload({
        keypairId: fullDecryptionDomain.keypairId,
        epoch: networkState.epoch,
        contractId: fullDecryptionDomain.contractId,
        domain: fullDecryptionDomain.label,
        ephemeralEncKey: ephemeralEncryptionKey,
    });

    return {networkState, request};
}

/**
 * Verify the pairing equation for a materialized IDK share against the public
 * share key at the same SDK index. Wire metadata is checked before this function
 * is called so malformed or misrouted shares do not reach curve decompression.
 *
 * Logs and returns `false` on mismatch so the caller can drop the share.
 */
function verifyIdkShare({share, sdkIdx, sessionPks, id, nodeAddr, endpoint, label}: {
    share: tibe.IdentityDecryptionKeyShare,
    sdkIdx: number,
    sessionPks: {basePoint: GroupElement, sharePks: GroupElement[]},
    id: Uint8Array,
    nodeAddr: string,
    endpoint: string,
    label: string,
}): boolean {
    const ok = tibe.verifyShare({
        basePoint: sessionPks.basePoint,
        sharePk: sessionPks.sharePks[sdkIdx],
        id,
        share,
    }).okValue ?? false;
    if (!ok) {
        console.log(`  [${label}] worker ${nodeAddr} (${endpoint}): share failed pairing verification`);
        return false;
    }
    return true;
}

function parseAndVerifyIdkShare({shareBytes, expectedScheme, sdkIdx, sessionPks, id, nodeAddr, endpoint, label}: {
    shareBytes: Uint8Array,
    expectedScheme: number,
    sdkIdx: number,
    sessionPks: {basePoint: GroupElement, sharePks: GroupElement[]},
    id: Uint8Array,
    nodeAddr: string,
    endpoint: string,
    label: string,
}): tibe.IdentityDecryptionKeyShare | null {
    const wire = tibe.IdentityDecryptionKeyShareWire.fromBytes(shareBytes).okValue ?? null;
    if (wire === null) {
        console.log(`  [${label}] worker ${nodeAddr} (${endpoint}): share wire parse failed`);
        return null;
    }
    if (wire.scheme !== expectedScheme) {
        console.log(`  [${label}] worker ${nodeAddr} (${endpoint}): scheme mismatch (got ${wire.scheme}, expected ${expectedScheme})`);
        return null;
    }
    const expectedEval = BigInt(sdkIdx + 1);
    if (wire.evalPoint !== expectedEval) {
        console.log(`  [${label}] worker ${nodeAddr} (${endpoint}): evalPoint mismatch (got ${wire.evalPoint}, expected ${expectedEval})`);
        return null;
    }

    const share = wire.materialize().okValue ?? null;
    if (share === null) {
        console.log(`  [${label}] worker ${nodeAddr} (${endpoint}): invalid compressed curve point`);
        return null;
    }
    return verifyIdkShare({share, sdkIdx, sessionPks, id, nodeAddr, endpoint, label}) ? share : null;
}

/**
 * Fetch the basePoint and per-holder share PKs of the most-recent DKG/DKR session for `keypairId`.
 *
 * Used by identity-key-share fetchers to verify that each returned IDK share is
 * `H_G2(id)^{f(i+1)}` where `share_pks[i] = basePoint^{f(i+1)}` - without this check, a single
 * corrupt node returning a syntactically-valid-but-wrong share corrupts the aggregate and forces
 * a MAC failure for everyone.
 *
 * The discriminator `currentSession === keypairId` distinguishes the initial DKG (no DKR yet)
 * from subsequent DKR sessions.
 */
export async function fetchCurrentSessionPks(aceDeployment: AceDeployment, networkState: NetworkState, keypairId: AccountAddress): Promise<{basePoint: GroupElement, sharePks: GroupElement[]}> {
    const aptos = createAptos(aceDeployment.apiEndpoint, aceDeployment.apiKey);
    const aceContractAddr = aceDeployment.contractAddr.toStringLong();
    const keypairIdStr = keypairId.toStringLong();

    const secret = networkState.secrets.find(s => s.keypairId.toStringLong() === keypairIdStr);
    if (secret === undefined) {
        throw `ACE: keypairId ${keypairIdStr} not found in network state secrets`;
    }
    const isInitialDkg = secret.currentSession.toStringLong() === keypairIdStr;
    const sessionFn = isInitialDkg ? 'dkg::get_session_bcs' : 'dkr::get_session_bcs';

    const [hexBytes] = await aptos.view({
        payload: {
            function: `${aceContractAddr}::${sessionFn}` as `${string}::${string}::${string}`,
            typeArguments: [],
            functionArguments: [secret.currentSession.toStringLong()],
        },
    });
    const sessionBytes = hexToBytes((hexBytes as string).replace(/^0x/, ''));

    // Session classes already store basePoint / sharePks as group.Element (see vss/index.ts
    // re-export `Element as PublicPoint`).  No re-wrapping needed.
    if (isInitialDkg) {
        const session = dkg.Session.fromBytes(sessionBytes).unwrapOrThrow('ACE: parse DKG session');
        return { basePoint: session.basePoint, sharePks: session.sharePks };
    } else {
        const session = dkr.Session.fromBytes(sessionBytes).unwrapOrThrow('ACE: parse DKR session');
        return { basePoint: session.publicBaseElement, sharePks: session.sharePks };
    }
}

export async function fetchWorkerClientEndpoint(aptos: Aptos, aceContractAddr: string, workerAddr: string): Promise<string> {
    return workerConfig.fetchWorkerClientEndpoint(aptos, aceContractAddr, workerAddr);
}

export async function fetchWorkerPkeEncryptionKey(aptos: Aptos, aceContractAddr: string, workerAddr: string, context: string): Promise<pke.EncryptionKey> {
    return workerConfig.fetchWorkerPkeEncryptionKey(aptos, aceContractAddr, workerAddr, context);
}

export async function fetchWorkerNodeInfo({
    aptos,
    aceContractAddr,
    nodeAddr,
    pkeParseContext,
}: {
    aptos: Aptos,
    aceContractAddr: string,
    nodeAddr: AccountAddress,
    pkeParseContext: string,
}): Promise<WorkerNodeInfo> {
    const addrStr = nodeAddr.toStringLong();
    const [endpoint, nodeEncKey] = await Promise.all([
        fetchWorkerClientEndpoint(aptos, aceContractAddr, addrStr),
        fetchWorkerPkeEncryptionKey(aptos, aceContractAddr, addrStr, `${pkeParseContext} for ${addrStr}`),
    ]);
    return { nodeAddr: addrStr, endpoint, nodeEncKey };
}

export async function fetchCurrentWorkerNodeInfos({
    aceDeployment,
    networkState,
    pkeParseContext,
}: {
    aceDeployment: AceDeployment,
    networkState: NetworkState,
    pkeParseContext: string,
}): Promise<WorkerNodeInfo[]> {
    const aptos = createAptos(aceDeployment.apiEndpoint, aceDeployment.apiKey);
    const aceContractAddr = aceDeployment.contractAddr.toStringLong();
    return Promise.all(networkState.curNodes.map((nodeAddr) => fetchWorkerNodeInfo({
        aptos,
        aceContractAddr,
        nodeAddr,
        pkeParseContext,
    })));
}

export function decryptWithIdentityKeyShares({ciphertext, identityKeyShares}: {
    ciphertext: Uint8Array,
    identityKeyShares: tibe.IdentityDecryptionKeyShare[],
}): Result<Uint8Array> {
    return Result.capture({
        task: (_extra) => {
            return tibe.decrypt({
                idkShares: identityKeyShares,
                ciphertext: tibe.Ciphertext.fromBytes(ciphertext)
                    .unwrapOrThrow('ACE.decryptWithIdentityKeyShares: parse ciphertext'),
            }).unwrapOrThrow('ACE.decryptWithIdentityKeyShares: tibe.decrypt failed');
        },
        recordsExecutionTimeMs: true,
    });
}

export async function fetchIdentityKeySharesCore({aceDeployment, networkState, request, proof, ephemeralDecryptionKey, tibeScheme}: {
    aceDeployment: AceDeployment,
    networkState: NetworkState,
    request: DecryptionRequestPayload,
    proof: ProofOfPermission,
    ephemeralDecryptionKey: pke.DecryptionKey,
    tibeScheme: number,
}): Promise<Result<tibe.IdentityDecryptionKeyShare[]>> {
    return Result.captureAsync({
        task: async (_extra) => {
            const fdd = new FullDecryptionDomain({
                keypairId: request.keypairId,
                contractId: request.contractId,
                label: request.domain,
            });
            const fddBytes = fdd.toBytes();

            const [nodeInfos, currentSessionPks] = await Promise.all([
                fetchCurrentWorkerNodeInfos({
                    aceDeployment,
                    networkState,
                    pkeParseContext: 'ACE.fetchIdentityKeySharesCore',
                }),
                fetchCurrentSessionPks(aceDeployment, networkState, request.keypairId),
            ]);

            if (currentSessionPks.sharePks.length !== networkState.curNodes.length) {
                throw `ACE.fetchIdentityKeySharesCore: sharePks length ${currentSessionPks.sharePks.length} != curNodes length ${networkState.curNodes.length}`;
            }

            const reqBytes = WorkerRequest.newDecryptionBasicFlow(request, proof, tibeScheme).toBytes();

            const taskResults = await settleUntilThreshold(
                nodeInfos.map(({endpoint, nodeEncKey}, i) => async (signal) => {
                    const nodeAddr = networkState.curNodes[i].toStringLong();
                    const requestBody = await buildWorkerNodeRequestBody({nodeEncKey, plaintext: reqBytes});
                    let resp: Response;
                    try {
                        resp = await postWithTimeout(endpoint, requestBody, signal);
                    } catch (e) {
                        if (!signal.aborted) {
                            console.log(`  [decrypt] worker ${nodeAddr} (${endpoint}): fetch error — ${e}`);
                        }
                        throw e;
                    }
                    if (!resp.ok) {
                        const body = await resp.text().catch(() => '');
                        console.log(`  [decrypt] worker ${nodeAddr} (${endpoint}): HTTP ${resp.status} — ${body.trim().slice(0, 120)}`);
                        throw new Error(`worker returned HTTP ${resp.status}`);
                    }
                    let respCt: pke.Ciphertext;
                    try {
                        respCt = await readWorkerNodeResponseCiphertext(resp);
                    } catch (e) {
                        console.log(`  [decrypt] worker ${nodeAddr} (${endpoint}): response ciphertext parse failed`);
                        throw e;
                    }
                    const shareBytes = (await pke.decrypt({decryptionKey: ephemeralDecryptionKey, ciphertext: respCt})).okValue ?? null;
                    if (shareBytes === null) {
                        console.log(`  [decrypt] worker ${nodeAddr} (${endpoint}): response decryption failed`);
                        throw new Error('response decryption failed');
                    }
                    const share = parseAndVerifyIdkShare({
                        shareBytes,
                        expectedScheme: tibeScheme,
                        sdkIdx: i,
                        sessionPks: currentSessionPks,
                        id: fddBytes,
                        nodeAddr,
                        endpoint,
                        label: 'decrypt',
                    });
                    if (share === null) throw new Error('identity key share validation failed');
                    console.log(`  [decrypt] worker ${nodeAddr} (${endpoint}): OK`);
                    return share;
                }),
                networkState.curThreshold,
            );
            const idkShares = taskResults.flatMap(result => result.status === 'fulfilled' ? [result.value] : []);
            if (idkShares.length < networkState.curThreshold) {
                throw `ACE.fetchIdentityKeySharesCore: need ${networkState.curThreshold} identity key shares, got ${idkShares.length}`;
            }

            return idkShares;
        },
        recordsExecutionTimeMs: true,
    });
}

export async function decryptCore(args: {
    aceDeployment: AceDeployment,
    networkState: NetworkState,
    request: DecryptionRequestPayload,
    proof: ProofOfPermission,
    ephemeralDecryptionKey: pke.DecryptionKey,
    ciphertext: Uint8Array,
}): Promise<Result<Uint8Array>> {
    const ciphertext = tibe.Ciphertext.fromBytes(args.ciphertext);
    if (!ciphertext.isOk) return Result.Err({error: ciphertext.errValue, extra: ciphertext.extra});
    const identityKeySharesResult = await fetchIdentityKeySharesCore({
        aceDeployment: args.aceDeployment,
        networkState: args.networkState,
        request: args.request,
        proof: args.proof,
        ephemeralDecryptionKey: args.ephemeralDecryptionKey,
        tibeScheme: ciphertext.okValue!.scheme,
    });
    if (!identityKeySharesResult.isOk) return Result.Err({error: identityKeySharesResult.errValue, extra: identityKeySharesResult.extra});
    return decryptWithIdentityKeyShares({
        ciphertext: args.ciphertext,
        identityKeyShares: identityKeySharesResult.okValue!,
    });
}

export async function fetchIdentityKeySharesCoreCustom({aceDeployment, networkState, customRequest, callerDecryptionKey, tibeScheme}: {
    aceDeployment: AceDeployment,
    networkState: NetworkState,
    customRequest: CustomFlowRequest,
    callerDecryptionKey: pke.DecryptionKey,
    tibeScheme: number,
}): Promise<Result<tibe.IdentityDecryptionKeyShare[]>> {
    return Result.captureAsync({
        task: async (_extra) => {
            const fdd = new FullDecryptionDomain({
                keypairId: customRequest.keypairId,
                contractId: customRequest.contractId,
                label: customRequest.label,
            });
            const fddBytes = fdd.toBytes();

            const [nodeInfos, currentSessionPks] = await Promise.all([
                fetchCurrentWorkerNodeInfos({
                    aceDeployment,
                    networkState,
                    pkeParseContext: 'ACE.fetchIdentityKeySharesCoreCustom',
                }),
                fetchCurrentSessionPks(aceDeployment, networkState, customRequest.keypairId),
            ]);

            if (currentSessionPks.sharePks.length !== networkState.curNodes.length) {
                throw `ACE.fetchIdentityKeySharesCoreCustom: sharePks length ${currentSessionPks.sharePks.length} != curNodes length ${networkState.curNodes.length}`;
            }

            const reqBytes = WorkerRequest.newDecryptionCustomFlow(customRequest, tibeScheme).toBytes();

            const taskResults = await settleUntilThreshold(
                nodeInfos.map(({endpoint, nodeEncKey}, i) => async (signal) => {
                    const nodeAddr = networkState.curNodes[i].toStringLong();
                    const requestBody = await buildWorkerNodeRequestBody({nodeEncKey, plaintext: reqBytes});
                    let resp: Response;
                    try {
                        resp = await postWithTimeout(endpoint, requestBody, signal);
                    } catch (e) {
                        if (!signal.aborted) {
                            console.log(`  [decrypt-custom] worker ${nodeAddr} (${endpoint}): fetch error — ${e}`);
                        }
                        throw e;
                    }
                    if (!resp.ok) {
                        const body = await resp.text().catch(() => '');
                        console.log(`  [decrypt-custom] worker ${nodeAddr} (${endpoint}): HTTP ${resp.status} — ${body.trim().slice(0, 120)}`);
                        throw new Error(`worker returned HTTP ${resp.status}`);
                    }
                    let respCt: pke.Ciphertext;
                    try {
                        respCt = await readWorkerNodeResponseCiphertext(resp);
                    } catch (e) {
                        console.log(`  [decrypt-custom] worker ${nodeAddr} (${endpoint}): response ciphertext parse failed`);
                        throw e;
                    }
                    const shareBytes = (await pke.decrypt({decryptionKey: callerDecryptionKey, ciphertext: respCt})).okValue ?? null;
                    if (shareBytes === null) {
                        console.log(`  [decrypt-custom] worker ${nodeAddr} (${endpoint}): response decryption failed`);
                        throw new Error('response decryption failed');
                    }
                    const share = parseAndVerifyIdkShare({
                        shareBytes,
                        expectedScheme: tibeScheme,
                        sdkIdx: i,
                        sessionPks: currentSessionPks,
                        id: fddBytes,
                        nodeAddr,
                        endpoint,
                        label: 'decrypt-custom',
                    });
                    if (share === null) throw new Error('identity key share validation failed');
                    console.log(`  [decrypt-custom] worker ${nodeAddr} (${endpoint}): OK`);
                    return share;
                }),
                networkState.curThreshold,
            );
            const idkShares = taskResults.flatMap(result => result.status === 'fulfilled' ? [result.value] : []);
            if (idkShares.length < networkState.curThreshold) {
                throw `ACE.fetchIdentityKeySharesCoreCustom: need ${networkState.curThreshold} identity key shares, got ${idkShares.length}`;
            }

            return idkShares;
        },
        recordsExecutionTimeMs: true,
    });
}

export async function decryptCoreCustom(args: {
    aceDeployment: AceDeployment,
    networkState: NetworkState,
    customRequest: CustomFlowRequest,
    callerDecryptionKey: pke.DecryptionKey,
    ciphertext: Uint8Array,
}): Promise<Result<Uint8Array>> {
    const ciphertext = tibe.Ciphertext.fromBytes(args.ciphertext);
    if (!ciphertext.isOk) return Result.Err({error: ciphertext.errValue, extra: ciphertext.extra});
    const identityKeySharesResult = await fetchIdentityKeySharesCoreCustom({
        aceDeployment: args.aceDeployment,
        networkState: args.networkState,
        customRequest: args.customRequest,
        callerDecryptionKey: args.callerDecryptionKey,
        tibeScheme: ciphertext.okValue!.scheme,
    });
    if (!identityKeySharesResult.isOk) return Result.Err({error: identityKeySharesResult.errValue, extra: identityKeySharesResult.extra});
    return decryptWithIdentityKeyShares({
        ciphertext: args.ciphertext,
        identityKeyShares: identityKeySharesResult.okValue!,
    });
}

/**
 * Build the per-node request body for ONE worker, without contacting the
 * other committee members. Returns the hex string of the BCS `NodeRequest`
 * body a client would POST to `targetEndpoint`. The caller does the POST itself.
 *
 * Looks up the target node's `(endpoint, pke_enc_key)` from `worker_config`
 * by walking `networkState.curNodes` and matching `endpoint`. Errors if no
 * current committee member's registered endpoint equals `targetEndpoint`.
 */
export async function buildPerNodeRequestCore({
    aceDeployment, networkState, request, proof, tibeScheme, targetEndpoint,
}: {
    aceDeployment: AceDeployment,
    networkState: NetworkState,
    request: DecryptionRequestPayload,
    proof: ProofOfPermission,
    tibeScheme: number,
    targetEndpoint: string,
}): Promise<Result<{ encReqHex: string, epoch: number, sdkIdx: number }>> {
    return Result.captureAsync({
        task: async (_extra) => {
            const nodeInfos = await fetchCurrentWorkerNodeInfos({
                aceDeployment,
                networkState,
                pkeParseContext: 'ACE.buildPerNodeRequest',
            });

            const sdkIdx = nodeInfos.findIndex(n => n.endpoint === targetEndpoint);
            if (sdkIdx < 0) {
                throw `ACE.buildPerNodeRequest: targetEndpoint ${targetEndpoint} is not in the current committee. Registered endpoints: ${nodeInfos.map(n => n.endpoint).join(', ')}`;
            }
            const { nodeEncKey } = nodeInfos[sdkIdx];

            const reqBytes = WorkerRequest.newDecryptionBasicFlow(request, proof, tibeScheme).toBytes();
            const encReqHex = bytesToHex(await buildWorkerNodeRequestBody({nodeEncKey, plaintext: reqBytes}));
            return { encReqHex, epoch: Number(networkState.epoch), sdkIdx };
        },
        recordsExecutionTimeMs: true,
    });
}

export function createAptos(rpcUrl?: string, apiKey?: string): Aptos {
    const headers = apiKey ? { Authorization: `Bearer ${apiKey}` } : undefined;
    return new Aptos(new AptosConfig({
        network: Network.CUSTOM,
        fullnode: rpcUrl ?? 'http://localhost:8080/v1',
        clientConfig: headers ? { HEADERS: headers } : undefined,
    }));
}
