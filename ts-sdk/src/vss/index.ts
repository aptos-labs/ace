// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { Result } from "../result";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import * as Bls12381G1 from "../group/bls12381g1";
import * as Bls12381G2 from "../group/bls12381g2";
import * as pke from "../pke";
import {
    Commitment as PcsCommitment,
    Opening as PcsOpening,
    PublicParams as PcsPublicParams,
} from "../pedersen-polynomial-commitment";
import { Proof as SigmaDlogLinearProof } from "../sigma-dlog-linear";
import { Scalar, Element, SCHEME_BLS12381G1, SCHEME_BLS12381G2 } from "../group";

export { Scalar as PrivateScalar, Element as PublicPoint, SCHEME_BLS12381G1, SCHEME_BLS12381G2 } from "../group";
export { PcsCommitment, PcsOpening, PcsPublicParams, SigmaDlogLinearProof };

// Bls12381G1's Fr-only types (PrivateScalar / SecretShare / DealerState) are byte-for-byte
// identical to Bls12381G2's; we keep separate inner classes per scheme so the dispatch is
// uniform with how Element / PublicPoint is structured.
//
// TODO: extract Fr-only code (PrivateScalar / SecretShare / DealerState / sample / reconstruct
// / split) to a shared bls12381fr module and remove the duplication.


export function sample(scheme: number): Scalar {
    if (scheme === SCHEME_BLS12381G1) {
        const secret = Bls12381G1.sample();
        return new Scalar(SCHEME_BLS12381G1, secret);
    }
    if (scheme === SCHEME_BLS12381G2) {
        const secret = Bls12381G2.sample();
        return new Scalar(SCHEME_BLS12381G2, secret);
    }
    throw new Error(`sample: unsupported scheme ${scheme}`);
}

export function sampleBLS12381G1(): Scalar {
    return sample(SCHEME_BLS12381G1);
}

export function sampleBLS12381G2(): Scalar {
    return sample(SCHEME_BLS12381G2);
}

export function reconstruct({ indexedShares }: {
    indexedShares: { index: number; share: SecretShare }[]
}): Result<Scalar> {
    return Result.capture({
        recordsExecutionTimeMs: false,
        task: () => {
            if (indexedShares.length < 1) throw "reconstruct: no shares";
            const scheme = indexedShares[0].share.scheme;
            for (const { share } of indexedShares) {
                if (share.scheme !== scheme) throw "reconstruct: SecretShare scheme mismatch";
            }
            if (scheme === SCHEME_BLS12381G1) {
                const inners = indexedShares.map(({ index, share }) => ({
                    index,
                    share: share.inner as Bls12381G1.SecretShare,
                }));
                const s = Bls12381G1.reconstruct({ indexedShares: inners }).unwrapOrThrow("reconstruct: Bls12381G1 failed");
                return new Scalar(SCHEME_BLS12381G1, s);
            }
            if (scheme === SCHEME_BLS12381G2) {
                const inners = indexedShares.map(({ index, share }) => ({
                    index,
                    share: share.inner as Bls12381G2.SecretShare,
                }));
                const s = Bls12381G2.reconstruct({ indexedShares: inners }).unwrapOrThrow("reconstruct: Bls12381G2 failed");
                return new Scalar(SCHEME_BLS12381G2, s);
            }
            throw `reconstruct: unsupported scheme ${scheme}`;
        },
    });
}

// ── SecretShare ───────────────────────────────────────────────────────────────

export class SecretShare {
    constructor(readonly scheme: number, readonly inner: any) {}

    static deserialize(deserializer: Deserializer): Result<SecretShare> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: (extra: Record<string, any>) => {
                const scheme = deserializer.deserializeU8();
                extra["scheme"] = scheme;
                if (scheme === SCHEME_BLS12381G1) {
                    const inner = Bls12381G1.SecretShare.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                    return new SecretShare(SCHEME_BLS12381G1, inner);
                }
                if (scheme === SCHEME_BLS12381G2) {
                    const inner = Bls12381G2.SecretShare.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                    return new SecretShare(SCHEME_BLS12381G2, inner);
                }
                throw `unsupported scheme ${scheme}`;
            },
        });
    }

    static fromBytes(bytes: Uint8Array): Result<SecretShare> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = SecretShare.deserialize(deserializer).unwrapOrThrow(
                    "deserialization failed",
                );
                if (deserializer.remaining() !== 0) {
                    throw "trailing bytes";
                }
                return obj;
            },
        });
    }

    static fromHex(hex: string): Result<SecretShare> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () =>
                SecretShare.fromBytes(hexToBytes(hex)).unwrapOrThrow(
                    "SecretShare.fromHex failed with bytes deserialization error",
                ),
        });
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        if (this.scheme === SCHEME_BLS12381G1) {
            (this.inner as Bls12381G1.SecretShare).serialize(serializer);
        } else if (this.scheme === SCHEME_BLS12381G2) {
            (this.inner as Bls12381G2.SecretShare).serialize(serializer);
        } else {
            throw `unsupported scheme ${this.scheme}`;
        }
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    add(other: SecretShare): SecretShare {
        if (this.scheme !== other.scheme) throw 'SecretShare.add: scheme mismatch';
        if (this.scheme === SCHEME_BLS12381G1) {
            const inner = (this.inner as Bls12381G1.SecretShare).add(other.inner as Bls12381G1.SecretShare);
            return new SecretShare(SCHEME_BLS12381G1, inner);
        }
        if (this.scheme === SCHEME_BLS12381G2) {
            const inner = (this.inner as Bls12381G2.SecretShare).add(other.inner as Bls12381G2.SecretShare);
            return new SecretShare(SCHEME_BLS12381G2, inner);
        }
        throw `SecretShare.add: unsupported scheme ${this.scheme}`;
    }
}

// ── PrivateShareMessage ───────────────────────────────────────────────────────

/** The plaintext payload encrypted to each share holder: a Pedersen PCS opening. */
export class PrivateShareMessage {
    constructor(readonly opening: PcsOpening) {}

    get share(): SecretShare {
        return secretShareFromScalar(this.opening.evalValueP);
    }

    serialize(serializer: Serializer): void {
        this.opening.serialize(serializer);
    }

    static deserialize(deserializer: Deserializer): Result<PrivateShareMessage> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const opening = PcsOpening.deserialize(deserializer).unwrapOrThrow("opening deserialize failed");
                return new PrivateShareMessage(opening);
            },
        });
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<PrivateShareMessage> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const msg = PrivateShareMessage.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return msg;
            },
        });
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<PrivateShareMessage> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => PrivateShareMessage.fromBytes(hexToBytes(hex)).unwrapOrThrow("deserialization failed"),
        });
    }
}

function secretShareFromScalar(scalar: Scalar): SecretShare {
    if (scalar.scheme === SCHEME_BLS12381G1) {
        const bytes = (scalar.inner as Bls12381G1.PrivateScalar).toBytes();
        const inner = Bls12381G1.SecretShare.fromBytes(bytes).unwrapOrThrow("SecretShare G1 from scalar failed");
        return new SecretShare(SCHEME_BLS12381G1, inner);
    }
    if (scalar.scheme === SCHEME_BLS12381G2) {
        const bytes = (scalar.inner as Bls12381G2.PrivateScalar).toBytes();
        const inner = Bls12381G2.SecretShare.fromBytes(bytes).unwrapOrThrow("SecretShare G2 from scalar failed");
        return new SecretShare(SCHEME_BLS12381G2, inner);
    }
    throw `secretShareFromScalar: unsupported scheme ${scalar.scheme}`;
}

// ── DealerState ───────────────────────────────────────────────────────────────

export class DealerState {
    scheme: number;
    inner: any;
    constructor(scheme: number, inner: any) {
        this.scheme = scheme;
        this.inner = inner;
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        this.inner.serialize(serializer);
    }

    asBls12381Fr(): Bls12381G1.DealerState {
        if (this.scheme !== SCHEME_BLS12381G1) throw 'wrong scheme';
        return this.inner as Bls12381G1.DealerState;
    }

    asBls12381G2DealerState(): Bls12381G2.DealerState {
        if (this.scheme !== SCHEME_BLS12381G2) throw 'wrong scheme';
        return this.inner as Bls12381G2.DealerState;
    }

    static deserialize(deserializer: Deserializer): Result<DealerState> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const scheme = deserializer.deserializeU8();
                if (scheme === SCHEME_BLS12381G1) {
                    const inner = Bls12381G1.DealerState.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                    return new DealerState(SCHEME_BLS12381G1, inner);
                }
                if (scheme === SCHEME_BLS12381G2) {
                    const inner = Bls12381G2.DealerState.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                    return new DealerState(SCHEME_BLS12381G2, inner);
                }
                throw `unsupported scheme ${scheme}`;
            },
        });
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<DealerState> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = DealerState.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return obj;
            },
        });
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<DealerState> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => DealerState.fromBytes(hexToBytes(hex)).unwrapOrThrow("deserialization failed"),
        });
    }
}

// ── DealerContribution0 ───────────────────────────────────────────────────────

export class DealerContribution0 {
    pcsCommitment: PcsCommitment;
    privateShareMessages: pke.Ciphertext[];
    dealerState: pke.Ciphertext | undefined;
    consistencyProof: SigmaDlogLinearProof | undefined;

    constructor({ sharingPolyCommitment, privateShareMessages, dealerState, consistencyProof }: {
        sharingPolyCommitment: PcsCommitment;
        privateShareMessages: pke.Ciphertext[];
        dealerState?: pke.Ciphertext;
        consistencyProof?: SigmaDlogLinearProof;
    }) {
        this.pcsCommitment = sharingPolyCommitment;
        this.privateShareMessages = privateShareMessages;
        this.dealerState = dealerState ?? undefined;
        this.consistencyProof = consistencyProof ?? undefined;
    }

    /** Wire format: [PcsCommitment] [share messages] [Option<dealer state>] [Option<consistency proof>] */
    serialize(serializer: Serializer): void {
        this.pcsCommitment.serialize(serializer);
        serializer.serializeU32AsUleb128(this.privateShareMessages.length);
        for (const ct of this.privateShareMessages) {
            ct.serialize(serializer);
        }
        if (this.dealerState !== undefined) {
            serializer.serializeU8(1);
            this.dealerState.serialize(serializer);
        } else {
            serializer.serializeU8(0);
        }
        if (this.consistencyProof !== undefined) {
            serializer.serializeU8(1);
            this.consistencyProof.serialize(serializer);
        } else {
            serializer.serializeU8(0);
        }
    }

    static deserialize(deserializer: Deserializer): Result<DealerContribution0> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const pcsCommitment = PcsCommitment.deserialize(deserializer).unwrapOrThrow("pcsCommitment deserialize failed");
                const n = deserializer.deserializeUleb128AsU32();
                const privateShareMessages: pke.Ciphertext[] = [];
                for (let i = 0; i < n; i++) {
                    const ct = pke.Ciphertext.deserialize(deserializer).unwrapOrThrow(`privateShareMessages[${i}] deserialize failed`);
                    privateShareMessages.push(ct);
                }
                const dealerStateTag = deserializer.deserializeU8();
                let dealerState: pke.Ciphertext | undefined;
                if (dealerStateTag === 1) {
                    dealerState = pke.Ciphertext.deserialize(deserializer).unwrapOrThrow("dealerState deserialize failed");
                } else if (dealerStateTag !== 0) {
                    throw `dealerState option tag must be 0 or 1, got ${dealerStateTag}`;
                }
                const consistencyProofTag = deserializer.deserializeU8();
                let consistencyProof: SigmaDlogLinearProof | undefined;
                if (consistencyProofTag === 1) {
                    consistencyProof = SigmaDlogLinearProof.deserialize(deserializer).unwrapOrThrow("consistencyProof deserialize failed");
                } else if (consistencyProofTag !== 0) {
                    throw `consistencyProof option tag must be 0 or 1, got ${consistencyProofTag}`;
                }
                return new DealerContribution0({ sharingPolyCommitment: pcsCommitment, privateShareMessages, dealerState, consistencyProof });
            },
        });
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<DealerContribution0> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = DealerContribution0.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return obj;
            },
        });
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<DealerContribution0> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => DealerContribution0.fromBytes(hexToBytes(hex)).unwrapOrThrow("deserialization failed"),
        });
    }
}

// ── DealerContribution1 ───────────────────────────────────────────────────────

export class DealerContribution1 {
    constructor(
        readonly sharesToReveal: (PcsOpening | undefined)[],
        readonly publicKeys: Element[],
        readonly publicKeyProofs: (SigmaDlogLinearProof | undefined)[],
    ) {}

    serialize(serializer: Serializer): void {
        serializer.serializeU32AsUleb128(this.sharesToReveal.length);
        for (const opening of this.sharesToReveal) {
            if (opening === undefined) {
                serializer.serializeU8(0);
            } else {
                serializer.serializeU8(1);
                opening.serialize(serializer);
            }
        }
        serializer.serializeU32AsUleb128(this.publicKeys.length);
        for (const pk of this.publicKeys) pk.serialize(serializer);
        serializer.serializeU32AsUleb128(this.publicKeyProofs.length);
        for (const proof of this.publicKeyProofs) {
            if (proof === undefined) {
                serializer.serializeU8(0);
            } else {
                serializer.serializeU8(1);
                proof.serialize(serializer);
            }
        }
    }

    static deserialize(deserializer: Deserializer): Result<DealerContribution1> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const n = deserializer.deserializeUleb128AsU32();
                const sharesToReveal: (PcsOpening | undefined)[] = [];
                for (let i = 0; i < n; i++) {
                    const tag = deserializer.deserializeU8();
                    if (tag === 0) {
                        sharesToReveal.push(undefined);
                    } else if (tag === 1) {
                        sharesToReveal.push(PcsOpening.deserialize(deserializer).unwrapOrThrow(`sharesToReveal[${i}] deserialize failed`));
                    } else {
                        throw `sharesToReveal[${i}]: invalid option tag ${tag}`;
                    }
                }
                const pkLen = deserializer.deserializeUleb128AsU32();
                const publicKeys: Element[] = [];
                for (let i = 0; i < pkLen; i++) {
                    publicKeys.push(Element.deserialize(deserializer).unwrapOrThrow(`publicKeys[${i}] deserialize failed`));
                }
                const proofLen = deserializer.deserializeUleb128AsU32();
                const publicKeyProofs: (SigmaDlogLinearProof | undefined)[] = [];
                for (let i = 0; i < proofLen; i++) {
                    const tag = deserializer.deserializeU8();
                    if (tag === 0) {
                        publicKeyProofs.push(undefined);
                    } else if (tag === 1) {
                        publicKeyProofs.push(SigmaDlogLinearProof.deserialize(deserializer).unwrapOrThrow(`publicKeyProofs[${i}] deserialize failed`));
                    } else {
                        throw `publicKeyProofs[${i}]: invalid option tag ${tag}`;
                    }
                }
                return new DealerContribution1(sharesToReveal, publicKeys, publicKeyProofs);
            },
        });
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<DealerContribution1> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = DealerContribution1.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return obj;
            },
        });
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<DealerContribution1> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => DealerContribution1.fromBytes(hexToBytes(hex)).unwrapOrThrow("deserialization failed"),
        });
    }
}

// ── Session ───────────────────────────────────────────────────────────────────

export class Session {
    dealer: AccountAddress;
    shareHolders: AccountAddress[];
    threshold: number;
    basePoint: Element;
    previousPublicKey: Element | undefined;
    pcsContext: PcsPublicParams;
    stateCode: number;
    dealTimeMicros: number;
    dealerContribution0: DealerContribution0 | undefined;
    shareHolderAcks: boolean[];
    dealerContribution1: DealerContribution1 | undefined;
    nextPublicKeyToVerify: number;
    publicKeys: Element[];
    resultPk: Element | undefined;
    sharePks: Element[];

    private constructor(
        {
            dealer,
            shareHolders,
            threshold,
            basePoint,
            previousPublicKey,
            pcsContext,
            stateCode,
            dealTimeMicros,
            dealerContribution0,
            shareHolderAcks,
            dealerContribution1,
            nextPublicKeyToVerify,
            publicKeys,
            sharePks,
        }: {
            dealer: AccountAddress,
            shareHolders: AccountAddress[],
            threshold: number,
            basePoint: Element,
            previousPublicKey: Element | undefined,
            pcsContext: PcsPublicParams,
            stateCode: number,
            dealTimeMicros: number,
            dealerContribution0: DealerContribution0 | undefined,
            shareHolderAcks: boolean[],
            dealerContribution1: DealerContribution1 | undefined,
            nextPublicKeyToVerify: number,
            publicKeys: Element[],
            sharePks: Element[],
        }
    ) {
        this.dealer = dealer;
        this.shareHolders = shareHolders;
        this.threshold = threshold;
        this.basePoint = basePoint;
        this.previousPublicKey = previousPublicKey;
        this.pcsContext = pcsContext;
        this.stateCode = stateCode;
        this.dealTimeMicros = dealTimeMicros;
        this.dealerContribution0 = dealerContribution0;
        this.shareHolderAcks = shareHolderAcks;
        this.dealerContribution1 = dealerContribution1;
        this.nextPublicKeyToVerify = nextPublicKeyToVerify;
        this.publicKeys = publicKeys;
        this.resultPk = publicKeys[0];
        this.sharePks = sharePks;
    }

    serialize(serializer: Serializer): void {
        this.dealer.serialize(serializer);
        serializer.serializeU32AsUleb128(this.shareHolders.length);
        for (const sh of this.shareHolders) {
            sh.serialize(serializer);
        }
        serializer.serializeU64(this.threshold);
        this.basePoint.serialize(serializer);
        if (this.previousPublicKey !== undefined) {
            serializer.serializeU8(1);
            this.previousPublicKey.serialize(serializer);
        } else {
            serializer.serializeU8(0);
        }
        this.pcsContext.serialize(serializer);
        serializer.serializeU8(this.stateCode);
        serializer.serializeU64(this.dealTimeMicros);
        if (this.dealerContribution0 === undefined) {
            serializer.serializeU8(0);
        } else {
            serializer.serializeU8(1);
            this.dealerContribution0.serialize(serializer);
        }
        serializer.serializeU32AsUleb128(this.shareHolderAcks.length);
        for (const ack of this.shareHolderAcks) {
            serializer.serializeBool(ack);
        }
        if (this.dealerContribution1 === undefined) {
            serializer.serializeU8(0);
        } else {
            serializer.serializeU8(1);
            this.dealerContribution1.serialize(serializer);
        }
        serializer.serializeU64(this.nextPublicKeyToVerify);
        serializer.serializeU32AsUleb128(this.publicKeys.length);
        for (const pk of this.publicKeys) pk.serialize(serializer);
    }

    static deserialize(deserializer: Deserializer): Result<Session> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const dealer = AccountAddress.deserialize(deserializer);
                const holdersLen = deserializer.deserializeUleb128AsU32();
                const shareHolders: AccountAddress[] = [];
                for (let i = 0; i < holdersLen; i++) {
                    shareHolders.push(AccountAddress.deserialize(deserializer));
                }
                const threshold = Number(deserializer.deserializeU64());
                const basePoint = Element.deserialize(deserializer).unwrapOrThrow("basePoint deserialize failed");
                const previousPublicKeyTag = deserializer.deserializeU8();
                let previousPublicKey: Element | undefined;
                if (previousPublicKeyTag === 1) {
                    previousPublicKey = Element.deserialize(deserializer).unwrapOrThrow("previousPublicKey deserialize failed");
                } else if (previousPublicKeyTag !== 0) {
                    throw `previousPublicKey option tag must be 0 or 1, got ${previousPublicKeyTag}`;
                }
                const pcsContext = PcsPublicParams.deserialize(deserializer).unwrapOrThrow("pcsContext deserialize failed");
                const stateCode = deserializer.deserializeU8();
                const dealTimeMicros = Number(deserializer.deserializeU64());
                const dc0Tag = deserializer.deserializeU8();
                let dealerContribution0: DealerContribution0 | undefined;
                if (dc0Tag === 1) {
                    dealerContribution0 = DealerContribution0.deserialize(deserializer).unwrapOrThrow("dealerContribution0 deserialize failed");
                } else if (dc0Tag !== 0) {
                    throw `dealerContribution0 option tag must be 0 or 1, got ${dc0Tag}`;
                }
                const acksLen = deserializer.deserializeUleb128AsU32();
                const shareHolderAcks: boolean[] = [];
                for (let i = 0; i < acksLen; i++) {
                    shareHolderAcks.push(deserializer.deserializeBool());
                }
                const dc1Tag = deserializer.deserializeU8();
                let dealerContribution1: DealerContribution1 | undefined;
                if (dc1Tag === 1) {
                    dealerContribution1 = DealerContribution1.deserialize(deserializer).unwrapOrThrow("dealerContribution1 deserialize failed");
                } else if (dc1Tag !== 0) {
                    throw `dealerContribution1 option tag must be 0 or 1, got ${dc1Tag}`;
                }
                const nextPublicKeyToVerify = Number(deserializer.deserializeU64());
                const publicKeysLen = deserializer.deserializeUleb128AsU32();
                const publicKeys: Element[] = [];
                for (let i = 0; i < publicKeysLen; i++) {
                    publicKeys.push(Element.deserialize(deserializer).unwrapOrThrow(`publicKeys[${i}] deserialize failed`));
                }
                const sharePks = publicKeys.slice(1);
                return new Session({
                    dealer,
                    shareHolders,
                    threshold,
                    basePoint,
                    previousPublicKey,
                    pcsContext,
                    stateCode,
                    dealTimeMicros,
                    dealerContribution0,
                    shareHolderAcks,
                    dealerContribution1,
                    nextPublicKeyToVerify,
                    publicKeys,
                    sharePks,
                });
            },
        });
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<Session> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = Session.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return obj;
            },
        });
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<Session> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => Session.fromBytes(hexToBytes(hex)).unwrapOrThrow("deserialization failed"),
        });
    }

    isCompleted(): boolean {
        return this.stateCode === 3; // STATE__SUCCESS
    }
}
