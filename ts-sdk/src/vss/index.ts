// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { Result } from "../result";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import * as Bls12381Fr from "../group/bls12381g1";
import * as pke from "../pke";
import { Scalar, Element, SCHEME_BLS12381G1 } from "../group";

export { Scalar as PrivateScalar, Element as PublicPoint, SCHEME_BLS12381G1 } from "../group";
export const SCHEME_BLS12381G2 = 1;


export function sample(scheme: number): Scalar {
    if (scheme === SCHEME_BLS12381G1) {
        const secret = Bls12381Fr.sample();
        return new Scalar(SCHEME_BLS12381G1, secret);
    }
    throw new Error(`sample: unsupported scheme ${scheme}`);
}

export function sampleBLS12381G1(): Scalar {
    return sample(SCHEME_BLS12381G1);
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
                    share: share.inner as Bls12381Fr.SecretShare,
                }));
                const s = Bls12381Fr.reconstruct({ indexedShares: inners }).unwrapOrThrow("reconstruct: Bls12381G1 failed");
                return new Scalar(SCHEME_BLS12381G1, s);
            }
            throw `unsupported scheme`;
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
                    const inner = Bls12381Fr.SecretShare.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                    return new SecretShare(SCHEME_BLS12381G1, inner);
                }
                throw 'unsupported scheme';
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
            (this.inner as Bls12381Fr.SecretShare).serialize(serializer);
        } else {
            throw 'unsupported scheme';
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
            const inner = (this.inner as Bls12381Fr.SecretShare).add(other.inner as Bls12381Fr.SecretShare);
            return new SecretShare(SCHEME_BLS12381G1, inner);
        }
        throw `SecretShare.add: unsupported scheme ${this.scheme}`;
    }
}

// ── PcsCommitment ─────────────────────────────────────────────────────────────

/**
 * Feldman PCS commitment: a vector of G1 points, no scheme-byte prefix.
 * Wire format: [uleb128 t] { [uleb128(48)] [48-byte G1] } × t
 */
export class PcsCommitment {
    constructor(readonly points: Element[]) {}

    static fromBls12381G1(innerPoints: Bls12381Fr.PcsCommitment): PcsCommitment {
        return new PcsCommitment(
            innerPoints.vValues.map((pt) => Element.fromBls12381G1(new Bls12381Fr.PublicPoint(pt)))
        );
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU32AsUleb128(this.points.length);
        for (const pt of this.points) {
            pt.serialize(serializer); // writes [u8 scheme][uleb128(48)][48B]
        }
    }

    static deserialize(deserializer: Deserializer): Result<PcsCommitment> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const len = deserializer.deserializeUleb128AsU32();
                const points: Element[] = [];
                for (let i = 0; i < len; i++) {
                    const pt = Element.deserialize(deserializer).unwrapOrThrow(`point[${i}] deserialize failed`);
                    points.push(pt);
                }
                return new PcsCommitment(points);
            },
        });
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<PcsCommitment> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = PcsCommitment.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return obj;
            },
        });
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<PcsCommitment> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => PcsCommitment.fromBytes(hexToBytes(hex)).unwrapOrThrow("deserialization failed"),
        });
    }
}

// ── PrivateShareMessage ───────────────────────────────────────────────────────

/** The plaintext payload encrypted to each share holder: just the share scalar. */
export class PrivateShareMessage {
    constructor(readonly share: SecretShare) {}

    serialize(serializer: Serializer): void {
        this.share.serialize(serializer);
    }

    static deserialize(deserializer: Deserializer): Result<PrivateShareMessage> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const share = SecretShare.deserialize(deserializer).unwrapOrThrow("share deserialize failed");
                return new PrivateShareMessage(share);
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
                const obj = PrivateShareMessage.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return obj;
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

    asBls12381Fr(): Bls12381Fr.DealerState {
        if (this.scheme !== SCHEME_BLS12381G1) throw 'wrong scheme';
        return this.inner as Bls12381Fr.DealerState;
    }

    static deserialize(deserializer: Deserializer): Result<DealerState> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const scheme = deserializer.deserializeU8();
                if (scheme === SCHEME_BLS12381G1) {
                    const inner = Bls12381Fr.DealerState.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                    return new DealerState(SCHEME_BLS12381G1, inner);
                }
                throw 'unsupported scheme';
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

// ── ResharingDealerChallenge / ResharingDealerResponse ────────────────────────

export interface SigmaDlogEqProof {
    t0: Element;
    t1: Element;
    s: Scalar;
}

export interface ResharingDealerChallenge {
    expectedScaledElement: Element;
    anotherBaseElement: Element;
}

export interface ResharingDealerResponse {
    anotherScaledElement: Element;
    proof: SigmaDlogEqProof;
}

function deserializeScalar(deserializer: Deserializer): Scalar {
    const scheme = deserializer.deserializeU8();
    const inner = Bls12381Fr.PrivateScalar.deserialize(deserializer).unwrapOrThrow("Scalar deserialize failed");
    return new Scalar(scheme, inner);
}

function serializeScalar(serializer: Serializer, s: Scalar): void {
    serializer.serializeU8(s.scheme);
    (s.inner as Bls12381Fr.PrivateScalar).serialize(serializer);
}

// ── DealerContribution0 ───────────────────────────────────────────────────────

export class DealerContribution0 {
    pcsCommitment: PcsCommitment;
    privateShareMessages: pke.Ciphertext[];
    dealerState: pke.Ciphertext | undefined;
    resharingResponse: ResharingDealerResponse | undefined;

    constructor({ sharingPolyCommitment, privateShareMessages, dealerState, resharingResponse }: {
        sharingPolyCommitment: PcsCommitment;
        privateShareMessages: pke.Ciphertext[];
        dealerState?: pke.Ciphertext;
        resharingResponse?: ResharingDealerResponse;
    }) {
        this.pcsCommitment = sharingPolyCommitment;
        this.privateShareMessages = privateShareMessages;
        this.dealerState = dealerState ?? undefined;
        this.resharingResponse = resharingResponse ?? undefined;
    }

    /** Wire format: [PcsCommitment] [share messages] [Option<dealer state>] [Option<resharing response>] */
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
        if (this.resharingResponse !== undefined) {
            serializer.serializeU8(1);
            this.resharingResponse.anotherScaledElement.serialize(serializer);
            this.resharingResponse.proof.t0.serialize(serializer);
            this.resharingResponse.proof.t1.serialize(serializer);
            serializeScalar(serializer, this.resharingResponse.proof.s);
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
                const resharingResponseTag = deserializer.deserializeU8();
                let resharingResponse: ResharingDealerResponse | undefined;
                if (resharingResponseTag === 1) {
                    const anotherScaledElement = Element.deserialize(deserializer).unwrapOrThrow("anotherScaledElement deserialize failed");
                    const t0 = Element.deserialize(deserializer).unwrapOrThrow("proof.t0 deserialize failed");
                    const t1 = Element.deserialize(deserializer).unwrapOrThrow("proof.t1 deserialize failed");
                    const s = deserializeScalar(deserializer);
                    resharingResponse = { anotherScaledElement, proof: { t0, t1, s } };
                } else if (resharingResponseTag !== 0) {
                    throw `resharingResponse option tag must be 0 or 1, got ${resharingResponseTag}`;
                }
                return new DealerContribution0({ sharingPolyCommitment: pcsCommitment, privateShareMessages, dealerState, resharingResponse });
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

/**
 * Dealer's open message: for each share holder (in order), either reveal the share scalar
 * (if they did not ACK) or None (if they ACK'd and already have their share privately).
 *
 * Wire format: [uleb128 n] { [u8 0] | [u8 1] [uleb128(32)] [32-byte Fr LE] } × n
 * (BCS vector<Option<Element<Fr>>>)
 */
export class DealerContribution1 {
    constructor(readonly sharesToReveal: (Scalar | undefined)[]) {}

    serialize(serializer: Serializer): void {
        serializer.serializeU32AsUleb128(this.sharesToReveal.length);
        for (const s of this.sharesToReveal) {
            if (s === undefined) {
                serializer.serializeU8(0);
            } else {
                serializer.serializeU8(1);
                s.serialize(serializer);
            }
        }
    }

    static deserialize(deserializer: Deserializer): Result<DealerContribution1> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const n = deserializer.deserializeUleb128AsU32();
                const sharesToReveal: (Scalar | undefined)[] = [];
                for (let i = 0; i < n; i++) {
                    const tag = deserializer.deserializeU8();
                    if (tag === 0) {
                        sharesToReveal.push(undefined);
                    } else if (tag === 1) {
                        const scheme = deserializer.deserializeU8(); // scheme/variant byte
                        const inner = Bls12381Fr.PrivateScalar.deserialize(deserializer).unwrapOrThrow(`sharesToReveal[${i}]: deserialize failed`);
                        sharesToReveal.push(new Scalar(scheme, inner));
                    } else {
                        throw `sharesToReveal[${i}]: invalid option tag ${tag}`;
                    }
                }
                return new DealerContribution1(sharesToReveal);
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
    resharingChallenge: ResharingDealerChallenge | undefined;
    stateCode: number;
    dealTimeMicros: number;
    dealerContribution0: DealerContribution0 | undefined;
    shareHolderAcks: boolean[];
    dealerContribution1: DealerContribution1 | undefined;
    sharePks: Element[];

    private constructor(
        {
            dealer,
            shareHolders,
            threshold,
            basePoint,
            resharingChallenge,
            stateCode,
            dealTimeMicros,
            dealerContribution0,
            shareHolderAcks,
            dealerContribution1,
            sharePks,
        }: {
            dealer: AccountAddress,
            shareHolders: AccountAddress[],
            threshold: number,
            basePoint: Element,
            resharingChallenge: ResharingDealerChallenge | undefined,
            stateCode: number,
            dealTimeMicros: number,
            dealerContribution0: DealerContribution0 | undefined,
            shareHolderAcks: boolean[],
            dealerContribution1: DealerContribution1 | undefined,
            sharePks: Element[],
        }
    ) {
        this.dealer = dealer;
        this.shareHolders = shareHolders;
        this.threshold = threshold;
        this.basePoint = basePoint;
        this.resharingChallenge = resharingChallenge;
        this.stateCode = stateCode;
        this.dealTimeMicros = dealTimeMicros;
        this.dealerContribution0 = dealerContribution0;
        this.shareHolderAcks = shareHolderAcks;
        this.dealerContribution1 = dealerContribution1;
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
        if (this.resharingChallenge !== undefined) {
            serializer.serializeU8(1);
            this.resharingChallenge.expectedScaledElement.serialize(serializer);
            this.resharingChallenge.anotherBaseElement.serialize(serializer);
        } else {
            serializer.serializeU8(0);
        }
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
        serializer.serializeU32AsUleb128(this.sharePks.length);
        for (const pk of this.sharePks) pk.serialize(serializer);
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
                const resharingChallengeTag = deserializer.deserializeU8();
                let resharingChallenge: ResharingDealerChallenge | undefined;
                if (resharingChallengeTag === 1) {
                    const expectedScaledElement = Element.deserialize(deserializer).unwrapOrThrow("expectedScaledElement deserialize failed");
                    const anotherBaseElement = Element.deserialize(deserializer).unwrapOrThrow("anotherBaseElement deserialize failed");
                    resharingChallenge = { expectedScaledElement, anotherBaseElement };
                } else if (resharingChallengeTag !== 0) {
                    throw `resharingChallenge option tag must be 0 or 1, got ${resharingChallengeTag}`;
                }
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
                const sharePksLen = deserializer.deserializeUleb128AsU32();
                const sharePks: Element[] = [];
                for (let i = 0; i < sharePksLen; i++) {
                    sharePks.push(Element.deserialize(deserializer).unwrapOrThrow(`sharePks[${i}] deserialize failed`));
                }
                return new Session({
                    dealer,
                    shareHolders,
                    threshold,
                    basePoint,
                    resharingChallenge,
                    stateCode,
                    dealTimeMicros,
                    dealerContribution0,
                    shareHolderAcks,
                    dealerContribution1,
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
