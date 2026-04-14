// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { Result } from "../result";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import * as Bls12381Fr from "./bls12381-fr";
import * as pke from "../pke";

export const SCHEME_BLS12381Fr = 0;

export function sample(scheme: number): Secret {
    if (scheme === SCHEME_BLS12381Fr) {
        const secret = Bls12381Fr.sample();
        return new Secret(SCHEME_BLS12381Fr, secret);
    }
    throw new Error(`sample: unsupported scheme ${scheme}`);
}

export function sampleBLS12381Fr(): Secret {
    return sample(SCHEME_BLS12381Fr);
}

export function reconstruct({ secretShares }: { secretShares: SecretShare[] }): Result<Secret> {
    return Result.capture({
        recordsExecutionTimeMs: false,
        task: () => {
            if (secretShares.length < 1) throw "reconstruct: no shares";
            const scheme = secretShares[0].scheme;
            for (const sh of secretShares) {
                if (sh.scheme !== scheme) throw "reconstruct: SecretShare scheme mismatch";
            }
            if (scheme === SCHEME_BLS12381Fr) {
                const inners = secretShares.map((s) => s.inner as Bls12381Fr.SecretShare);
                const s = Bls12381Fr.reconstruct({ secretShares: inners }).unwrapOrThrow("reconstruct: Bls12381Fr failed");
                return new Secret(SCHEME_BLS12381Fr, s);
            }
            throw `unsupported scheme`;
        },
    });
}

export class Secret {
    constructor(readonly scheme: number, readonly inner: any) {}

    asBls12381Fr(): Bls12381Fr.Secret {
        if (this.scheme !== SCHEME_BLS12381Fr) throw 'wrong scheme';
        return this.inner as Bls12381Fr.Secret;
    }

    static deserialize(deserializer: Deserializer): Result<Secret> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: (extra: Record<string, any>) => {
                const scheme = deserializer.deserializeU8();
                extra["scheme"] = scheme;
                if (scheme === SCHEME_BLS12381Fr) {
                    const inner = Bls12381Fr.Secret.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                    return new Secret(SCHEME_BLS12381Fr, inner);
                }
                throw 'unsupported scheme';
            },
        });
    }

    static fromBytes(bytes: Uint8Array): Result<Secret> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: (_extra: Record<string, any>) => {
                const deserializer = new Deserializer(bytes);
                const obj = Secret.deserialize(deserializer).unwrapOrThrow("deserialization failed");
                if (deserializer.remaining() !== 0) {
                    throw "trailing bytes";
                }
                return obj;
            },
        });
    }

    static fromHex(hex: string): Result<Secret> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: (_extra: Record<string, any>) => {
                const bytes = hexToBytes(hex);
                return Secret.fromBytes(bytes).unwrapOrThrow("deserialization failed");
            },
        });
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        if (this.scheme === SCHEME_BLS12381Fr) {
            (this.inner as Bls12381Fr.Secret).serialize(serializer);
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
}

export class SecretShare {
    constructor(readonly scheme: number, readonly inner: any) {}

    static deserialize(deserializer: Deserializer): Result<SecretShare> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: (extra: Record<string, any>) => {
                const scheme = deserializer.deserializeU8();
                extra["scheme"] = scheme;
                if (scheme === SCHEME_BLS12381Fr) {
                    const inner = Bls12381Fr.SecretShare.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                    return new SecretShare(SCHEME_BLS12381Fr, inner);
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
        if (this.scheme === SCHEME_BLS12381Fr) {
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
}

export class PcsCommitment {
    private constructor(private readonly scheme: number, private readonly inner: any) {
    }

    static fromBls12381Fr(inner: Bls12381Fr.PcsCommitment): PcsCommitment {
        return new PcsCommitment(SCHEME_BLS12381Fr, inner);
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        if (this.scheme === SCHEME_BLS12381Fr) {
            (this.inner as Bls12381Fr.PcsCommitment).serialize(serializer);
        } else {
            throw 'unsupported scheme';
        }
    }

    static deserialize(deserializer: Deserializer): Result<PcsCommitment> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: (extra: Record<string, any>) => {
                const scheme = deserializer.deserializeU8();
                extra["scheme"] = scheme;
                if (scheme === SCHEME_BLS12381Fr) {
                    const inner = Bls12381Fr.PcsCommitment.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                    return new PcsCommitment(SCHEME_BLS12381Fr, inner);
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

export class PcsOpening {
    private constructor(private readonly scheme: number, private readonly inner: any) {
    }

    static fromBls12381Fr(inner: Bls12381Fr.PcsOpening): PcsOpening {
        return new PcsOpening(SCHEME_BLS12381Fr, inner);
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        if (this.scheme === SCHEME_BLS12381Fr) {
            (this.inner as Bls12381Fr.PcsOpening).serialize(serializer);
        } else {
            throw 'unsupported scheme';
        }
    }

    static deserialize(deserializer: Deserializer): Result<PcsOpening> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: (extra: Record<string, any>) => {
                const scheme = deserializer.deserializeU8();
                extra["scheme"] = scheme;
                if (scheme === SCHEME_BLS12381Fr) {
                    const inner = Bls12381Fr.PcsOpening.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                    return new PcsOpening(SCHEME_BLS12381Fr, inner);
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

    static fromBytes(bytes: Uint8Array): Result<PcsOpening> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = PcsOpening.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return obj;
            },
        });
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<PcsOpening> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => PcsOpening.fromBytes(hexToBytes(hex)).unwrapOrThrow("deserialization failed"),
        });
    }
}

export class PcsBatchOpening {
    private constructor(private readonly scheme: number, private readonly inner: any) {
    }

    static fromBls12381Fr(inner: Bls12381Fr.PcsBatchOpening): PcsBatchOpening {
        return new PcsBatchOpening(SCHEME_BLS12381Fr, inner);
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        if (this.scheme === SCHEME_BLS12381Fr) {
            (this.inner as Bls12381Fr.PcsBatchOpening).serialize(serializer);
        } else {
            throw 'unsupported scheme';
        }
    }

    static deserialize(deserializer: Deserializer): Result<PcsBatchOpening> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: (extra: Record<string, any>) => {
                const scheme = deserializer.deserializeU8();
                extra["scheme"] = scheme;
                if (scheme === SCHEME_BLS12381Fr) {
                    const inner = Bls12381Fr.PcsBatchOpening.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                    return new PcsBatchOpening(SCHEME_BLS12381Fr, inner);
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

    static fromBytes(bytes: Uint8Array): Result<PcsBatchOpening> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = PcsBatchOpening.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return obj;
            },
        });
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<PcsBatchOpening> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => PcsBatchOpening.fromBytes(hexToBytes(hex)).unwrapOrThrow("deserialization failed"),
        });
    }
}

export class PrivateShareMessage {
    share: SecretShare;
    proof: PcsOpening;

    constructor(share: SecretShare, proof: PcsOpening) {
        this.share = share;
        this.proof = proof;
    }

    serialize(serializer: Serializer): void {
        this.share.serialize(serializer);
        this.proof.serialize(serializer);
    }

    static deserialize(deserializer: Deserializer): Result<PrivateShareMessage> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const share = SecretShare.deserialize(deserializer).unwrapOrThrow("share deserialize failed");
                const proof = PcsOpening.deserialize(deserializer).unwrapOrThrow("proof deserialize failed");
                return new PrivateShareMessage(share, proof);
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
        if (this.scheme !== SCHEME_BLS12381Fr) throw 'wrong scheme';
        return this.inner as Bls12381Fr.DealerState;
    }

    static deserialize(deserializer: Deserializer): Result<DealerState> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const scheme = deserializer.deserializeU8();
                if (scheme === SCHEME_BLS12381Fr) {
                    const inner = Bls12381Fr.DealerState.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                    return new DealerState(SCHEME_BLS12381Fr, inner);
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

export class DealerContribution0 {
    pcsCommitment: PcsCommitment;
    privateShareMessages: pke.Ciphertext[];
    dealerState: pke.Ciphertext | undefined; /// Dealer can choose to save private state on chain.

    constructor({sharingPolyCommitment, privateShareMessages, dealerState}: {sharingPolyCommitment: PcsCommitment, privateShareMessages: pke.Ciphertext[], dealerState?: pke.Ciphertext}) {
        this.pcsCommitment = sharingPolyCommitment;
        this.privateShareMessages = privateShareMessages;
        this.dealerState = dealerState ?? undefined;
    }

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
                return new DealerContribution0({sharingPolyCommitment: pcsCommitment, privateShareMessages, dealerState});
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

/**
 * In paper, this message also includes v (the pcs commitment), I (the nodes that haven't ack yet), sigma (the valid acks received).
 * In this implementation, they are made available on chain already, so dealer doesn't need to re-publish.
 */
export class DealerContribution1 {
    pcsBatchOpening: PcsBatchOpening;

    constructor(pcsBatchOpening: PcsBatchOpening) {
        this.pcsBatchOpening = pcsBatchOpening;
    }

    serialize(serializer: Serializer): void {
        this.pcsBatchOpening.serialize(serializer);
    }

    static deserialize(deserializer: Deserializer): Result<DealerContribution1> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const pcsBatchOpening = PcsBatchOpening.deserialize(deserializer).unwrapOrThrow("pcsBatchOpening deserialize failed");
                return new DealerContribution1(pcsBatchOpening);
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

export class Session {
    //TODO: this should match Session in vss.move
    dealer: AccountAddress;
    shareHolders: AccountAddress[];
    threshold: number;
    secretScheme: number;
    stateCode: number;
    dealTimeMicros: number;
    dealerContribution0: DealerContribution0 | undefined;
    shareHolderAcks: boolean[];
    dealerContribution1: DealerContribution1 | undefined;

    private constructor(
        {
            dealer,
            shareHolders,
            threshold,
            secretScheme,
            stateCode,
            dealTimeMicros,
            dealerContribution0,
            shareHolderAcks,
            dealerContribution1
        }: {
            dealer: AccountAddress,
            shareHolders: AccountAddress[],
            threshold: number,
            secretScheme: number,
            stateCode: number,
            dealTimeMicros: number,
            dealerContribution0: DealerContribution0 | undefined,
            shareHolderAcks: boolean[],
            dealerContribution1: DealerContribution1 | undefined
        }
    ) {
        this.dealer = dealer;
        this.shareHolders = shareHolders;
        this.threshold = threshold;
        this.secretScheme = secretScheme;
        this.stateCode = stateCode;
        this.dealTimeMicros = dealTimeMicros;
        this.dealerContribution0 = dealerContribution0;
        this.shareHolderAcks = shareHolderAcks;
        this.dealerContribution1 = dealerContribution1;
    }

    serialize(serializer: Serializer): void {
        this.dealer.serialize(serializer);
        serializer.serializeU32AsUleb128(this.shareHolders.length);
        for (const sh of this.shareHolders) {
            sh.serialize(serializer);
        }
        serializer.serializeU64(this.threshold);
        serializer.serializeU8(this.secretScheme);
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
                const secretScheme = deserializer.deserializeU8();
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
                return new Session({
                    dealer,
                    shareHolders,
                    threshold,
                    secretScheme,
                    stateCode,
                    dealTimeMicros,
                    dealerContribution0,
                    shareHolderAcks,
                    dealerContribution1,
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
        return this.stateCode === 2; // STATE__SUCCESS
    }
}

export * as bls12381Fr from "./bls12381-fr";
