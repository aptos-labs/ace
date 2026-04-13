// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { AccountAddress, Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { Result } from "../result";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import * as Bls12381G1 from "./bls12381g1";
import * as Bls12381G2 from "./bls12381g2";

export const SCHEME_BLS12381G1 = 0;
export const SCHEME_BLS12381G2 = 1;

function keygenWithScheme(scheme: number): { secret: Secret; publicCommitment: PublicCommitment } {
    if (scheme === SCHEME_BLS12381G1) {
        const { secret, publicCommitment } = Bls12381G1.keygen();
        return { secret: Secret.fromG1(secret), publicCommitment: PublicCommitment.fromG1(publicCommitment) };
    }
    if (scheme === SCHEME_BLS12381G2) {
        const { secret, publicCommitment } = Bls12381G2.keygen();
        return { secret: Secret.fromG2(secret), publicCommitment: PublicCommitment.fromG2(publicCommitment) };
    }
    throw new Error(`keygenWithScheme: unsupported scheme ${scheme}`);
}

export function keygenBLS12381G1(): { secret: Secret; publicCommitment: PublicCommitment } {
    return keygenWithScheme(SCHEME_BLS12381G1);
}

export function keygenBLS12381G2(): { secret: Secret; publicCommitment: PublicCommitment } {
    return keygenWithScheme(SCHEME_BLS12381G2);
}

export function derivePublicCommitment({ secret }: { secret: Secret }): PublicCommitment {
    if (secret.scheme === SCHEME_BLS12381G1) {
        const pc = Bls12381G1.derivePublicCommitment({ secret: secret.inner as Bls12381G1.Secret });
        return PublicCommitment.fromG1(pc);
    }
    if (secret.scheme === SCHEME_BLS12381G2) {
        const pc = Bls12381G2.derivePublicCommitment({ secret: secret.inner as Bls12381G2.Secret });
        return PublicCommitment.fromG2(pc);
    }
    throw new Error(`derivePublicCommitment: unsupported scheme ${secret.scheme}`);
}

export function split({
    secret,
    numShares,
    threshold,
}: {
    secret: Secret;
    numShares: number;
    threshold: number;
}): Result<SecretShare[]> {
    return Result.capture({
        recordsExecutionTimeMs: false,
        task: () => {
            const n = numShares;
            const t = threshold;
            if (secret.scheme === SCHEME_BLS12381G1) {
                const shares = Bls12381G1.split({ secret: secret.inner as Bls12381G1.Secret, n, t }).unwrapOrThrow(
                    "split: Bls12381G1.split failed",
                );
                return shares.map((s) => SecretShare.fromG1(s));
            }
            if (secret.scheme === SCHEME_BLS12381G2) {
                const shares = Bls12381G2.split({ secret: secret.inner as Bls12381G2.Secret, n, t }).unwrapOrThrow(
                    "split: Bls12381G2.split failed",
                );
                return shares.map((s) => SecretShare.fromG2(s));
            }
            throw new Error(`split: unsupported scheme ${secret.scheme}`);
        },
    });
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
            if (scheme === SCHEME_BLS12381G1) {
                const inners = secretShares.map((s) => s.inner as Bls12381G1.SecretShare);
                const s = Bls12381G1.reconstruct({ secretShares: inners }).unwrapOrThrow("reconstruct: Bls12381G1 failed");
                return Secret.fromG1(s);
            }
            if (scheme === SCHEME_BLS12381G2) {
                const inners = secretShares.map((s) => s.inner as Bls12381G2.SecretShare);
                const s = Bls12381G2.reconstruct({ secretShares: inners }).unwrapOrThrow("reconstruct: Bls12381G2 failed");
                return Secret.fromG2(s);
            }
            throw new Error(`reconstruct: unsupported scheme ${scheme}`);
        },
    });
}

export class Secret {
    scheme: number;
    inner: any;

    private constructor(scheme: number, inner: any) {
        this.scheme = scheme;
        this.inner = inner;
    }

    static fromG1(inner: Bls12381G1.Secret): Secret {
        return new Secret(SCHEME_BLS12381G1, inner);
    }

    static fromG2(inner: Bls12381G2.Secret): Secret {
        return new Secret(SCHEME_BLS12381G2, inner);
    }

    static deserialize(deserializer: Deserializer): Result<Secret> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: (extra: Record<string, any>) => {
                const scheme = deserializer.deserializeU8();
                extra["scheme"] = scheme;
                if (scheme === SCHEME_BLS12381G1) {
                    const inner = Bls12381G1.Secret.deserialize(deserializer).unwrapOrThrow(
                        "Bls12381G1.Secret deserialization failed",
                    );
                    return new Secret(scheme, inner);
                }
                if (scheme === SCHEME_BLS12381G2) {
                    const inner = Bls12381G2.Secret.deserialize(deserializer).unwrapOrThrow(
                        "Bls12381G2.Secret deserialization failed",
                    );
                    return new Secret(scheme, inner);
                }
                throw new Error(`Secret.deserialize: unsupported scheme ${scheme}`);
            },
        });
    }

    static fromBytes(bytes: Uint8Array): Result<Secret> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: (_extra: Record<string, any>) => {
                const deserializer = new Deserializer(bytes);
                const obj = Secret.deserialize(deserializer).unwrapOrThrow("Secret.fromBytes failed with deserialization error");
                if (deserializer.remaining() !== 0) {
                    throw "Secret.fromBytes failed with trailing bytes";
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
                return Secret.fromBytes(bytes).unwrapOrThrow("Secret.fromHex failed with bytes deserialization error");
            },
        });
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        if (this.scheme === SCHEME_BLS12381G1) {
            (this.inner as Bls12381G1.Secret).serialize(serializer);
        } else if (this.scheme === SCHEME_BLS12381G2) {
            (this.inner as Bls12381G2.Secret).serialize(serializer);
        } else {
            throw new Error(`Secret.serialize: unsupported scheme ${this.scheme}`);
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

export class PublicCommitment {
    scheme: number;
    inner: any;

    private constructor(scheme: number, inner: any) {
        this.scheme = scheme;
        this.inner = inner;
    }

    static fromG1(inner: Bls12381G1.PublicCommitment): PublicCommitment {
        return new PublicCommitment(SCHEME_BLS12381G1, inner);
    }

    static fromG2(inner: Bls12381G2.PublicCommitment): PublicCommitment {
        return new PublicCommitment(SCHEME_BLS12381G2, inner);
    }

    static deserialize(deserializer: Deserializer): Result<PublicCommitment> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: (extra: Record<string, any>) => {
                const scheme = deserializer.deserializeU8();
                extra["scheme"] = scheme;
                if (scheme === SCHEME_BLS12381G1) {
                    const inner = Bls12381G1.PublicCommitment.deserialize(deserializer).unwrapOrThrow(
                        "Bls12381G1.PublicCommitment deserialization failed",
                    );
                    return new PublicCommitment(scheme, inner);
                }
                if (scheme === SCHEME_BLS12381G2) {
                    const inner = Bls12381G2.PublicCommitment.deserialize(deserializer).unwrapOrThrow(
                        "Bls12381G2.PublicCommitment deserialization failed",
                    );
                    return new PublicCommitment(scheme, inner);
                }
                throw new Error(`PublicCommitment.deserialize: unsupported scheme ${scheme}`);
            },
        });
    }

    static fromBytes(bytes: Uint8Array): Result<PublicCommitment> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = PublicCommitment.deserialize(deserializer).unwrapOrThrow(
                    "PublicCommitment.fromBytes failed with deserialization error",
                );
                if (deserializer.remaining() !== 0) {
                    throw "PublicCommitment.fromBytes failed with trailing bytes";
                }
                return obj;
            },
        });
    }

    static fromHex(hex: string): Result<PublicCommitment> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () =>
                PublicCommitment.fromBytes(hexToBytes(hex)).unwrapOrThrow(
                    "PublicCommitment.fromHex failed with bytes deserialization error",
                ),
        });
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        if (this.scheme === SCHEME_BLS12381G1) {
            (this.inner as Bls12381G1.PublicCommitment).serialize(serializer);
        } else if (this.scheme === SCHEME_BLS12381G2) {
            (this.inner as Bls12381G2.PublicCommitment).serialize(serializer);
        } else {
            throw new Error(`PublicCommitment.serialize: unsupported scheme ${this.scheme}`);
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
    scheme: number;
    inner: any;

    private constructor(scheme: number, inner: any) {
        this.scheme = scheme;
        this.inner = inner;
    }

    static fromG1(inner: Bls12381G1.SecretShare): SecretShare {
        return new SecretShare(SCHEME_BLS12381G1, inner);
    }

    static fromG2(inner: Bls12381G2.SecretShare): SecretShare {
        return new SecretShare(SCHEME_BLS12381G2, inner);
    }

    static deserialize(deserializer: Deserializer): Result<SecretShare> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: (extra: Record<string, any>) => {
                const scheme = deserializer.deserializeU8();
                extra["scheme"] = scheme;
                if (scheme === SCHEME_BLS12381G1) {
                    const inner = Bls12381G1.SecretShare.deserialize(deserializer).unwrapOrThrow(
                        "Bls12381G1.SecretShare deserialization failed",
                    );
                    return new SecretShare(scheme, inner);
                }
                if (scheme === SCHEME_BLS12381G2) {
                    const inner = Bls12381G2.SecretShare.deserialize(deserializer).unwrapOrThrow(
                        "Bls12381G2.SecretShare deserialization failed",
                    );
                    return new SecretShare(scheme, inner);
                }
                throw new Error(`SecretShare.deserialize: unsupported scheme ${scheme}`);
            },
        });
    }

    static fromBytes(bytes: Uint8Array): Result<SecretShare> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = SecretShare.deserialize(deserializer).unwrapOrThrow(
                    "SecretShare.fromBytes failed with deserialization error",
                );
                if (deserializer.remaining() !== 0) {
                    throw "SecretShare.fromBytes failed with trailing bytes";
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
            throw new Error(`SecretShare.serialize: unsupported scheme ${this.scheme}`);
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

export class Session {
    //TODO: this should match Session in vss.move
    dealer: AccountAddress;
    shareHolders: AccountAddress[];
    threshold: number;
    secretScheme: number;
    stateCode: number;
    dealTimeMicros: number;
    dealerContribution0: Uint8Array;
    shareHolderAcks: boolean[];
    dealerContribution1: Uint8Array;

    private constructor({dealer, shareHolders, threshold, secretScheme, stateCode, dealTimeMicros, dealerContribution0, shareHolderAcks, dealerContribution1}: {dealer: AccountAddress, shareHolders: AccountAddress[], threshold: number, secretScheme: number, stateCode: number, dealTimeMicros: number, dealerContribution0: Uint8Array, shareHolderAcks: boolean[], dealerContribution1: Uint8Array}) {
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

    /**
     * Build a {@link Session} from the JSON shape returned by the Aptos node resource API
     * for `ace::vss::Session` (snake_case field names, address hex strings, `u64` as string).
     *
     * Example:
     * ```json
     * {
     *   "deal_time_micros": "0",
     *   "dealer": "0x9b4026268872d0ee307c6aca4562700d3344d302e51d96213c0e1663746b3444",
     *   "dealer_contribution_0": "0x",
     *   "dealer_contribution_1": "0x",
     *   "secret_scheme": 0,
     *   "share_holder_acks": [ false, false, false, false ],
     *   "share_holders": [
     *     "0x9b4026268872d0ee307c6aca4562700d3344d302e51d96213c0e1663746b3444",
     *     "0xe2c4a1ba6571fdc000eee47dc5eee5404e891376093bfe7b9b07aa6580256e5",
     *     "0xe73b92ec1494170f9da69bf81dfd6746f0b418c41afd3fc2180e55ad14656880",
     *     "0x23fef4f7b1a8a745053ae0a0c9745d88c5793b893c68c96ca4eaaf3effedda03"
     *   ],
     *   "state_code": 0,
     *   "threshold": "3"
     * }
     * ```
     */
    static fromNodeResourceApi(dataJson: any): Result<Session> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const parseHexBytes = (field: string): Uint8Array => {
                    const raw = dataJson[field];
                    if (typeof raw !== "string") {
                        throw new Error(`Session.fromNodeResourceApi: "${field}" must be a hex string`);
                    }
                    let hex = raw.trim();
                    if (hex.startsWith("0x") || hex.startsWith("0X")) {
                        hex = hex.slice(2);
                    }
                    if (hex.length === 0) {
                        return new Uint8Array();
                    }
                    if (hex.length % 2 === 1) {
                        hex = `0${hex}`;
                    }
                    return hexToBytes(hex);
                };

                const u64FieldToNumber = (field: string): number => {
                    const raw = dataJson[field];
                    if (raw === undefined || raw === null) {
                        throw new Error(`Session.fromNodeResourceApi: missing field "${field}"`);
                    }
                    const bn = BigInt(String(raw));
                    if (bn < 0n || bn > BigInt(Number.MAX_SAFE_INTEGER)) {
                        throw new Error(`Session.fromNodeResourceApi: "${field}" is out of JS safe integer range`);
                    }
                    return Number(bn);
                };

                if (dataJson.dealer === undefined || dataJson.dealer === null) {
                    throw new Error(`Session.fromNodeResourceApi: missing field "dealer"`);
                }
                const dealer = AccountAddress.fromString(String(dataJson.dealer));

                const holdersRaw = dataJson.share_holders;
                if (!Array.isArray(holdersRaw)) {
                    throw new Error(`Session.fromNodeResourceApi: share_holders must be an array`);
                }
                const shareHolders = holdersRaw.map((a: unknown) => AccountAddress.fromString(String(a)));

                const threshold = u64FieldToNumber("threshold");

                const secretScheme = Number(dataJson.secret_scheme);
                if (secretScheme !== SCHEME_BLS12381G1 && secretScheme !== SCHEME_BLS12381G2) {
                    throw new Error(`Session.fromNodeResourceApi: unsupported secret_scheme ${secretScheme}`);
                }

                const stateCode = Number(dataJson.state_code);
                if (!Number.isInteger(stateCode) || stateCode < 0 || stateCode > 255) {
                    throw new Error(`Session.fromNodeResourceApi: invalid state_code ${dataJson.state_code}`);
                }

                const dealTimeMicros = u64FieldToNumber("deal_time_micros");

                const acksRaw = dataJson.share_holder_acks;
                if (!Array.isArray(acksRaw)) {
                    throw new Error(`Session.fromNodeResourceApi: share_holder_acks must be an array`);
                }
                const shareHolderAcks = acksRaw.map((v: unknown) => Boolean(v));
                if (shareHolderAcks.length !== shareHolders.length) {
                    throw new Error(
                        `Session.fromNodeResourceApi: share_holder_acks length ${shareHolderAcks.length} != share_holders length ${shareHolders.length}`,
                    );
                }

                return new Session({
                    dealer,
                    shareHolders,
                    threshold,
                    secretScheme,
                    stateCode,
                    dealTimeMicros,
                    dealerContribution0: parseHexBytes("dealer_contribution_0"),
                    shareHolderAcks,
                    dealerContribution1: parseHexBytes("dealer_contribution_1"),
                });
            },
        });
    }

    isCompleted(): boolean {
        return this.stateCode === 2; // STATE__SUCCESS
    }
}

export { type SplitConfig } from "./dealing";
