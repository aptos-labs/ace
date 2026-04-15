// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { Result } from "../result";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import * as Bls12381G1 from "./bls12381g1";

export * as bls12381G1 from "./bls12381g1";

export const SCHEME_BLS12381G1 = 0;

// ── Scalar ────────────────────────────────────────────────────────────────────

export class Scalar {
    constructor(readonly scheme: number, readonly inner: any) {}

    asBls12381G1(): Bls12381G1.PrivateScalar {
        if (this.scheme !== SCHEME_BLS12381G1) throw 'wrong scheme';
        return this.inner as Bls12381G1.PrivateScalar;
    }

    static deserialize(deserializer: Deserializer): Result<Scalar> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: (extra: Record<string, any>) => {
                const scheme = deserializer.deserializeU8();
                extra["scheme"] = scheme;
                if (scheme === SCHEME_BLS12381G1) {
                    const inner = Bls12381G1.PrivateScalar.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                    return new Scalar(SCHEME_BLS12381G1, inner);
                }
                throw 'unsupported scheme';
            },
        });
    }

    static fromBytes(bytes: Uint8Array): Result<Scalar> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = Scalar.deserialize(deserializer).unwrapOrThrow("deserialization failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return obj;
            },
        });
    }

    static fromHex(hex: string): Result<Scalar> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const bytes = hexToBytes(hex);
                return Scalar.fromBytes(bytes).unwrapOrThrow("deserialization failed");
            },
        });
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        if (this.scheme === SCHEME_BLS12381G1) {
            (this.inner as Bls12381G1.PrivateScalar).serialize(serializer);
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

// ── Element ───────────────────────────────────────────────────────────────────

export class Element {
    constructor(readonly scheme: number, readonly inner: any) {}

    static fromBls12381G1(inner: Bls12381G1.PublicPoint): Element {
        return new Element(SCHEME_BLS12381G1, inner);
    }

    /** Scalar multiplication: returns scalar * this. */
    scale(scalar: Scalar): Element {
        if (this.scheme === SCHEME_BLS12381G1) {
            const result = (this.inner as Bls12381G1.PublicPoint).scale(scalar.asBls12381G1());
            return new Element(SCHEME_BLS12381G1, result);
        }
        throw `scale: unsupported scheme ${this.scheme}`;
    }

    /** Projective equality check. */
    equals(other: Element): boolean {
        if (this.scheme !== other.scheme) return false;
        if (this.scheme === SCHEME_BLS12381G1) {
            return (this.inner as Bls12381G1.PublicPoint).equals(other.inner as Bls12381G1.PublicPoint);
        }
        throw `equals: unsupported scheme ${this.scheme}`;
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU8(this.scheme);
        if (this.scheme === SCHEME_BLS12381G1) {
            (this.inner as Bls12381G1.PublicPoint).serialize(serializer);
        } else {
            throw 'unsupported scheme';
        }
    }

    static deserialize(deserializer: Deserializer): Result<Element> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: (extra: Record<string, any>) => {
                const scheme = deserializer.deserializeU8();
                extra["scheme"] = scheme;
                if (scheme === SCHEME_BLS12381G1) {
                    const inner = Bls12381G1.PublicPoint.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                    return new Element(SCHEME_BLS12381G1, inner);
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

    static fromBytes(bytes: Uint8Array): Result<Element> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = Element.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return obj;
            },
        });
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<Element> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => Element.fromBytes(hexToBytes(hex)).unwrapOrThrow("deserialization failed"),
        });
    }
}
