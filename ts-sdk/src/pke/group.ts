// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { RistrettoPoint } from "@noble/curves/ed25519";
import { bytesToHex, bytesToNumberLE, numberToBytesLE } from "@noble/curves/abstract/utils";
import { randBytes } from "../utils";

const Q = BigInt("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed");

export class Element {
    bytes: Uint8Array;

    constructor(bytes: Uint8Array) {
        this.bytes = bytes;
    }

    static dummy(): Element {
        return new Element(new Uint8Array(32));
    }

    static fromInner(inner: InstanceType<typeof RistrettoPoint>): Element {
        const bytes = inner.toRawBytes();
        return new Element(bytes);
    }

    static groupIdentity(): Element {
        return Element.fromInner(RistrettoPoint.ZERO);
    }

    static rand(): Element {
        const randomBytes = randBytes(64);
        const point = RistrettoPoint.hashToCurve(randomBytes);
        return Element.fromInner(point);
    }

    static decode(deserializer: Deserializer): Element {
        const bytes = deserializer.deserializeBytes();
        return new Element(bytes);
    }

    encode(serializer: Serializer): void {
        serializer.serializeBytes(this.bytes);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.encode(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    asInner(): InstanceType<typeof RistrettoPoint> {
        return RistrettoPoint.fromHex(this.bytes);
    }

    add(other: Element): Element {
        const pointA = this.asInner();
        const pointB = other.asInner();
        const result = pointA.add(pointB);
        return Element.fromInner(result);
    }

    sub(other: Element): Element {
        const pointA = this.asInner();
        const pointB = other.asInner();
        const result = pointA.subtract(pointB);
        return Element.fromInner(result);
    }

    scale(scalar: Scalar): Element {
        if (scalar.isZero()) {
            return Element.groupIdentity();
        }
        const point = this.asInner();
        const s = bytesToNumberLE(scalar.bytes);
        const result = point.multiply(s);
        return Element.fromInner(result);
    }
}

export class Scalar {
    bytes: Uint8Array;

    constructor(bytes: Uint8Array) {
        this.bytes = bytes;
    }

    static dummy(): Scalar {
        return new Scalar(new Uint8Array(32));
    }

    static fromU64(x: bigint): Scalar {
        return new Scalar(numberToBytesLE(x, 32));
    }

    static fromLittleEndianBytesModQ(bytes: Uint8Array): Scalar {
        const value = bytesToNumberLE(bytes) % Q;
        return new Scalar(numberToBytesLE(value, 32));
    }

    static rand(): Scalar {
        const randomBytes = randBytes(64);
        const value = bytesToNumberLE(randomBytes) % Q;
        const scalarValue = value === 0n ? 1n : value;
        return new Scalar(numberToBytesLE(scalarValue, 32));
    }

    static decode(deserializer: Deserializer): Scalar {
        const bytes = deserializer.deserializeBytes();
        return new Scalar(bytes);
    }

    encode(serializer: Serializer): void {
        serializer.serializeBytes(this.bytes);
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.encode(serializer);
        return serializer.toUint8Array();
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    isZero(): boolean {
        return this.bytes.every((b) => b === 0);
    }

    add(other: Scalar): Scalar {
        const result = (bytesToNumberLE(this.bytes) + bytesToNumberLE(other.bytes)) % Q;
        return new Scalar(numberToBytesLE(result, 32));
    }

    sub(other: Scalar): Scalar {
        const result = (Q - bytesToNumberLE(other.bytes) + bytesToNumberLE(this.bytes)) % Q;
        return new Scalar(numberToBytesLE(result, 32));
    }

    mul(other: Scalar): Scalar {
        const result = (bytesToNumberLE(this.bytes) * bytesToNumberLE(other.bytes)) % Q;
        return new Scalar(numberToBytesLE(result, 32));
    }

    neg(): Scalar {
        const result = Q - bytesToNumberLE(this.bytes);
        return new Scalar(numberToBytesLE(result, 32));
    }
}

export function msm(bases: Element[], scalars: Scalar[]): Element {
    let acc = Element.groupIdentity();
    for (let i = 0; i < bases.length; i++) {
        const scaled = bases[i].scale(scalars[i]);
        acc = acc.add(scaled);
    }
    return acc;
}

export function scalarFrom512BitHash(hash: Uint8Array): Scalar {
    if (hash.length !== 64) {
        throw new Error("Hash must be 512 bits (64 bytes)");
    }
    const value = bytesToNumberLE(hash.slice(0, 32)) % Q;
    const scalarValue = value === 0n ? 1n : value;
    return new Scalar(numberToBytesLE(scalarValue, 32));
}
