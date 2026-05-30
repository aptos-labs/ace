// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import * as Bls12381G1 from "../group/bls12381g1";
import * as Bls12381G2 from "../group/bls12381g2";
import { Element, Scalar } from "../group";
import { Result } from "../result";

export class PublicParams {
    constructor(readonly generatorG: Element, readonly generatorH: Element) {}

    serialize(serializer: Serializer): void {
        this.generatorG.serialize(serializer);
        this.generatorH.serialize(serializer);
    }

    static deserialize(deserializer: Deserializer): Result<PublicParams> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const generatorG = Element.deserialize(deserializer).unwrapOrThrow("generatorG deserialize failed");
                const generatorH = Element.deserialize(deserializer).unwrapOrThrow("generatorH deserialize failed");
                return new PublicParams(generatorG, generatorH);
            },
        });
    }
}

/** Pedersen PCS commitment points over the ACE domain {0, 1, ..., n}. */
export class Commitment {
    constructor(readonly points: Element[]) {}

    static fromBls12381G1(innerPoints: Bls12381G1.PcsCommitment): Commitment {
        return new Commitment(
            innerPoints.vValues.map((pt) => Element.fromBls12381G1(new Bls12381G1.PublicPoint(pt)))
        );
    }

    static fromBls12381G2(innerPoints: Bls12381G2.PcsCommitment): Commitment {
        return new Commitment(
            innerPoints.vValues.map((pt) => Element.fromBls12381G2(new Bls12381G2.PublicPoint(pt)))
        );
    }

    serialize(serializer: Serializer): void {
        serializer.serializeU32AsUleb128(this.points.length);
        for (const pt of this.points) {
            pt.serialize(serializer);
        }
    }

    static deserialize(deserializer: Deserializer): Result<Commitment> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const len = deserializer.deserializeUleb128AsU32();
                const points: Element[] = [];
                for (let i = 0; i < len; i++) {
                    const pt = Element.deserialize(deserializer).unwrapOrThrow(`point[${i}] deserialize failed`);
                    points.push(pt);
                }
                return new Commitment(points);
            },
        });
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<Commitment> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = Commitment.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return obj;
            },
        });
    }

    toHex(): string {
        return bytesToHex(this.toBytes());
    }

    static fromHex(hex: string): Result<Commitment> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => Commitment.fromBytes(hexToBytes(hex)).unwrapOrThrow("deserialization failed"),
        });
    }
}

export class Opening {
    constructor(
        readonly evalPosition: number,
        readonly evalValueP: Scalar,
        readonly evalValueR: Scalar,
    ) {}

    serialize(serializer: Serializer): void {
        serializer.serializeU64(this.evalPosition);
        this.evalValueP.serialize(serializer);
        this.evalValueR.serialize(serializer);
    }

    static deserialize(deserializer: Deserializer): Result<Opening> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const evalPosition = Number(deserializer.deserializeU64());
                const evalValueP = Scalar.deserialize(deserializer).unwrapOrThrow("evalValueP deserialize failed");
                const evalValueR = Scalar.deserialize(deserializer).unwrapOrThrow("evalValueR deserialize failed");
                return new Opening(evalPosition, evalValueP, evalValueR);
            },
        });
    }

    toBytes(): Uint8Array {
        const serializer = new Serializer();
        this.serialize(serializer);
        return serializer.toUint8Array();
    }

    static fromBytes(bytes: Uint8Array): Result<Opening> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const deserializer = new Deserializer(bytes);
                const obj = Opening.deserialize(deserializer).unwrapOrThrow("deserialize failed");
                if (deserializer.remaining() !== 0) throw "trailing bytes";
                return obj;
            },
        });
    }
}
