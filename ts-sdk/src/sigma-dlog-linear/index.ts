// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Deserializer, Serializer } from "@aptos-labs/ts-sdk";
import { Element, Scalar } from "../group";
import { Result } from "../result";

export class Proof {
    constructor(readonly tVals: Element[], readonly zVals: Scalar[]) {}

    serialize(serializer: Serializer): void {
        serializer.serializeU32AsUleb128(this.tVals.length);
        for (const t of this.tVals) t.serialize(serializer);
        serializer.serializeU32AsUleb128(this.zVals.length);
        for (const z of this.zVals) z.serialize(serializer);
    }

    static deserialize(deserializer: Deserializer): Result<Proof> {
        return Result.capture({
            recordsExecutionTimeMs: false,
            task: () => {
                const tLen = deserializer.deserializeUleb128AsU32();
                const tVals: Element[] = [];
                for (let i = 0; i < tLen; i++) {
                    tVals.push(Element.deserialize(deserializer).unwrapOrThrow(`tVals[${i}] deserialize failed`));
                }
                const zLen = deserializer.deserializeUleb128AsU32();
                const zVals: Scalar[] = [];
                for (let i = 0; i < zLen; i++) {
                    zVals.push(Scalar.deserialize(deserializer).unwrapOrThrow(`zVals[${i}] deserialize failed`));
                }
                return new Proof(tVals, zVals);
            },
        });
    }
}
