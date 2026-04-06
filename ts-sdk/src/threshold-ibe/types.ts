// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

import { Fp2 } from "@noble/curves/abstract/tower";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
import { bls12_381 } from "@noble/curves/bls12-381";
import { bytesToHex, hexToBytes } from "@noble/hashes/utils";
import { Result } from "../result";

/**
 * A single worker's share of the IBE master scalar.
 * base·scalarShare gives the worker's contribution to the committee MPK.
 */
export class MasterKeyShare {
    base: WeierstrassPoint<bigint>;
    scalarShare: bigint;    // s_i = f(workerIndex) mod Fr
    workerIndex: number;    // 1-based index in the committee

    constructor(base: WeierstrassPoint<bigint>, scalarShare: bigint, workerIndex: number) {
        this.base = base;
        this.scalarShare = scalarShare;
        this.workerIndex = workerIndex;
    }
}

/**
 * A worker's partial identity key: s_i · H_2(id).
 * The client Lagrange-combines ≥threshold of these to recover r · H_2(id).
 */
export class PartialIdentityKey {
    partialG2: WeierstrassPoint<Fp2>;
    workerIndex: number;    // 1-based index

    constructor(partialG2: WeierstrassPoint<Fp2>, workerIndex: number) {
        this.partialG2 = partialG2;
        this.workerIndex = workerIndex;
    }

    /**
     * Serialize as: [1 byte workerIndex][96 bytes G2 compressed] → hex string.
     */
    toHex(): string {
        const g2Bytes = this.partialG2.toBytes();
        const bytes = new Uint8Array(1 + g2Bytes.length);
        bytes[0] = this.workerIndex;
        bytes.set(g2Bytes, 1);
        return bytesToHex(bytes);
    }

    static fromHex(hex: string): Result<PartialIdentityKey> {
        const task = (_extra: Record<string, any>) => {
            const bytes = hexToBytes(hex);
            if (bytes.length !== 97) {
                throw `PartialIdentityKey.fromHex: expected 97 bytes, got ${bytes.length}`;
            }
            const workerIndex = bytes[0];
            const g2Bytes = bytes.slice(1);
            const partialG2 = bls12_381.G2.Point.fromBytes(g2Bytes) as unknown as WeierstrassPoint<Fp2>;
            return new PartialIdentityKey(partialG2, workerIndex);
        };
        return Result.capture({ task, recordsExecutionTimeMs: false });
    }
}

/**
 * The committee's shared master public key.
 * Structurally identical to ibe.MasterPublicKey: (base, MPK = base·r).
 */
export class ThresholdMasterPublicKey {
    base: WeierstrassPoint<bigint>;
    publicPointG1: WeierstrassPoint<bigint>;    // base · r

    constructor(base: WeierstrassPoint<bigint>, publicPointG1: WeierstrassPoint<bigint>) {
        this.base = base;
        this.publicPointG1 = publicPointG1;
    }
}
