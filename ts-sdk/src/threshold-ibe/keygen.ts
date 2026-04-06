// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

// Trusted-dealer key generation for threshold IBE.
// Generates (base, r, MPK) and Shamir-splits r over Fr.
// In production, this would be replaced by a multi-party DKG protocol.

import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
import { bls12_381 } from "@noble/curves/bls12-381";
import { bytesToNumberBE, bytesToNumberLE, numberToBytesLE } from "@noble/curves/utils";
import { randomBytes } from "@noble/hashes/utils";
import { split } from "../shamir_fr";
import { MasterKeyShare, ThresholdMasterPublicKey } from "./types";

export interface DealerOutput {
    mpk: ThresholdMasterPublicKey;
    masterScalar: bigint;
    masterScalarBytes: Uint8Array;  // 32-byte LE encoding
    shares: MasterKeyShare[];
}

/**
 * Trusted-dealer DKG.
 * 1. Generate a random G1 base point.
 * 2. Generate a random master scalar r in Fr.
 * 3. Compute MPK = base · r.
 * 4. Shamir-split r into `total` shares with reconstruction threshold `threshold`.
 */
export function dealerKeygen(threshold: number, total: number): DealerOutput {
    // Random G1 base
    const base = bls12_381.G1.hashToCurve(randomBytes(32)) as unknown as WeierstrassPoint<bigint>;

    // Random master scalar r (use noble's randomSecretKey for a valid Fr element, BE encoded)
    const rBE = bls12_381.utils.randomSecretKey();
    const r = bytesToNumberBE(rBE);

    // MPK = base · r
    const publicPointG1 = base.multiply(r);
    const mpk = new ThresholdMasterPublicKey(base, publicPointG1);

    // Convert r to 32-byte LE for Shamir split
    const rLE = numberToBytesLE(r, 32);

    const shareBytes = split(rLE, threshold, total).unwrapOrThrow('dealerKeygen: shamir split failed');
    const shares = shareBytes.map((shareLE, i) => {
        const scalar = bytesToNumberLE(shareLE);
        return new MasterKeyShare(base, scalar, i + 1);
    });

    return { mpk, masterScalar: r, masterScalarBytes: rLE, shares };
}
