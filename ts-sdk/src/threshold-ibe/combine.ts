// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

// Client-side Lagrange combination of partial G2 identity keys.
// Computes Σ λ_i · partial_i.partialG2 to reconstruct r · H_2(id).

import { Fp2 } from "@noble/curves/abstract/tower";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
import * as ibe from "../ibe";
import * as OtpHmac from "../ibe/otp_hmac_boneh_franklin_bls12381_short_pk";
import { PartialIdentityKey } from "./types";
import { frMod, frMul, frInv } from "./lagrange_fr";

/**
 * Lagrange-combine ≥threshold partial G2 keys into the full identity private key.
 *
 * λ_i = Π_{j≠i} (0 - x_j) / (x_i - x_j)  where x_k = workerIndex_k
 * result = Σ_i λ_i · partial_i.partialG2
 */
export function combinePartialKeys(partials: PartialIdentityKey[]): ibe.IdentityPrivateKey {
    if (partials.length === 0) throw new Error('combinePartialKeys: no partial keys provided');

    const xs = partials.map(p => BigInt(p.workerIndex));

    // Compute Lagrange coefficients at x=0
    const lambdas = xs.map((xi, i) => {
        let lambda = 1n;
        for (let j = 0; j < xs.length; j++) {
            if (i === j) continue;
            const xj = xs[j];
            const num = frMod(-xj);          // 0 - x_j
            const den = frMod(xi - xj);      // x_i - x_j
            lambda = frMul(lambda, frMul(num, frInv(den)));
        }
        return lambda;
    });

    // Combine: Σ λ_i · partialG2_i
    let combined: WeierstrassPoint<Fp2> | null = null;
    for (let i = 0; i < partials.length; i++) {
        const coeff = lambdas[i];
        if (coeff === 0n) continue;
        const scaled = partials[i].partialG2.multiply(coeff);
        combined = combined === null ? scaled : combined.add(scaled);
    }
    if (combined === null) throw new Error('combinePartialKeys: all Lagrange coefficients were zero');

    const inner = new OtpHmac.IdentityPrivateKey(combined);
    return ibe.IdentityPrivateKey._create(ibe.SCHEME_OTP_HAMC_BONEH_FRANKLIN_BLS12381_SHORT_PK, inner);
}
