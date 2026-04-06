// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

// Worker-side partial key extraction for threshold IBE.
// Computes s_i · H_2(id) where s_i is the worker's scalar share.

import { Fp2 } from "@noble/curves/abstract/tower";
import { WeierstrassPoint } from "@noble/curves/abstract/weierstrass";
import { bls12_381 } from "@noble/curves/bls12-381";
import { MasterKeyShare, PartialIdentityKey } from "./types";

// Must match the DST used in otp_hmac_boneh_franklin_bls12381_short_pk.ts
const DST_ID_HASH = new TextEncoder().encode("BONEH_FRANKLIN_BLS12381_SHORT_PK/HASH_ID_TO_CURVE");

/**
 * Compute the partial identity key for a given identity.
 *
 * @param keyShare - The worker's share of the master scalar
 * @param id       - The IBE identity bytes (typically FullDecryptionDomain.toBytes())
 */
export function partialExtract(keyShare: MasterKeyShare, id: Uint8Array): PartialIdentityKey {
    const idPoint = bls12_381.G2.hashToCurve(id, { DST: DST_ID_HASH }) as unknown as WeierstrassPoint<Fp2>;
    const partialG2 = idPoint.multiply(keyShare.scalarShare);
    return new PartialIdentityKey(partialG2, keyShare.workerIndex);
}
