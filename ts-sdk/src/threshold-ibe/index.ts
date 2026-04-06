// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/**
 * @module threshold-ibe
 *
 * Threshold IBE over BLS12-381.
 * The committee holds Shamir shares of a single IBE master scalar r.
 * Encryption uses one IBE ciphertext under the shared MPK = base·r.
 * Decryption: each worker contributes s_i·H_2(id); the client Lagrange-combines
 * ≥threshold partials to reconstruct r·H_2(id) and IBE-decrypts.
 */

export { MasterKeyShare, PartialIdentityKey, ThresholdMasterPublicKey } from "./types";
export { dealerKeygen } from "./keygen";
export type { DealerOutput } from "./keygen";
export { partialExtract } from "./partial_extract";
export { combinePartialKeys } from "./combine";
export { encryptWithMpk } from "./encrypt";
export { decryptWithPartials } from "./decrypt";
export { FR_MODULUS, frMod, frAdd, frMul, frInv } from "./lagrange_fr";
