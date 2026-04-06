// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

// IBE decryption using combined partial identity keys.
// Lagrange-combines partial G2 keys, then delegates to ibe.decrypt.

import * as ibe from "../ibe";
import { Result } from "../result";
import { PartialIdentityKey } from "./types";
import { combinePartialKeys } from "./combine";

/**
 * Combine ≥threshold partial identity keys and IBE-decrypt a ciphertext.
 *
 * @param partials    - Partial identity keys from ≥threshold workers
 * @param ciphertext  - The IBE ciphertext to decrypt
 */
export function decryptWithPartials(
    partials: PartialIdentityKey[],
    ciphertext: ibe.Ciphertext,
): Result<Uint8Array> {
    const task = (extra: Record<string, any>) => {
        extra['numPartials'] = partials.length;
        const combinedKey = combinePartialKeys(partials);
        return ibe.decrypt(combinedKey, ciphertext).unwrapOrThrow('ThresholdIBE.decryptWithPartials: IBE decrypt failed');
    };
    return Result.capture({ task, recordsExecutionTimeMs: true });
}
