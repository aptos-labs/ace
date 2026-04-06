// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

// IBE encryption under the committee's shared master public key.
// Delegates to ibe.encrypt after converting ThresholdMasterPublicKey to ibe.MasterPublicKey.

import * as ibe from "../ibe";
import * as OtpHmac from "../ibe/otp_hmac_boneh_franklin_bls12381_short_pk";
import { Result } from "../result";
import { ThresholdMasterPublicKey } from "./types";

function toIbeMpk(mpk: ThresholdMasterPublicKey): ibe.MasterPublicKey {
    const inner = new OtpHmac.MasterPublicKey(mpk.base, mpk.publicPointG1);
    return ibe.MasterPublicKey._create(ibe.SCHEME_OTP_HAMC_BONEH_FRANKLIN_BLS12381_SHORT_PK, inner);
}

/**
 * IBE-encrypt plaintext under the committee's ThresholdMasterPublicKey.
 *
 * @param mpk       - Committee master public key
 * @param id        - IBE identity (typically FullDecryptionDomain.toBytes())
 * @param plaintext - Bytes to encrypt (typically the symmetric key)
 */
export function encryptWithMpk(
    mpk: ThresholdMasterPublicKey,
    id: Uint8Array,
    plaintext: Uint8Array,
): Result<ibe.Ciphertext> {
    return ibe.encrypt(toIbeMpk(mpk), id, plaintext);
}
