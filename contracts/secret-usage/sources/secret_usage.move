// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Registry for ACE threshold-secret usages.
///
/// Primitive id `i` corresponds to bit `1 << i` in a secret usage mask. The
/// group scheme remains an implementation detail derived from that mask.
module ace::secret_usage {
    use std::error;
    use std::string::{Self, String};
    use ace::group;

    const E_UNSUPPORTED_USAGE: u64 = 1;
    const E_INCONSISTENT_GROUP_SCHEME: u64 = 2;
    const E_NOTE_TOO_LONG: u64 = 3;

    const NO_GROUP_SCHEME: u8 = 255;

    const PRIMITIVE__BFIBE_BLS12381_SHORTPK_OTP_HMAC: u8 = 0;
    const PRIMITIVE__BFIBE_BLS12381_SHORTSIG_AEAD: u8 = 1;
    const PRIMITIVE__BLS12381_THRESHOLD_VRF: u8 = 2;

    const USAGE__BFIBE_BLS12381_SHORTPK_OTP_HMAC: u64 = 1;
    const USAGE__BFIBE_BLS12381_SHORTSIG_AEAD: u64 = 2;
    const USAGE__BLS12381_THRESHOLD_VRF: u64 = 4;

    const SUPPORTED_USAGE_MASK: u64 = 7;
    const MAX_NOTE_BYTES: u64 = 256;

    struct SecretRequest has copy, drop, store {
        expected_usage: u64,
        note: String,
    }

    #[view]
    public fun primitive_bfibe_bls12381_shortpk_otp_hmac(): u8 {
        PRIMITIVE__BFIBE_BLS12381_SHORTPK_OTP_HMAC
    }

    #[view]
    public fun primitive_bfibe_bls12381_shortsig_aead(): u8 {
        PRIMITIVE__BFIBE_BLS12381_SHORTSIG_AEAD
    }

    #[view]
    public fun primitive_bls12381_threshold_vrf(): u8 {
        PRIMITIVE__BLS12381_THRESHOLD_VRF
    }

    #[view]
    public fun usage_bfibe_bls12381_shortpk_otp_hmac(): u64 {
        USAGE__BFIBE_BLS12381_SHORTPK_OTP_HMAC
    }

    #[view]
    public fun usage_bfibe_bls12381_shortsig_aead(): u64 {
        USAGE__BFIBE_BLS12381_SHORTSIG_AEAD
    }

    #[view]
    public fun usage_bls12381_threshold_vrf(): u64 {
        USAGE__BLS12381_THRESHOLD_VRF
    }

    #[view]
    public fun supported_usage_mask(): u64 {
        SUPPORTED_USAGE_MASK
    }

    #[view]
    public fun max_note_bytes(): u64 {
        MAX_NOTE_BYTES
    }

    #[view]
    public fun usage_for_primitive(primitive: u8): u64 {
        if (primitive == PRIMITIVE__BFIBE_BLS12381_SHORTPK_OTP_HMAC) {
            USAGE__BFIBE_BLS12381_SHORTPK_OTP_HMAC
        } else if (primitive == PRIMITIVE__BFIBE_BLS12381_SHORTSIG_AEAD) {
            USAGE__BFIBE_BLS12381_SHORTSIG_AEAD
        } else if (primitive == PRIMITIVE__BLS12381_THRESHOLD_VRF) {
            USAGE__BLS12381_THRESHOLD_VRF
        } else {
            abort error::invalid_argument(E_UNSUPPORTED_USAGE)
        }
    }

    #[view]
    public fun primitive_group_scheme(primitive: u8): u8 {
        usage_group_scheme(usage_for_primitive(primitive))
    }

    public fun new_request(expected_usage: u64, note: String): SecretRequest {
        validate_metadata(expected_usage, &note);
        SecretRequest { expected_usage, note }
    }

    public fun request_expected_usage(request: &SecretRequest): u64 {
        request.expected_usage
    }

    public fun request_note(request: &SecretRequest): String {
        request.note
    }

    public fun validate_request(request: &SecretRequest): u8 {
        validate_metadata(request.expected_usage, &request.note)
    }

    public fun validate_metadata(expected_usage: u64, note: &String): u8 {
        let scheme = usage_group_scheme(expected_usage);
        assert!(string::length(note) <= MAX_NOTE_BYTES, error::invalid_argument(E_NOTE_TOO_LONG));
        scheme
    }

    public fun usage_supported(expected_usage: u64): bool {
        expected_usage != 0 && (expected_usage | SUPPORTED_USAGE_MASK) == SUPPORTED_USAGE_MASK
    }

    public fun usage_group_scheme(expected_usage: u64): u8 {
        assert!(usage_supported(expected_usage), error::invalid_argument(E_UNSUPPORTED_USAGE));

        let scheme = NO_GROUP_SCHEME;
        if (has_usage(expected_usage, USAGE__BFIBE_BLS12381_SHORTPK_OTP_HMAC)) {
            scheme = merge_group_scheme(scheme, group::scheme_bls12381_g1());
        };
        if (has_usage(expected_usage, USAGE__BFIBE_BLS12381_SHORTSIG_AEAD)) {
            scheme = merge_group_scheme(scheme, group::scheme_bls12381_g2());
        };
        if (has_usage(expected_usage, USAGE__BLS12381_THRESHOLD_VRF)) {
            scheme = merge_group_scheme(scheme, group::scheme_bls12381_g2());
        };

        scheme
    }

    public fun request_group_scheme(request: &SecretRequest): u8 {
        usage_group_scheme(request.expected_usage)
    }

    fun has_usage(expected_usage: u64, usage: u64): bool {
        (expected_usage & usage) != 0
    }

    fun merge_group_scheme(current: u8, next: u8): u8 {
        if (current == NO_GROUP_SCHEME) {
            next
        } else {
            assert!(current == next, error::invalid_argument(E_INCONSISTENT_GROUP_SCHEME));
            current
        }
    }
}
