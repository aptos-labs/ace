// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Rust mirror of `ace::secret_usage` for request-time policy checks.

use anyhow::{anyhow, Result};

use crate::crypto::{SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC, SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD};

pub const USAGE_BFIBE_BLS12381_SHORTPK_OTP_HMAC: u64 = 1;
pub const USAGE_BFIBE_BLS12381_SHORTSIG_AEAD: u64 = 2;
pub const USAGE_BLS12381_THRESHOLD_VRF: u64 = 4;

pub fn usage_for_tibe_scheme(tibe_scheme: u8) -> Result<u64> {
    match tibe_scheme {
        SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC => Ok(USAGE_BFIBE_BLS12381_SHORTPK_OTP_HMAC),
        SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD => Ok(USAGE_BFIBE_BLS12381_SHORTSIG_AEAD),
        s => Err(anyhow!("unsupported t-IBE scheme {}", s)),
    }
}

pub fn allows_usage(expected_usage: u64, required_usage: u64) -> bool {
    (expected_usage & required_usage) != 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tibe_scheme_maps_to_usage_bit() {
        assert_eq!(
            usage_for_tibe_scheme(SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC).unwrap(),
            USAGE_BFIBE_BLS12381_SHORTPK_OTP_HMAC
        );
        assert_eq!(
            usage_for_tibe_scheme(SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD).unwrap(),
            USAGE_BFIBE_BLS12381_SHORTSIG_AEAD
        );
        assert!(usage_for_tibe_scheme(0xff).is_err());
    }

    #[test]
    fn usage_mask_checks_required_bit() {
        let both_g2 = USAGE_BFIBE_BLS12381_SHORTSIG_AEAD | USAGE_BLS12381_THRESHOLD_VRF;
        assert!(allows_usage(both_g2, USAGE_BFIBE_BLS12381_SHORTSIG_AEAD));
        assert!(allows_usage(both_g2, USAGE_BLS12381_THRESHOLD_VRF));
        assert!(!allows_usage(
            both_g2,
            USAGE_BFIBE_BLS12381_SHORTPK_OTP_HMAC
        ));
    }
}
