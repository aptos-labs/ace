// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Minimal RSA JWK representation.
//!
//! Mirrors `aptos_types::jwks::rsa::RSA_JWK` on the BCS wire — used here as
//! the input to [`crate::verify_keyless`] for the kid-match check. JWT
//! signature verification under this JWK is *not yet* implemented (TODO).

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[allow(non_camel_case_types)]
pub struct RsaJwk {
    pub kid: String,
    pub kty: String,
    pub alg: String,
    /// Public exponent, base64url-encoded (typically `"AQAB"` for 65537).
    pub e: String,
    /// Public modulus, base64url-encoded.
    pub n: String,
}
