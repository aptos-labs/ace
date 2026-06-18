// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use p256::ecdsa::{
    signature::hazmat::PrehashVerifier, Signature as P256Signature,
    VerifyingKey as P256VerifyingKey,
};
use sha2::{Digest, Sha256};

use super::aptos_any::WebAuthnAssertion;

pub(super) fn verify(
    vk: &P256VerifyingKey,
    sig: &P256Signature,
    assertion: &WebAuthnAssertion,
) -> Result<()> {
    let cdj_hash = Sha256::digest(&assertion.client_data_json);
    let mut ecdsa_preimage =
        Vec::with_capacity(assertion.authenticator_data.len() + cdj_hash.len());
    ecdsa_preimage.extend_from_slice(&assertion.authenticator_data);
    ecdsa_preimage.extend_from_slice(&cdj_hash);
    let prehash: [u8; 32] = Sha256::digest(&ecdsa_preimage).into();
    vk.verify_prehash(&prehash, sig).map_err(|e| {
        anyhow!(
            "verify_webauthn_signature: P-256 ECDSA verification failed: {}",
            e
        )
    })
}
