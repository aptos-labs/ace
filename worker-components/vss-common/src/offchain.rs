// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! BCS message bodies and response encryption for off-chain VSS share delivery.

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

use crate::{
    pke::{self, EncryptionKey},
    pke_hpke_x25519_chacha20poly1305 as hpke,
};

const SHARE_RESPONSE_AAD_DOMAIN: &str = "ace::vss::share-response::v1";
const SHARE_REQUEST_ID_DOMAIN: &[u8] = b"ace::vss::share-request-id::v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ShareRequest {
    pub session_addr: String,
    pub holder_index: u64,
    /// Fresh HPKE key used only for this response.
    pub response_enc_key: EncryptionKey,
}

/// The private half of a request's ephemeral response keypair.
pub struct ShareResponseDecryptionKey(hpke::DecryptionKey);

impl Drop for ShareResponseDecryptionKey {
    fn drop(&mut self) {
        self.0.sk.zeroize();
    }
}

impl ShareRequest {
    pub fn new(
        session_addr: impl Into<String>,
        holder_index: u64,
    ) -> (Self, ShareResponseDecryptionKey) {
        let (ek, dk) = hpke::keygen();
        (
            Self {
                session_addr: session_addr.into(),
                holder_index,
                response_enc_key: EncryptionKey::HpkeX25519ChaCha20Poly1305(ek),
            },
            ShareResponseDecryptionKey(dk),
        )
    }

    pub fn request_id(&self) -> Result<String> {
        let request_bcs = bcs::to_bytes(self)
            .map_err(|e| anyhow!("encode VSS share request for request ID: {}", e))?;
        let mut hasher = Sha256::new();
        hasher.update(SHARE_REQUEST_ID_DOMAIN);
        hasher.update(request_bcs);
        Ok(format!("vss-share:{}", hex::encode(hasher.finalize())))
    }
}

#[derive(Serialize)]
struct ShareResponseAad<'a> {
    domain: &'static str,
    sender: &'a str,
    recipient: &'a str,
    request_id: &'a str,
    request: &'a ShareRequest,
}

fn response_aad(
    request: &ShareRequest,
    sender: &str,
    recipient: &str,
    request_id: &str,
) -> Result<Vec<u8>> {
    bcs::to_bytes(&ShareResponseAad {
        domain: SHARE_RESPONSE_AAD_DOMAIN,
        sender,
        recipient,
        request_id,
        request,
    })
    .map_err(|e| anyhow!("encode VSS share-response AAD: {}", e))
}

pub fn encrypt_share_response(
    request: &ShareRequest,
    sender: &str,
    recipient: &str,
    request_id: &str,
    share_bcs: &[u8],
) -> Result<Vec<u8>> {
    let ciphertext =
        encrypt_share_response_ciphertext(request, sender, recipient, request_id, share_bcs)?;
    bcs::to_bytes(&ciphertext).map_err(|e| anyhow!("encode encrypted VSS share response: {}", e))
}

pub fn encrypt_share_response_ciphertext(
    request: &ShareRequest,
    sender: &str,
    recipient: &str,
    request_id: &str,
    share_bcs: &[u8],
) -> Result<pke::Ciphertext> {
    let ek = match &request.response_enc_key {
        EncryptionKey::HpkeX25519ChaCha20Poly1305(ek) => ek,
        EncryptionKey::ElGamalOtpRistretto255(_) => {
            return Err(anyhow!(
                "VSS share responses require HPKE-X25519 response encryption"
            ));
        }
    };
    let aad = response_aad(request, sender, recipient, request_id)?;
    let ciphertext = hpke::encrypt(ek, share_bcs, &aad)?;
    Ok(pke::Ciphertext::HpkeX25519ChaCha20Poly1305(ciphertext))
}

pub fn decrypt_share_response(
    request: &ShareRequest,
    response_dk: &ShareResponseDecryptionKey,
    sender: &str,
    recipient: &str,
    request_id: &str,
    response_bytes: &[u8],
) -> Result<Vec<u8>> {
    let ciphertext: pke::Ciphertext = bcs::from_bytes(response_bytes)
        .map_err(|e| anyhow!("decode encrypted VSS share response: {}", e))?;
    decrypt_share_response_ciphertext(
        request,
        response_dk,
        sender,
        recipient,
        request_id,
        &ciphertext,
    )
}

pub fn decrypt_share_response_ciphertext(
    request: &ShareRequest,
    response_dk: &ShareResponseDecryptionKey,
    sender: &str,
    recipient: &str,
    request_id: &str,
    response_ciphertext: &pke::Ciphertext,
) -> Result<Vec<u8>> {
    let request_ek = match &request.response_enc_key {
        EncryptionKey::HpkeX25519ChaCha20Poly1305(ek) => ek,
        EncryptionKey::ElGamalOtpRistretto255(_) => {
            return Err(anyhow!(
                "VSS share responses require HPKE-X25519 response encryption"
            ));
        }
    };
    let derived_ek = hpke::derive_encryption_key(&response_dk.0)?;
    if &derived_ek != request_ek {
        return Err(anyhow!(
            "VSS share response decryption key does not match request encryption key"
        ));
    }

    let ciphertext = match response_ciphertext {
        pke::Ciphertext::HpkeX25519ChaCha20Poly1305(ciphertext) => ciphertext,
        pke::Ciphertext::ElGamalOtpRistretto255(_) => {
            return Err(anyhow!("VSS share response ciphertext is not HPKE-X25519"));
        }
    };
    let aad = response_aad(request, sender, recipient, request_id)?;
    hpke::decrypt(&response_dk.0, &ciphertext, &aad)
        .map_err(|e| anyhow!("decrypt VSS share response: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOLDER: &str = "0xholder";
    const DEALER: &str = "0xdealer";

    #[test]
    fn share_response_round_trip() {
        let (request, dk) = ShareRequest::new("0xsession", 2);
        let request_id = request.request_id().unwrap();
        let opening = vec![0x5a; 96];
        let response =
            encrypt_share_response(&request, HOLDER, DEALER, &request_id, &opening).unwrap();

        let decrypted =
            decrypt_share_response(&request, &dk, HOLDER, DEALER, &request_id, &response).unwrap();
        assert_eq!(decrypted, opening);
    }

    #[test]
    fn share_response_is_bound_to_request_transcript() {
        let (request, dk) = ShareRequest::new("0xsession", 2);
        let request_id = request.request_id().unwrap();
        let response =
            encrypt_share_response(&request, HOLDER, DEALER, &request_id, b"opening").unwrap();

        assert!(decrypt_share_response(
            &request,
            &dk,
            HOLDER,
            DEALER,
            "different-request",
            &response,
        )
        .is_err());
        assert!(decrypt_share_response(
            &request,
            &dk,
            "0xdifferent-holder",
            DEALER,
            &request_id,
            &response,
        )
        .is_err());

        let mut different_request = request.clone();
        different_request.holder_index += 1;
        assert!(decrypt_share_response(
            &different_request,
            &dk,
            HOLDER,
            DEALER,
            &request_id,
            &response,
        )
        .is_err());
    }

    #[test]
    fn share_response_rejects_a_different_ephemeral_key() {
        let (request, _) = ShareRequest::new("0xsession", 2);
        let (_, wrong_dk) = ShareRequest::new("0xsession", 2);
        let request_id = request.request_id().unwrap();
        let response =
            encrypt_share_response(&request, HOLDER, DEALER, &request_id, b"opening").unwrap();

        let err =
            decrypt_share_response(&request, &wrong_dk, HOLDER, DEALER, &request_id, &response)
                .unwrap_err();
        assert!(err
            .to_string()
            .contains("does not match request encryption key"));
    }
}
