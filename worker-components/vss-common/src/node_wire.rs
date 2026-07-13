// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Typed BCS wire messages accepted by a worker node's single HTTP endpoint.

use anyhow::{anyhow, Result};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::{
    normalize_account_addr,
    offchain::ShareRequest,
    pke::{self, EncryptionKey},
    sig::{self, sign_ed25519},
};

const VSS_SHARE_REQUEST_SIGNATURE_DOMAIN: &[u8] = b"ace::node-request::vss-share-request::v1";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NodeRequest {
    VssShareRequest(VssShareRequest),
    WorkerRequest(pke::Ciphertext),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NodeResponse {
    VssShareResponse(pke::Ciphertext),
    WorkerResponse(pke::Ciphertext),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VssShareRequest {
    pub payload: VssShareRequestPayload,
    pub sig: sig::Signature,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct VssShareRequestPayload {
    pub sender: String,
    pub recipient: String,
    pub session_addr: String,
    pub holder_index: u64,
    pub response_enc_key: EncryptionKey,
}

impl VssShareRequestPayload {
    pub fn new(
        sender: impl AsRef<str>,
        recipient: impl AsRef<str>,
        session_addr: impl AsRef<str>,
        holder_index: u64,
        response_enc_key: EncryptionKey,
    ) -> Self {
        Self {
            sender: normalize_account_addr(sender.as_ref()),
            recipient: normalize_account_addr(recipient.as_ref()),
            session_addr: normalize_account_addr(session_addr.as_ref()),
            holder_index,
            response_enc_key,
        }
    }

    pub fn share_request(&self) -> ShareRequest {
        ShareRequest {
            session_addr: self.session_addr.clone(),
            holder_index: self.holder_index,
            response_enc_key: self.response_enc_key.clone(),
        }
    }

    pub fn request_id(&self) -> Result<String> {
        self.share_request().request_id()
    }
}

pub fn sign_vss_share_request(
    chain_id: u8,
    ace_addr: &str,
    signing_key: &SigningKey,
    payload: VssShareRequestPayload,
) -> Result<VssShareRequest> {
    let signing_bytes = vss_share_request_signing_bytes(chain_id, ace_addr, &payload)?;
    Ok(VssShareRequest {
        payload,
        sig: sign_ed25519(signing_key, &signing_bytes),
    })
}

pub fn verify_vss_share_request(
    chain_id: u8,
    ace_addr: &str,
    public_key: &sig::PublicKey,
    request: &VssShareRequest,
) -> Result<bool> {
    let signing_bytes = vss_share_request_signing_bytes(chain_id, ace_addr, &request.payload)?;
    public_key.verify(&signing_bytes, &request.sig)
}

#[derive(Serialize)]
struct VssShareRequestToSign {
    domain: Vec<u8>,
    chain_id: u8,
    ace_addr: Vec<u8>,
    sender: Vec<u8>,
    recipient: Vec<u8>,
    session_addr: Vec<u8>,
    holder_index: u64,
    response_enc_key: EncryptionKey,
}

fn vss_share_request_signing_bytes(
    chain_id: u8,
    ace_addr: &str,
    payload: &VssShareRequestPayload,
) -> Result<Vec<u8>> {
    let to_sign = VssShareRequestToSign {
        domain: VSS_SHARE_REQUEST_SIGNATURE_DOMAIN.to_vec(),
        chain_id,
        ace_addr: address_bytes(ace_addr)?.to_vec(),
        sender: address_bytes(&payload.sender)?.to_vec(),
        recipient: address_bytes(&payload.recipient)?.to_vec(),
        session_addr: address_bytes(&payload.session_addr)?.to_vec(),
        holder_index: payload.holder_index,
        response_enc_key: payload.response_enc_key.clone(),
    };
    bcs::to_bytes(&to_sign)
        .map_err(|e| anyhow!("BCS encode VSS share request signing payload: {e}"))
}

fn address_bytes(addr: &str) -> Result<[u8; 32]> {
    let normalized = normalize_account_addr(addr);
    let raw = hex::decode(normalized.trim_start_matches("0x"))?;
    raw.try_into()
        .map_err(|v: Vec<u8>| anyhow!("address must be 32 bytes, got {}", v.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vss_share_request_signature_round_trip() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let payload = VssShareRequestPayload::new(
            "0x1111",
            "0x2222",
            "0x3333",
            4,
            EncryptionKey::HpkeX25519ChaCha20Poly1305(
                crate::pke_hpke_x25519_chacha20poly1305::keygen().0,
            ),
        );
        let request =
            sign_vss_share_request(4, "0xace", &sk, payload.clone()).expect("sign request");
        let pk = sig::PublicKey::from_ed25519_verifying_key(&sk.verifying_key());
        assert!(verify_vss_share_request(4, "0xace", &pk, &request).unwrap());

        let mut tampered = request.clone();
        tampered.payload.holder_index += 1;
        assert!(!verify_vss_share_request(4, "0xace", &pk, &tampered).unwrap());
    }
}
