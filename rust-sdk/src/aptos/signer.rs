// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! The `sign` callback every Aptos decrypt/derive flow takes (TS: `sign: (msgToSign) =>
//! Promise<{pubKey, signature, fullMessage}>`), plus `buildAptosWalletFullMessage`
//! (`ts-sdk/src/ibe-for-aptos/aptos-wallet-message.ts`) and an Ed25519 implementation.

use async_trait::async_trait;

use super::common::{AptosPublicKey, AptosSignature};
use crate::address::AccountAddress;
use crate::error::Result;

/// What a wallet returns after signing an Aptos "sign message" request.
#[derive(Clone, Debug)]
pub struct SignedMessage {
    pub pub_key: AptosPublicKey,
    pub signature: AptosSignature,
    /// The exact string that was signed (`build_aptos_wallet_full_message` output).
    pub full_message: String,
}

#[async_trait]
pub trait MessageSigner: Send + Sync {
    fn account_address(&self) -> AccountAddress;
    /// `msg_to_sign` is the hex request payload the flow wants covered; the signer wraps it in
    /// the wallet full-message envelope (or lets the wallet do so) and signs that.
    async fn sign(&self, msg_to_sign: &str) -> Result<SignedMessage>;
}

/// Exactly the Aptos wallet-standard envelope, joined with `\n`.
pub fn build_aptos_wallet_full_message(
    account_address: &AccountAddress,
    application: &str,
    chain_id: u8,
    message: &str,
    nonce: &str,
) -> String {
    [
        "APTOS".to_string(),
        format!("address: {}", account_address.to_string_long()),
        format!("application: {application}"),
        format!("chainId: {chain_id}"),
        format!("message: {message}"),
        format!("nonce: {nonce}"),
    ]
    .join("\n")
}

/// Ed25519 single-key signer (what an Aptos SDK `Account` does for `signMessage`).
pub struct Ed25519Signer {
    key: ed25519_dalek::SigningKey,
    address: AccountAddress,
    pub application: String,
    pub chain_id: u8,
}

impl Ed25519Signer {
    /// `address` defaults to the Ed25519 auth-key address `sha3_256(pubkey || 0x00)`.
    pub fn new(private_key: &[u8; 32], application: impl Into<String>, chain_id: u8) -> Self {
        let key = ed25519_dalek::SigningKey::from_bytes(private_key);
        let mut pre = key.verifying_key().to_bytes().to_vec();
        pre.push(0u8); // Ed25519 single-key scheme id
        let address = AccountAddress(crate::utils::sha3_256(&pre));
        Self {
            key,
            address,
            application: application.into(),
            chain_id,
        }
    }
    /// Use when the on-chain account address differs from the derived auth key (rotated keys).
    pub fn with_address(mut self, address: AccountAddress) -> Self {
        self.address = address;
        self
    }
    pub fn public_key_bytes(&self) -> [u8; 32] {
        self.key.verifying_key().to_bytes()
    }
}

#[async_trait]
impl MessageSigner for Ed25519Signer {
    fn account_address(&self) -> AccountAddress {
        self.address
    }
    async fn sign(&self, msg_to_sign: &str) -> Result<SignedMessage> {
        use ed25519_dalek::Signer as _;
        let nonce = crate::utils::rand_u64().to_string();
        let full_message = build_aptos_wallet_full_message(
            &self.address,
            &self.application,
            self.chain_id,
            msg_to_sign,
            &nonce,
        );
        let sig = self.key.sign(full_message.as_bytes());
        Ok(SignedMessage {
            pub_key: AptosPublicKey::ed25519(&self.key.verifying_key().to_bytes()),
            signature: AptosSignature::ed25519(&sig.to_bytes()),
            full_message,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn full_message_layout() {
        let m = build_aptos_wallet_full_message(&AccountAddress::ONE, "ace-cli", 118, "0xab", "42");
        let want = format!(
            "APTOS\naddress: {}\napplication: ace-cli\nchainId: 118\nmessage: 0xab\nnonce: 42",
            AccountAddress::ONE
        );
        assert_eq!(m, want);
    }

    #[tokio::test]
    async fn ed25519_signer_verifies() {
        use ed25519_dalek::Verifier as _;
        let s = Ed25519Signer::new(&[7u8; 32], "app", 1);
        let out = s.sign("hello").await.unwrap();
        let vk = ed25519_dalek::VerifyingKey::from_bytes(&s.public_key_bytes()).unwrap();
        let sig_bytes: [u8; 64] = out.signature.bcs[1..].try_into().unwrap();
        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
        assert!(vk.verify(out.full_message.as_bytes(), &sig).is_ok());
        assert!(out.full_message.contains("message: hello"));
        assert_eq!(out.pub_key.bcs.len(), 33);
    }
}
