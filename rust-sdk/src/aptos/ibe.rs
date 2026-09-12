// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Aptos IBE flows (TS: `ibe-for-aptos/{encrypt,basic-decryption-session,decrypt-basic-flow,
//! decrypt-custom-flow}.ts`).
//!
//! The IBE identity is always `FullDecryptionDomain { keypair_id, ContractID::Aptos { chain_id,
//! module_addr, module_name }, label }.to_bytes()` (see [`identity`]).
//!
//! Not ported: the WebAuthn (passkey / secp256r1) variants of `BasicDecryptionSession`
//! (`decryptWithWebAuthnProof`, `fetchIdentityKeySharesWithWebAuthnProof`, ...). Requires the
//! `aptos` feature.

use crate::address::AccountAddress;
use crate::aptos::common::{
    AptosPublicKey, AptosSignature, ContractID, CustomFlowProof, CustomFlowRequest,
    DecryptionRequestPayload, FullDecryptionDomain, ProofOfPermission,
};
use crate::aptos::deployment::AceDeployment;
use crate::aptos::flows::{
    build_per_node_request_core, decrypt_with_identity_key_shares, fetch_identity_key_shares_core,
    fetch_identity_key_shares_core_custom, fetch_network_state,
    fetch_network_state_and_build_request, fetch_tibe_public_key, BuildPerNodeRequestCoreArgs,
    FetchIdentityKeySharesCoreArgs, FetchIdentityKeySharesCoreCustomArgs, PerNodeRequest,
};
use crate::aptos::signer::MessageSigner;
use crate::error::{AceError, Result};
use crate::network::State as NetworkState;
use crate::pke;
use crate::t_ibe as tibe;
use crate::wire::Wire;

/// The `{aceDeployment, keypairId, chainId, moduleAddr, moduleName}` argument bundle every TS
/// entry point in this module takes.
#[derive(Clone, Copy, Debug)]
pub struct Target<'a> {
    pub ace_deployment: &'a AceDeployment,
    pub keypair_id: AccountAddress,
    pub chain_id: u8,
    pub module_addr: AccountAddress,
    pub module_name: &'a str,
}

impl<'a> Target<'a> {
    pub fn contract_id(&self) -> ContractID {
        ContractID::new_aptos(self.chain_id, self.module_addr, self.module_name)
    }

    /// `new FullDecryptionDomain({keypairId, contractId, label})`.
    pub fn full_decryption_domain(&self, label: &[u8]) -> FullDecryptionDomain {
        FullDecryptionDomain::new(self.keypair_id, self.contract_id(), label)
    }
}

/// The IBE identity used by every Aptos flow: `fdd.toBytes()`.
pub fn identity(target: &Target<'_>, label: &[u8]) -> Vec<u8> {
    target.full_decryption_domain(label).to_bytes()
}

// ── encrypt.ts ───────────────────────────────────────────────────────────────────────────────

/// TS `fetchPk`.
pub async fn fetch_pk(
    ace_deployment: &AceDeployment,
    keypair_id: AccountAddress,
    tibe_scheme: Option<u8>,
) -> Result<tibe::MasterPublicKey> {
    fetch_tibe_public_key(
        ace_deployment,
        &keypair_id,
        tibe_scheme,
        "AptosEncrypt.fetchPk",
    )
    .await
}

/// Args of TS `encrypt`.
pub struct EncryptArgs<'a> {
    pub target: Target<'a>,
    pub label: &'a [u8],
    pub plaintext: &'a [u8],
    /// Defaults to `pk.scheme()` if `pk` is given, else shortsig-aead.
    pub tibe_scheme: Option<u8>,
    /// Skip the on-chain fetch when the caller already holds the master public key.
    pub pk: Option<&'a tibe::MasterPublicKey>,
}

/// TS `encrypt`: IBE-encrypt `plaintext` to the identity of `(target, label)`.
pub async fn encrypt(args: EncryptArgs<'_>) -> Result<tibe::Ciphertext> {
    let effective_scheme = args
        .tibe_scheme
        .or_else(|| args.pk.map(|pk| pk.scheme()))
        .unwrap_or(tibe::SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD);
    let id = identity(&args.target, args.label);
    let fetched;
    let mpk = match args.pk {
        Some(pk) => pk,
        None => {
            fetched = fetch_pk(
                args.target.ace_deployment,
                args.target.keypair_id,
                Some(effective_scheme),
            )
            .await
            .map_err(|e| AceError::Other(format!("AptosEncrypt: fetchPk failed: {e}")))?;
            &fetched
        }
    };
    if mpk.scheme() != effective_scheme {
        return Err(AceError::crypto(format!(
            "AptosEncrypt: pk.scheme {} does not match tibeScheme={effective_scheme}",
            mpk.scheme()
        )));
    }
    tibe::encrypt(mpk, &id, args.plaintext)
        .map_err(|e| AceError::crypto(format!("AptosEncrypt: tibe.encrypt failed: {e}")))
}

// ── basic-decryption-session.ts ──────────────────────────────────────────────────────────────

/// Args of TS `BasicDecryptionSession.create`.
pub struct CreateArgs<'a> {
    pub target: Target<'a>,
    pub label: &'a [u8],
    /// Required by `decrypt_with_proof`; optional for the share-only methods.
    pub ciphertext: Option<&'a [u8]>,
    /// TS `primitive`: the worker primitive byte. Defaults to the ciphertext's scheme (or
    /// shortsig-aead when there is no ciphertext). Streams pass
    /// `PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEADSTREAM`.
    pub primitive: Option<u8>,
}

/// TS `BasicDecryptionSession`: an ephemeral PKE keypair + the request the wallet signs.
///
/// Lifecycle: [`create`](Self::create) → [`get_request_to_sign`](Self::get_request_to_sign)
/// (fetches network state, builds the payload) → sign it → `decrypt_with_proof` /
/// `fetch_identity_key_shares_with_proof` / `build_per_node_request`.
pub struct BasicDecryptionSession {
    pub ace_deployment: AceDeployment,
    pub full_decryption_domain: FullDecryptionDomain,
    pub ciphertext: Option<Vec<u8>>,
    pub primitive: Option<u8>,
    pub ephemeral_decryption_key: pke::DecryptionKey,
    pub ephemeral_encryption_key: pke::EncryptionKey,
    pub request: Option<DecryptionRequestPayload>,
    pub network_state: Option<NetworkState>,
}

impl BasicDecryptionSession {
    /// TS `BasicDecryptionSession.create`: generates the ephemeral PKE keypair (no network).
    pub async fn create(args: CreateArgs<'_>) -> Result<Self> {
        let ephemeral_decryption_key = pke::keygen(pke::DEFAULT_SCHEME)?;
        let ephemeral_encryption_key = pke::derive_encryption_key(&ephemeral_decryption_key);
        Ok(Self {
            ace_deployment: args.target.ace_deployment.clone(),
            full_decryption_domain: args.target.full_decryption_domain(args.label),
            ciphertext: args.ciphertext.map(|c| c.to_vec()),
            primitive: args.primitive,
            ephemeral_decryption_key,
            ephemeral_encryption_key,
            request: None,
            network_state: None,
        })
    }

    /// TS `getRequestToSign`: fetch network state, build and cache the request payload, return
    /// `'0x' + hex(request.toBytes())` — the string handed to the wallet.
    pub async fn get_request_to_sign(&mut self) -> Result<String> {
        let nsr = fetch_network_state_and_build_request(
            &self.ace_deployment,
            &self.full_decryption_domain,
            &self.ephemeral_encryption_key,
        )
        .await?;
        self.network_state = Some(nsr.network_state);
        let s = Self::format_request_to_sign(&nsr.request);
        self.request = Some(nsr.request);
        Ok(s)
    }

    /// Pure formatting half of [`get_request_to_sign`](Self::get_request_to_sign).
    pub fn format_request_to_sign(request: &DecryptionRequestPayload) -> String {
        format!("0x{}", request.to_hex())
    }

    fn get_ciphertext(&self, context: &str) -> Result<&[u8]> {
        self.ciphertext
            .as_deref()
            .ok_or_else(|| AceError::Other(format!("{context}: ciphertext is required")))
    }

    /// TS `getPrimitive`: explicit `primitive`, else the ciphertext scheme, else shortsig-aead.
    pub fn get_primitive(&self) -> Result<u8> {
        if let Some(p) = self.primitive {
            return Ok(p);
        }
        match &self.ciphertext {
            None => Ok(tibe::SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD),
            Some(ct) => Ok(tibe::Ciphertext::from_bytes(ct)?.scheme()),
        }
    }

    fn state(&self, context: &str) -> Result<(&NetworkState, &DecryptionRequestPayload)> {
        match (&self.network_state, &self.request) {
            (Some(ns), Some(req)) => Ok((ns, req)),
            _ => Err(AceError::Other(format!(
                "{context}: call get_request_to_sign() first"
            ))),
        }
    }

    /// TS `decryptWithProof`.
    pub async fn decrypt_with_proof(
        &self,
        user_addr: AccountAddress,
        public_key: AptosPublicKey,
        signature: AptosSignature,
        full_message: &str,
    ) -> Result<Vec<u8>> {
        let ciphertext =
            self.get_ciphertext("ACE.IBE_Aptos.BasicDecryptionSession.decryptWithProof")?;
        let shares = self
            .fetch_identity_key_shares_with_proof(user_addr, public_key, signature, full_message)
            .await?;
        decrypt_with_identity_key_shares(ciphertext, &shares)
    }

    /// TS `fetchIdentityKeySharesWithProof`.
    pub async fn fetch_identity_key_shares_with_proof(
        &self,
        user_addr: AccountAddress,
        public_key: AptosPublicKey,
        signature: AptosSignature,
        full_message: &str,
    ) -> Result<Vec<tibe::IdentityDecryptionKeyShare>> {
        let primitive = self.get_primitive()?;
        let (network_state, request) =
            self.state("ACE.IBE_Aptos.BasicDecryptionSession.fetchIdentityKeySharesWithProof")?;
        let proof = ProofOfPermission::create_aptos(user_addr, public_key, signature, full_message);
        fetch_identity_key_shares_core(FetchIdentityKeySharesCoreArgs {
            ace_deployment: &self.ace_deployment,
            network_state,
            request,
            proof: &proof,
            ephemeral_decryption_key: &self.ephemeral_decryption_key,
            primitive,
        })
        .await
    }

    /// TS `buildPerNodeRequest`: the encrypted worker request for the single node at
    /// `target_endpoint`; the caller POSTs it.
    pub async fn build_per_node_request(
        &self,
        user_addr: AccountAddress,
        public_key: AptosPublicKey,
        signature: AptosSignature,
        full_message: &str,
        target_endpoint: &str,
    ) -> Result<PerNodeRequest> {
        let primitive = self.get_primitive()?;
        let (network_state, request) =
            self.state("ACE.IBE_Aptos.BasicDecryptionSession.buildPerNodeRequest")?;
        let proof = ProofOfPermission::create_aptos(user_addr, public_key, signature, full_message);
        build_per_node_request_core(BuildPerNodeRequestCoreArgs {
            ace_deployment: &self.ace_deployment,
            network_state,
            request,
            proof: &proof,
            primitive,
            target_endpoint,
        })
        .await
    }
}

// ── decrypt-basic-flow.ts ────────────────────────────────────────────────────────────────────

/// Args of TS `decryptBasicFlow`. `signer` replaces TS `{accountAddress, sign}`.
pub struct DecryptBasicFlowArgs<'a> {
    pub target: Target<'a>,
    pub label: &'a [u8],
    pub ciphertext: &'a [u8],
    pub signer: &'a dyn MessageSigner,
}

/// TS `decryptBasicFlow`: create session → sign request → fetch shares → decrypt.
pub async fn decrypt_basic_flow(args: DecryptBasicFlowArgs<'_>) -> Result<Vec<u8>> {
    let mut session = BasicDecryptionSession::create(CreateArgs {
        target: args.target,
        label: args.label,
        ciphertext: Some(args.ciphertext),
        primitive: None,
    })
    .await?;
    let message = session.get_request_to_sign().await?;
    let signed = args.signer.sign(&message).await?;
    session
        .decrypt_with_proof(
            args.signer.account_address(),
            signed.pub_key,
            signed.signature,
            &signed.full_message,
        )
        .await
}

// ── decrypt-custom-flow.ts ───────────────────────────────────────────────────────────────────

/// Args of TS `fetchIdentityKeySharesCustomFlow` / `decryptCustomFlow` (minus `ciphertext`).
/// `enc_pk`/`enc_sk` are the wire bytes of the caller's `pke::{EncryptionKey, DecryptionKey}`;
/// `payload` is the contract-defined custom-flow proof (`CustomFlowProof::create_aptos`).
pub struct CustomFlowArgs<'a> {
    pub target: Target<'a>,
    pub label: &'a [u8],
    pub enc_pk: &'a [u8],
    pub enc_sk: &'a [u8],
    pub payload: &'a [u8],
    /// Worker primitive byte; defaults to shortsig-aead.
    pub tibe_scheme: Option<u8>,
}

/// TS `fetchIdentityKeySharesCustomFlow`.
pub async fn fetch_identity_key_shares_custom_flow(
    args: CustomFlowArgs<'_>,
) -> Result<Vec<tibe::IdentityDecryptionKeyShare>> {
    let caller_enc_pk = pke::EncryptionKey::from_bytes(args.enc_pk).map_err(|e| {
        AceError::wire(format!(
            "AptosCustomFlow.fetchIdentityKeyShares: parse encPk: {e}"
        ))
    })?;
    let caller_dec_sk = pke::DecryptionKey::from_bytes(args.enc_sk).map_err(|e| {
        AceError::wire(format!(
            "AptosCustomFlow.fetchIdentityKeyShares: parse encSk: {e}"
        ))
    })?;
    let network_state = fetch_network_state(args.target.ace_deployment).await?;
    let custom_request = CustomFlowRequest {
        keypair_id: args.target.keypair_id,
        epoch: network_state.epoch,
        contract_id: args.target.contract_id(),
        label: args.label.to_vec(),
        enc_pk: caller_enc_pk,
        proof: CustomFlowProof::create_aptos(args.payload),
    };
    fetch_identity_key_shares_core_custom(FetchIdentityKeySharesCoreCustomArgs {
        ace_deployment: args.target.ace_deployment,
        network_state: &network_state,
        custom_request: &custom_request,
        caller_decryption_key: &caller_dec_sk,
        primitive: args
            .tibe_scheme
            .unwrap_or(tibe::SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD),
    })
    .await
}

/// TS `decryptCustomFlow`: the primitive is taken from the ciphertext scheme (any explicit
/// `args.tibe_scheme` is ignored, as in TS).
pub async fn decrypt_custom_flow(args: CustomFlowArgs<'_>, ciphertext: &[u8]) -> Result<Vec<u8>> {
    let tibe_scheme = tibe::Ciphertext::from_bytes(ciphertext)
        .map_err(|e| AceError::wire(format!("AptosCustomFlow.decrypt failed: {e}")))?
        .scheme();
    let shares = fetch_identity_key_shares_custom_flow(CustomFlowArgs {
        tibe_scheme: Some(tibe_scheme),
        ..args
    })
    .await
    .map_err(|e| AceError::Other(format!("AptosCustomFlow.decrypt failed: {e}")))?;
    decrypt_with_identity_key_shares(ciphertext, &shares)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::t_ibe::{derive_public_key, extract, keygen_for_testing};

    fn deployment() -> AceDeployment {
        AceDeployment::new("http://localhost:0", AccountAddress([0xAA; 32]))
    }

    fn target(dep: &AceDeployment) -> Target<'_> {
        Target {
            ace_deployment: dep,
            keypair_id: AccountAddress([0x11; 32]),
            chain_id: 4,
            module_addr: AccountAddress([0x22; 32]),
            module_name: "my_module",
        }
    }

    #[test]
    fn identity_is_bcs_of_full_decryption_domain() {
        let dep = deployment();
        let t = target(&dep);
        let label = b"hello".as_slice();
        let fdd = FullDecryptionDomain::new(
            AccountAddress([0x11; 32]),
            ContractID::new_aptos(4, AccountAddress([0x22; 32]), "my_module"),
            label,
        );
        assert_eq!(identity(&t, label), fdd.to_bytes());
        assert_eq!(t.full_decryption_domain(label), fdd);
    }

    #[test]
    fn request_to_sign_is_0x_prefixed_hex_of_payload() {
        let dk = pke::keygen(pke::DEFAULT_SCHEME).unwrap();
        let request = DecryptionRequestPayload {
            keypair_id: AccountAddress([0x11; 32]),
            epoch: 7,
            contract_id: ContractID::new_aptos(4, AccountAddress([0x22; 32]), "m"),
            domain: b"lbl".to_vec(),
            ephemeral_enc_key: pke::derive_encryption_key(&dk),
        };
        let s = BasicDecryptionSession::format_request_to_sign(&request);
        assert!(s.starts_with("0x"));
        assert_eq!(&s[2..], hex::encode(request.to_bytes()));
        assert_eq!(
            DecryptionRequestPayload::from_hex(&s[2..]).unwrap(),
            request
        );
    }

    #[tokio::test]
    async fn encrypt_with_provided_pk_round_trips_locally() {
        let dep = deployment();
        let t = target(&dep);
        let label = b"round-trip";
        let msk = keygen_for_testing(tibe::SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD).unwrap();
        let mpk = derive_public_key(&msk);
        let ct = encrypt(EncryptArgs {
            target: t,
            label,
            plaintext: b"secret payload",
            tibe_scheme: None,
            pk: Some(&mpk),
        })
        .await
        .unwrap();
        assert_eq!(ct.scheme(), tibe::SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD);
        let scalar = &msk.as_shortsig_aead().unwrap().scalar;
        let share = extract(
            tibe::SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD,
            scalar,
            &identity(&t, label),
        )
        .unwrap();
        let pt = decrypt_with_identity_key_shares(&ct.to_bytes(), &[share]).unwrap();
        assert_eq!(pt, b"secret payload");
    }

    #[tokio::test]
    async fn encrypt_rejects_scheme_mismatch_and_session_defaults() {
        let dep = deployment();
        let t = target(&dep);
        let msk = keygen_for_testing(tibe::SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD).unwrap();
        let mpk = derive_public_key(&msk);
        let err = encrypt(EncryptArgs {
            target: t,
            label: b"x",
            plaintext: b"y",
            tibe_scheme: Some(tibe::SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC),
            pk: Some(&mpk),
        })
        .await;
        assert!(err.is_err());

        let s = BasicDecryptionSession::create(CreateArgs {
            target: t,
            label: b"x",
            ciphertext: None,
            primitive: None,
        })
        .await
        .unwrap();
        assert_eq!(
            s.get_primitive().unwrap(),
            tibe::SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
        );
        assert!(s
            .decrypt_with_proof(
                AccountAddress([0; 32]),
                AptosPublicKey::ed25519(&[0; 32]),
                AptosSignature::ed25519(&[0; 64]),
                "m"
            )
            .await
            .is_err());
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::aptos::known_deployment;
    use crate::wire::Wire;

    /// Fetches the real shelbynet master public key (discovery path and fullnode path) and
    /// encrypts under it. Run with `cargo test -- --ignored`.
    #[tokio::test]
    #[ignore]
    async fn shelbynet_fetch_pk_and_encrypt() {
        let dep = known_deployment("shelbynet-20260731").unwrap();
        let pk_disc = fetch_pk(&dep.ace_deployment, dep.ibe_keypair_id, None)
            .await
            .unwrap();
        let full = dep.ace_deployment.clone().with_discovery_url(None);
        let pk_full = fetch_pk(&full, dep.ibe_keypair_id, None).await.unwrap();
        assert_eq!(pk_disc, pk_full);
        assert_eq!(
            pk_disc.scheme(),
            crate::t_ibe::SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD
        );
        let target = Target {
            ace_deployment: &dep.ace_deployment,
            keypair_id: dep.ibe_keypair_id,
            chain_id: dep.chain_id,
            module_addr: AccountAddress::from_str_relaxed(
                "0x10d3efec2ff80d77600bb0b61a05c12411759a3831c4d848d21af47e43de5cb0",
            )
            .unwrap(),
            module_name: "presigned_access",
        };
        let ct = encrypt(EncryptArgs {
            target,
            label: b"rust-sdk/live-test",
            plaintext: b"hello from rust",
            tibe_scheme: None,
            pk: None,
        })
        .await
        .unwrap();
        assert_eq!(ct.scheme(), 1);
        assert!(ct.to_bytes().len() > 96);
    }
}
