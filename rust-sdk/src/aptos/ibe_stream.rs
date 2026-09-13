// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Aptos streaming IBE flows (TS: `ibe-for-aptos-stream/{encrypt,decrypt}.ts`).
//!
//! Identity: the same `FullDecryptionDomain.to_bytes()` as the non-stream flow
//! ([`ibe::identity`]). Scheme/primitive handling mirrors TS exactly:
//! * `fetch_pk` fetches the keypair as a **scheme-1** (shortsig-aead) `MasterPublicKey` — the
//!   stream KEM reuses the scheme-1 key; the untagged inner key is what the stream module wants.
//! * Share requests are sent to workers with primitive **3**
//!   (`PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEADSTREAM`); the shares come back as scheme-1
//!   `IdentityDecryptionKeyShare`s and feed the stream decryptor directly.
//!
//! Requires the `aptos` feature.

use crate::address::AccountAddress;
use crate::aptos::deployment::AceDeployment;
use crate::aptos::flows::fetch_tibe_public_key;
use crate::aptos::ibe::{
    self, fetch_identity_key_shares_custom_flow, BasicDecryptionSession, CreateArgs,
    CustomFlowArgs, Target,
};
use crate::aptos::signer::MessageSigner;
use crate::error::{AceError, Result};
use crate::network::PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEADSTREAM;
use crate::t_ibe as tibe;
use crate::t_ibe::bfibe_bls12381_shortsig_aead_stream as stream;

pub use crate::t_ibe::bfibe_bls12381_shortsig_aead_stream::{
    DecryptChunks, EncryptChunks, SeekableDecryptor, DEFAULT_CHUNK_SIZE,
};

// ── encrypt.ts ───────────────────────────────────────────────────────────────────────────────

/// TS `fetchPk`: always fetches as `SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD` (1).
pub async fn fetch_pk(
    ace_deployment: &AceDeployment,
    keypair_id: AccountAddress,
) -> Result<tibe::MasterPublicKey> {
    fetch_tibe_public_key(
        ace_deployment,
        &keypair_id,
        Some(tibe::SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD),
        "StreamIBE_Aptos.fetchPk",
    )
    .await
}

/// Args of TS `encryptStream` (minus the `plaintext` chunk iterator).
pub struct EncryptStreamArgs<'a> {
    pub target: Target<'a>,
    pub label: &'a [u8],
    /// Skip the on-chain fetch when the caller already holds the (tagged, scheme-1) key.
    pub pk: Option<&'a tibe::MasterPublicKey>,
    /// Optional KEM randomness (TS `randomness`); fresh if `None`.
    pub randomness: Option<&'a [u8]>,
    /// Segment size; `None` = [`DEFAULT_CHUNK_SIZE`] (TS default).
    pub chunk_size: Option<usize>,
}

/// TS `encryptStream`: returns a lazy iterator of ciphertext chunks (header first, then one
/// AEAD segment per `chunk_size` plaintext bytes; input chunk boundaries are irrelevant).
pub async fn encrypt_stream<I: Iterator<Item = Vec<u8>>>(
    args: EncryptStreamArgs<'_>,
    plaintext: I,
) -> Result<EncryptChunks<I>> {
    let fetched;
    let mpk = match args.pk {
        Some(pk) => pk,
        None => {
            fetched = fetch_pk(args.target.ace_deployment, args.target.keypair_id)
                .await
                .map_err(|e| {
                    AceError::Other(format!(
                        "StreamIBE_Aptos.encryptStream: fetchPk failed: {e}"
                    ))
                })?;
            &fetched
        }
    };
    let inner = mpk.as_shortsig_aead()?;
    let id = ibe::identity(&args.target, args.label);
    stream::encrypt_chunks(
        inner,
        &id,
        args.randomness,
        args.chunk_size.unwrap_or(DEFAULT_CHUNK_SIZE),
        plaintext,
    )
}

// ── decrypt.ts ───────────────────────────────────────────────────────────────────────────────

/// TS `StreamDecryptor`: holds the identity key shares from one network round-trip and
/// decrypts any number of streams under the same identity.
pub struct StreamDecryptor {
    /// Tagged shares as returned by the workers (scheme 1).
    pub idk_shares: Vec<tibe::IdentityDecryptionKeyShare>,
    /// The same shares, untagged, as the stream DEM module consumes them.
    inner: Vec<crate::t_ibe::bfibe_bls12381_shortsig_aead::IdentityDecryptionKeyShare>,
}

impl StreamDecryptor {
    /// Fails if any share is not a shortsig-aead (scheme 1) share.
    pub fn new(idk_shares: Vec<tibe::IdentityDecryptionKeyShare>) -> Result<Self> {
        let inner = idk_shares
            .iter()
            .map(|s| s.as_shortsig_aead().cloned())
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { idk_shares, inner })
    }

    /// TS `decryptStream` (default chunk size).
    pub fn decrypt_stream<I: Iterator<Item = Vec<u8>>>(
        &self,
        chunks: I,
    ) -> Result<DecryptChunks<'_, I>> {
        stream::decrypt_chunks_default(&self.inner, chunks)
    }

    /// `decrypt_stream` with an explicit segment size.
    pub fn decrypt_stream_with_chunk_size<I: Iterator<Item = Vec<u8>>>(
        &self,
        chunk_size: usize,
        chunks: I,
    ) -> Result<DecryptChunks<'_, I>> {
        stream::decrypt_chunks(&self.inner, chunk_size, chunks)
    }

    /// TS `createSeekableDecryptor`: `byte_length` is the total ciphertext length and `header`
    /// at least its first `HEADER_BYTES` bytes (TS reads these from `CiphertextSource`).
    pub fn create_seekable_decryptor(
        &self,
        byte_length: u64,
        header: &[u8],
    ) -> Result<SeekableDecryptor> {
        SeekableDecryptor::open_default(&self.inner, byte_length, header)
    }
}

/// Args of TS `createStreamDecryptorBasicFlow`; `signer` replaces `{accountAddress, sign}`.
pub struct StreamBasicFlowArgs<'a> {
    pub target: Target<'a>,
    pub label: &'a [u8],
    pub signer: &'a dyn MessageSigner,
}

/// TS `createStreamDecryptorBasicFlow`: session with primitive 3 → sign → fetch shares once.
pub async fn create_stream_decryptor_basic_flow(
    args: StreamBasicFlowArgs<'_>,
) -> Result<StreamDecryptor> {
    let mut session = BasicDecryptionSession::create(CreateArgs {
        target: args.target,
        label: args.label,
        ciphertext: None,
        primitive: Some(PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEADSTREAM),
    })
    .await?;
    let message = session.get_request_to_sign().await?;
    let signed = args.signer.sign(&message).await?;
    let idk_shares = session
        .fetch_identity_key_shares_with_proof(
            args.signer.account_address(),
            signed.pub_key,
            signed.signature,
            &signed.full_message,
        )
        .await
        .map_err(|e| {
            AceError::Other(format!(
                "StreamIBE_Aptos.basicFlow: fetchIdentityKeyShares failed: {e}"
            ))
        })?;
    StreamDecryptor::new(idk_shares)
}

/// TS `createStreamDecryptorCustomFlow`: custom flow with primitive 3 (`args.tibe_scheme` is
/// overridden).
pub async fn create_stream_decryptor_custom_flow(
    args: CustomFlowArgs<'_>,
) -> Result<StreamDecryptor> {
    let idk_shares = fetch_identity_key_shares_custom_flow(CustomFlowArgs {
        tibe_scheme: Some(PRIMITIVE_BFIBE_BLS12381_SHORTSIG_AEADSTREAM),
        ..args
    })
    .await
    .map_err(|e| {
        AceError::Other(format!(
            "StreamIBE_Aptos.customFlow: fetchIdentityKeyShares failed: {e}"
        ))
    })?;
    StreamDecryptor::new(idk_shares)
}
