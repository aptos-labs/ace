// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Network flows against the ACE committee (TS: `_internal/common.ts` lines 609-1003):
//! fetch network state / t-IBE public key / session PKs, build the per-node encrypted
//! `WorkerRequest`, fan out to every current node, verify each returned IDK share and
//! threshold-decrypt. Requires the `aptos` feature.
//!
//! Worker HTTP protocol (mirrors the TS `fetch` call exactly):
//!   `POST <worker_endpoint>` (no extra path, no headers), body = lower-case hex of the
//!   PKE ciphertext of the BCS `WorkerRequest`, encrypted to the worker's registered enc key.
//!   Response body = hex of a PKE ciphertext (encrypted to the request's ephemeral enc key)
//!   whose plaintext is the BCS bytes of a tagged `tibe::IdentityDecryptionKeyShare`.

use std::time::Duration;

use futures::future::join_all;

use crate::address::AccountAddress;
use crate::aptos::client::{chain_reader, ChainReader};
use crate::aptos::common::{
    CustomFlowRequest, DecryptionRequestPayload, FullDecryptionDomain, ProofOfPermission,
    WorkerRequest,
};
use crate::aptos::deployment::AceDeployment;
use crate::error::{AceError, Result};
use crate::group::Element;
use crate::network::State as NetworkState;
use crate::pke;
use crate::t_ibe as tibe;
use crate::wire::Wire;

/// Per-worker request timeout (TS: `setTimeout(() => ctrl.abort(), 8000)`).
pub const WORKER_REQUEST_TIMEOUT: Duration = Duration::from_secs(8);

/// `basePoint` + per-holder `sharePks` of the most recent DKG/DKR session (TS returns an
/// anonymous `{basePoint, sharePks}` object).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct CurrentSessionPks {
    pub base_point: Element,
    pub share_pks: Vec<Element>,
}

/// Return of [`fetch_network_state_and_build_request`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NetworkStateAndRequest {
    pub network_state: NetworkState,
    pub request: DecryptionRequestPayload,
}

/// Return of [`build_per_node_request_core`].
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PerNodeRequest {
    /// Hex the client POSTs to the target worker endpoint.
    pub enc_req_hex: String,
    pub epoch: u64,
    /// Position of the target node in `network_state.cur_nodes` (0-based).
    pub sdk_idx: usize,
}

/// `(endpoint, enc_key)` of one committee member, as registered on chain.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NodeInfo {
    pub endpoint: String,
    pub node_enc_key: pke::EncryptionKey,
}

// ── Simple reads ─────────────────────────────────────────────────────────────────────────

/// TS `fetchNetworkState`.
pub async fn fetch_network_state(ace_deployment: &AceDeployment) -> Result<NetworkState> {
    chain_reader(ace_deployment).network_state().await
}

/// TS `fetchTibePublicKey`. `tibe_scheme` defaults to shortsig-aead. The `keypair_id` is always
/// the origin DKG session, so `session(keypair_id, is_dkg = true)` gives `basePoint`/`resultPk`.
/// `context` prefixes error messages like the TS `context` argument.
pub async fn fetch_tibe_public_key(
    ace_deployment: &AceDeployment,
    keypair_id: &AccountAddress,
    tibe_scheme: Option<u8>,
    context: &str,
) -> Result<tibe::MasterPublicKey> {
    let tibe_scheme = tibe_scheme.unwrap_or(tibe::SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD);
    let pks = chain_reader(ace_deployment)
        .session(keypair_id, true)
        .await?;
    let result_pk = pks.result_pk.as_ref().ok_or_else(|| {
        AceError::Chain(format!(
            "{context}: DKG session has no resultPk (not yet finalized)"
        ))
    })?;
    tibe::MasterPublicKey::from_group_elements(tibe_scheme, &pks.base_point, result_pk).map_err(
        |e| {
            AceError::crypto(format!(
                "{context}: keypairId {} is incompatible with tibeScheme={tibe_scheme}: {e}",
                keypair_id.to_string_long()
            ))
        },
    )
}

/// TS `fetchNetworkStateAndBuildRequest`.
pub async fn fetch_network_state_and_build_request(
    ace_deployment: &AceDeployment,
    full_decryption_domain: &FullDecryptionDomain,
    ephemeral_encryption_key: &pke::EncryptionKey,
) -> Result<NetworkStateAndRequest> {
    let network_state = chain_reader(ace_deployment).network_state().await?;
    let request = DecryptionRequestPayload {
        keypair_id: full_decryption_domain.keypair_id,
        epoch: network_state.epoch,
        contract_id: full_decryption_domain.contract_id.clone(),
        domain: full_decryption_domain.label.clone(),
        ephemeral_enc_key: ephemeral_encryption_key.clone(),
    };
    Ok(NetworkStateAndRequest {
        network_state,
        request,
    })
}

/// TS `fetchCurrentSessionPks`: `basePoint` and per-holder share PKs of the most recent
/// DKG/DKR session for `keypair_id`. `current_session == keypair_id` means the initial DKG.
pub async fn fetch_current_session_pks(
    ace_deployment: &AceDeployment,
    network_state: &NetworkState,
    keypair_id: &AccountAddress,
) -> Result<CurrentSessionPks> {
    fetch_current_session_pks_with(
        chain_reader(ace_deployment).as_ref(),
        network_state,
        keypair_id,
    )
    .await
}

async fn fetch_current_session_pks_with(
    reader: &dyn ChainReader,
    network_state: &NetworkState,
    keypair_id: &AccountAddress,
) -> Result<CurrentSessionPks> {
    let secret = network_state.secret(keypair_id).ok_or_else(|| {
        AceError::Chain(format!(
            "ACE: keypairId {} not found in network state secrets",
            keypair_id.to_string_long()
        ))
    })?;
    let is_initial_dkg = secret.current_session == *keypair_id;
    let pks = reader
        .session(&secret.current_session, is_initial_dkg)
        .await?;
    Ok(CurrentSessionPks {
        base_point: pks.base_point,
        share_pks: pks.share_pks,
    })
}

// ── Pure helpers ─────────────────────────────────────────────────────────────────────────

/// BCS-encode `req` and PKE-encrypt it to `node_enc_key`; returns the lower-case hex a client
/// POSTs to the worker (the sync core of TS `buildPerNodeRequestCore` / the fan-out loops).
pub fn encrypt_worker_request(
    req: &WorkerRequest,
    node_enc_key: &pke::EncryptionKey,
) -> Result<String> {
    Ok(pke::encrypt(node_enc_key, &req.to_bytes())?.to_hex())
}

/// Decode a worker's hex response, decrypt it with the ephemeral/caller PKE decryption key and
/// parse the tagged IDK share. Each failure maps to the corresponding TS log line.
pub fn parse_worker_response(
    hex_text: &str,
    decryption_key: &pke::DecryptionKey,
) -> Result<tibe::IdentityDecryptionKeyShare> {
    let resp_ct = pke::Ciphertext::from_hex(hex_text.trim())
        .map_err(|e| AceError::crypto(format!("response ciphertext parse failed: {e}")))?;
    let share_bytes = pke::decrypt(decryption_key, &resp_ct)
        .map_err(|e| AceError::crypto(format!("response decryption failed: {e}")))?;
    tibe::IdentityDecryptionKeyShare::from_bytes(&share_bytes)
        .map_err(|e| AceError::crypto(format!("share parse failed: {e}")))
}

fn share_eval_point(share: &tibe::IdentityDecryptionKeyShare) -> u64 {
    match share {
        tibe::IdentityDecryptionKeyShare::ShortPkOtpHmac(s) => s.eval_point,
        tibe::IdentityDecryptionKeyShare::ShortSigAead(s) => s.eval_point,
    }
}

/// TS `verifyIdkShare`: the embedded `eval_point` must be `sdk_idx + 1` and the pairing
/// equation `e(g, idkShare) == e(share_pks[sdk_idx], H(id))` must hold. Returns `false`
/// (never errors) so the caller can drop the share, exactly like TS.
fn verify_idk_share(
    share: &tibe::IdentityDecryptionKeyShare,
    sdk_idx: usize,
    session_pks: &CurrentSessionPks,
    id: &[u8],
) -> bool {
    let expected_eval = sdk_idx as u64 + 1;
    if share_eval_point(share) != expected_eval {
        return false;
    }
    let Some(share_pk) = session_pks.share_pks.get(sdk_idx) else {
        return false;
    };
    tibe::verify_share(&session_pks.base_point, share_pk, id, share).unwrap_or(false)
}

/// TS `decryptWithIdentityKeyShares`.
pub fn decrypt_with_identity_key_shares(
    ciphertext: &[u8],
    identity_key_shares: &[tibe::IdentityDecryptionKeyShare],
) -> Result<Vec<u8>> {
    let ct = tibe::Ciphertext::from_bytes(ciphertext).map_err(|e| {
        AceError::crypto(format!(
            "ACE.decryptWithIdentityKeyShares: parse ciphertext: {e}"
        ))
    })?;
    tibe::decrypt(identity_key_shares, &ct).map_err(|e| {
        AceError::crypto(format!(
            "ACE.decryptWithIdentityKeyShares: tibe.decrypt failed: {e}"
        ))
    })
}

// ── Committee lookup + fan-out ───────────────────────────────────────────────────────────

/// `(endpoint, enc_key)` for every node in `cur_nodes`, fetched concurrently (TS inner
/// `Promise.all` in the fetchers).
async fn fetch_node_infos(
    reader: &dyn ChainReader,
    network_state: &NetworkState,
) -> Result<Vec<NodeInfo>> {
    join_all(network_state.cur_nodes.iter().map(|addr| async move {
        let (endpoint, node_enc_key) =
            futures::future::try_join(reader.worker_endpoint(addr), reader.worker_enc_key(addr))
                .await?;
        Ok(NodeInfo {
            endpoint,
            node_enc_key,
        })
    }))
    .await
    .into_iter()
    .collect()
}

fn http_client() -> Result<reqwest::Client> {
    reqwest::Client::builder()
        .timeout(WORKER_REQUEST_TIMEOUT)
        .build()
        .map_err(|e| AceError::Chain(format!("reqwest client: {e}")))
}

/// One worker round-trip: encrypt, POST the hex, decrypt + parse + verify. `Err` means the
/// share is dropped (TS logs and returns `null`).
async fn fetch_one_share(
    http: &reqwest::Client,
    node: &NodeInfo,
    req: &WorkerRequest,
    decryption_key: &pke::DecryptionKey,
    sdk_idx: usize,
    session_pks: &CurrentSessionPks,
    id: &[u8],
) -> Result<tibe::IdentityDecryptionKeyShare> {
    let enc_req_hex = encrypt_worker_request(req, &node.node_enc_key)?;
    let resp = http
        .post(&node.endpoint)
        .body(enc_req_hex)
        .send()
        .await
        .map_err(|e| AceError::Chain(format!("fetch error: {e}")))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(AceError::Http {
            status: status.as_u16(),
            body: body.trim().chars().take(120).collect(),
        });
    }
    let share = parse_worker_response(&body, decryption_key)?;
    if !verify_idk_share(&share, sdk_idx, session_pks, id) {
        return Err(AceError::Verify(
            "share failed eval_point / pairing verification".into(),
        ));
    }
    Ok(share)
}

/// Shared body of TS `fetchIdentityKeySharesCore` / `fetchIdentityKeySharesCoreCustom`.
async fn fetch_shares_inner(
    ace_deployment: &AceDeployment,
    network_state: &NetworkState,
    keypair_id: &AccountAddress,
    fdd: &FullDecryptionDomain,
    req: &WorkerRequest,
    decryption_key: &pke::DecryptionKey,
    fn_name: &str,
) -> Result<Vec<tibe::IdentityDecryptionKeyShare>> {
    let reader = chain_reader(ace_deployment);
    let fdd_bytes = fdd.to_bytes();
    let (node_infos, session_pks) = futures::future::try_join(
        fetch_node_infos(reader.as_ref(), network_state),
        fetch_current_session_pks_with(reader.as_ref(), network_state, keypair_id),
    )
    .await?;
    if session_pks.share_pks.len() != network_state.cur_nodes.len() {
        return Err(AceError::Chain(format!(
            "ACE.{fn_name}: sharePks length {} != curNodes length {}",
            session_pks.share_pks.len(),
            network_state.cur_nodes.len()
        )));
    }
    let http = http_client()?;
    let results = join_all(node_infos.iter().enumerate().map(|(i, node)| {
        fetch_one_share(
            &http,
            node,
            req,
            decryption_key,
            i,
            &session_pks,
            &fdd_bytes,
        )
    }))
    .await;
    let shares: Vec<_> = results.into_iter().filter_map(|r| r.ok()).collect();
    let need = network_state.cur_threshold as usize;
    if shares.len() < need {
        return Err(AceError::InsufficientShares {
            need,
            got: shares.len(),
        });
    }
    Ok(shares)
}

// ── Public flows ─────────────────────────────────────────────────────────────────────────

/// Args of TS `fetchIdentityKeySharesCore` / `decryptCore` (minus `ciphertext`).
pub struct FetchIdentityKeySharesCoreArgs<'a> {
    pub ace_deployment: &'a AceDeployment,
    pub network_state: &'a NetworkState,
    pub request: &'a DecryptionRequestPayload,
    pub proof: &'a ProofOfPermission,
    pub ephemeral_decryption_key: &'a pke::DecryptionKey,
    pub primitive: u8,
}

/// TS `fetchIdentityKeySharesCore`: fan out the basic-flow request to every current node,
/// keep the shares that decrypt/parse/verify, require at least `cur_threshold` of them.
pub async fn fetch_identity_key_shares_core(
    args: FetchIdentityKeySharesCoreArgs<'_>,
) -> Result<Vec<tibe::IdentityDecryptionKeyShare>> {
    let fdd = FullDecryptionDomain::new(
        args.request.keypair_id,
        args.request.contract_id.clone(),
        &args.request.domain,
    );
    let req = WorkerRequest::new_decryption_basic_flow(
        args.request.clone(),
        args.proof.clone(),
        args.primitive,
    );
    fetch_shares_inner(
        args.ace_deployment,
        args.network_state,
        &args.request.keypair_id,
        &fdd,
        &req,
        args.ephemeral_decryption_key,
        "fetchIdentityKeySharesCore",
    )
    .await
}

/// Args of TS `decryptCore`.
pub struct DecryptCoreArgs<'a> {
    pub ace_deployment: &'a AceDeployment,
    pub network_state: &'a NetworkState,
    pub request: &'a DecryptionRequestPayload,
    pub proof: &'a ProofOfPermission,
    pub ephemeral_decryption_key: &'a pke::DecryptionKey,
    pub ciphertext: &'a [u8],
}

/// TS `decryptCore`: parse the t-IBE ciphertext (its scheme selects the primitive), fetch the
/// shares, decrypt.
pub async fn decrypt_core(args: DecryptCoreArgs<'_>) -> Result<Vec<u8>> {
    let ct = tibe::Ciphertext::from_bytes(args.ciphertext)?;
    let shares = fetch_identity_key_shares_core(FetchIdentityKeySharesCoreArgs {
        ace_deployment: args.ace_deployment,
        network_state: args.network_state,
        request: args.request,
        proof: args.proof,
        ephemeral_decryption_key: args.ephemeral_decryption_key,
        primitive: ct.scheme(),
    })
    .await?;
    decrypt_with_identity_key_shares(args.ciphertext, &shares)
}

/// Args of TS `fetchIdentityKeySharesCoreCustom`.
pub struct FetchIdentityKeySharesCoreCustomArgs<'a> {
    pub ace_deployment: &'a AceDeployment,
    pub network_state: &'a NetworkState,
    pub custom_request: &'a CustomFlowRequest,
    pub caller_decryption_key: &'a pke::DecryptionKey,
    pub primitive: u8,
}

/// TS `fetchIdentityKeySharesCoreCustom`.
pub async fn fetch_identity_key_shares_core_custom(
    args: FetchIdentityKeySharesCoreCustomArgs<'_>,
) -> Result<Vec<tibe::IdentityDecryptionKeyShare>> {
    let fdd = FullDecryptionDomain::new(
        args.custom_request.keypair_id,
        args.custom_request.contract_id.clone(),
        &args.custom_request.label,
    );
    let req =
        WorkerRequest::new_decryption_custom_flow(args.custom_request.clone(), args.primitive);
    fetch_shares_inner(
        args.ace_deployment,
        args.network_state,
        &args.custom_request.keypair_id,
        &fdd,
        &req,
        args.caller_decryption_key,
        "fetchIdentityKeySharesCoreCustom",
    )
    .await
}

/// Args of TS `decryptCoreCustom`.
pub struct DecryptCoreCustomArgs<'a> {
    pub ace_deployment: &'a AceDeployment,
    pub network_state: &'a NetworkState,
    pub custom_request: &'a CustomFlowRequest,
    pub caller_decryption_key: &'a pke::DecryptionKey,
    pub ciphertext: &'a [u8],
}

/// TS `decryptCoreCustom`.
pub async fn decrypt_core_custom(args: DecryptCoreCustomArgs<'_>) -> Result<Vec<u8>> {
    let ct = tibe::Ciphertext::from_bytes(args.ciphertext)?;
    let shares = fetch_identity_key_shares_core_custom(FetchIdentityKeySharesCoreCustomArgs {
        ace_deployment: args.ace_deployment,
        network_state: args.network_state,
        custom_request: args.custom_request,
        caller_decryption_key: args.caller_decryption_key,
        primitive: ct.scheme(),
    })
    .await?;
    decrypt_with_identity_key_shares(args.ciphertext, &shares)
}

/// Args of TS `buildPerNodeRequestCore`.
pub struct BuildPerNodeRequestCoreArgs<'a> {
    pub ace_deployment: &'a AceDeployment,
    pub network_state: &'a NetworkState,
    pub request: &'a DecryptionRequestPayload,
    pub proof: &'a ProofOfPermission,
    pub primitive: u8,
    pub target_endpoint: &'a str,
}

/// TS `buildPerNodeRequestCore`: build the encrypted request body for ONE worker (looked up
/// by `target_endpoint` among the current committee) without contacting the others. The
/// caller does the POST itself.
pub async fn build_per_node_request_core(
    args: BuildPerNodeRequestCoreArgs<'_>,
) -> Result<PerNodeRequest> {
    let reader = chain_reader(args.ace_deployment);
    let node_infos = fetch_node_infos(reader.as_ref(), args.network_state).await?;
    let sdk_idx = node_infos
        .iter()
        .position(|n| n.endpoint == args.target_endpoint)
        .ok_or_else(|| {
            AceError::Chain(format!(
                "ACE.buildPerNodeRequest: targetEndpoint {} is not in the current committee. Registered endpoints: {}",
                args.target_endpoint,
                node_infos
                    .iter()
                    .map(|n| n.endpoint.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
        })?;
    let req = WorkerRequest::new_decryption_basic_flow(
        args.request.clone(),
        args.proof.clone(),
        args.primitive,
    );
    let enc_req_hex = encrypt_worker_request(&req, &node_infos[sdk_idx].node_enc_key)?;
    Ok(PerNodeRequest {
        enc_req_hex,
        epoch: args.network_state.epoch,
        sdk_idx,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mpk_elements(mpk: &tibe::MasterPublicKey) -> (Element, Element) {
        match mpk {
            tibe::MasterPublicKey::ShortSigAead(m) => {
                (Element::Bls12381G2(m.base_point), Element::Bls12381G2(m.pk))
            }
            tibe::MasterPublicKey::ShortPkOtpHmac(m) => {
                (Element::Bls12381G1(m.base_point), Element::Bls12381G1(m.pk))
            }
        }
    }

    #[test]
    fn verify_idk_share_accepts_extracted_share_and_rejects_wrong_id() {
        for scheme in [
            tibe::SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD,
            tibe::SCHEME_BFIBE_BLS12381_SHORTPK_OTP_HMAC,
        ] {
            let msk = tibe::keygen_for_testing(scheme).unwrap();
            let mpk = tibe::derive_public_key(&msk);
            let (base_point, pk) = mpk_elements(&mpk);
            let scalar = match &msk {
                tibe::MasterPrivateKey::ShortSigAead(m) => m.scalar,
                tibe::MasterPrivateKey::ShortPkOtpHmac(m) => m.scalar,
            };
            let id = b"some-full-decryption-domain";
            // A single-holder committee: share_pks[0] = base^f(1) = pk.
            let pks = CurrentSessionPks {
                base_point,
                share_pks: vec![pk],
            };
            let share = tibe::extract(scheme, &scalar, id).unwrap();
            assert!(verify_idk_share(&share, 0, &pks, id), "scheme {scheme}");
            assert!(
                !verify_idk_share(&share, 0, &pks, b"other-id"),
                "scheme {scheme}"
            );
            // eval_point is 1, so sdk_idx=1 (expects eval 2) must be rejected.
            assert!(!verify_idk_share(&share, 1, &pks, id), "scheme {scheme}");
        }
    }

    #[test]
    fn encrypt_worker_request_roundtrips_through_worker_dk() {
        let worker_dk = pke::keygen(pke::DEFAULT_SCHEME).unwrap();
        let worker_ek = pke::derive_encryption_key(&worker_dk);
        let eph_dk = pke::keygen(pke::DEFAULT_SCHEME).unwrap();
        let req = WorkerRequest::new_decryption_custom_flow(
            CustomFlowRequest {
                keypair_id: AccountAddress::from_str_relaxed("0x1").unwrap(),
                epoch: 7,
                contract_id: crate::aptos::common::ContractID::dummy(),
                label: b"label".to_vec(),
                enc_pk: pke::derive_encryption_key(&eph_dk),
                proof: crate::aptos::common::CustomFlowProof::create_aptos(b"payload"),
            },
            tibe::SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD,
        );
        let hex_body = encrypt_worker_request(&req, &worker_ek).unwrap();
        let ct = pke::Ciphertext::from_hex(&hex_body).unwrap();
        let plain = pke::decrypt(&worker_dk, &ct).unwrap();
        let parsed = WorkerRequest::from_bytes(&plain).unwrap();
        assert_eq!(parsed, req);
    }

    #[test]
    fn parse_worker_response_roundtrip() {
        let eph_dk = pke::keygen(pke::DEFAULT_SCHEME).unwrap();
        let msk = tibe::keygen_for_testing(tibe::SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD).unwrap();
        let scalar = msk.as_shortsig_aead().unwrap().scalar;
        let share =
            tibe::extract(tibe::SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD, &scalar, b"id").unwrap();
        let ct = pke::encrypt(&pke::derive_encryption_key(&eph_dk), &share.to_bytes()).unwrap();
        let got = parse_worker_response(&format!(" {}\n", ct.to_hex()), &eph_dk).unwrap();
        assert_eq!(got, share);
        assert!(parse_worker_response("zz", &eph_dk).is_err());
    }
}
