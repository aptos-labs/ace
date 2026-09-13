// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Threshold VRF client (TS: `vrf-for-aptos/index.ts`). Requires the `aptos` feature.
//!
//! Flow: `DerivationSession::create` → `get_request_to_sign` (hex payload the wallet signs)
//! → `derive_with_signature` (fan out the encrypted `WorkerRequest::ThresholdVrf` to every
//! current node, decrypt + pairing-verify each `ThresholdVrfShare`, Lagrange-combine the
//! first `cur_threshold` valid G1 shares and hash to the 32-byte VRF output).
//!
//! Math (TS `verifyThresholdVrfShare` / `reconstructThresholdVrf`, worker
//! `crypto.rs::partial_derive_threshold_vrf_share`):
//!   * `input = bcs(str("ace.threshold-vrf.input.v1") ++ keypair_id ++ contract_id ++
//!     account_address ++ bytes(label))`
//!   * `H = hash_to_G1(input, DST = "ACE_THRESHOLD_VRF_BLS12381G1/HASH_TO_CURVE/v1")`
//!     (RFC 9380 SSWU / WB map, SHA-256 expand_message_xmd, 128-bit security)
//!   * node `i` returns `share_i = H * s_i` (G1); verified via
//!     `e(share_i, basePoint) == e(H, sharePk_i)` with `basePoint, sharePk_i` in G2.
//!   * `full = Σ λ_i · share_i` (Lagrange at zero over Fr, `x_i = eval_point`);
//!     `output = sha3_256(sha3_256("ACE::ThresholdVrfOutput") ++ compressed48(full))`.
//!
//! Not ported: the WebAuthn variants (`getRequestToSignForWebAuthn`,
//! `deriveWithWebAuthnAssertion`) — they need a browser authenticator; the pure
//! [`ThresholdVrfRequestPayload::to_webauthn_challenge`] is kept so a caller can build one.

use ark_bls12_381::{g1, Bls12_381, Fr, G1Projective};
use ark_ec::hashing::{
    curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,
};
use ark_ec::pairing::Pairing;
use ark_ff::field_hashers::DefaultFieldHasher;
use ark_ff::{Field, One, Zero};
use futures::future::join_all;
use sha2::Sha256;

use crate::address::AccountAddress;
use crate::aptos::client::{chain_reader, ChainReader};
use crate::aptos::common::{
    AptosProofOfPermission, AptosPublicKey, AptosSignature, ContractID, WorkerRequest,
};
use crate::aptos::deployment::AceDeployment;
use crate::aptos::flows::{encrypt_worker_request, CurrentSessionPks, WORKER_REQUEST_TIMEOUT};
use crate::aptos::signer::MessageSigner;
use crate::error::{AceError, Result};
use crate::group::bls12381fr::fr_from_u64;
use crate::group::bls12381g1::PublicPoint as G1Point;
use crate::group::{wire_via_serialize, Element, SCHEME_BLS12381G2};
use crate::network::State as NetworkState;
use crate::pke;
use crate::utils::sha3_256;
use crate::wire::{encode_hex, from_bytes_exact, Deserializer, Serializer, Wire};

/// TS `PURPOSE`.
pub const PURPOSE: &str = "ace.threshold-vrf.derive.v1";
/// Domain-separation prefix of the BCS VRF input (TS `toVrfInputBytes`).
pub const VRF_INPUT_PURPOSE: &str = "ace.threshold-vrf.input.v1";
/// Hash-to-G1 DST shared with the worker (`crypto.rs::DST_THRESHOLD_VRF_G1`).
pub const DST_THRESHOLD_VRF_G1: &[u8] = b"ACE_THRESHOLD_VRF_BLS12381G1/HASH_TO_CURVE/v1";
const WEBAUTHN_CHALLENGE_SEED: &[u8] = b"ACE::ThresholdVrfRequestPayload";
const OUTPUT_SEED: &[u8] = b"ACE::ThresholdVrfOutput";

type G1Hasher =
    MapToCurveBasedHasher<G1Projective, DefaultFieldHasher<Sha256, 128>, WBMap<g1::Config>>;

/// `hash_to_G1(input)` with the threshold-VRF DST.
pub fn hash_vrf_input_to_g1(input: &[u8]) -> Result<G1Point> {
    let hasher = G1Hasher::new(DST_THRESHOLD_VRF_G1)
        .map_err(|e| AceError::crypto(format!("tVRF hash-to-G1 init: {e:?}")))?;
    let affine = hasher
        .hash(input)
        .map_err(|e| AceError::crypto(format!("tVRF hash-to-G1: {e:?}")))?;
    Ok(G1Point {
        pt: G1Projective::from(affine),
    })
}

// ── Wire types ─────────────────────────────────────────────────────────────────────────

/// TS `RequestToSignArgs`.
pub struct RequestToSignArgs<'a> {
    pub ace_deployment: &'a AceDeployment,
    pub keypair_id: AccountAddress,
    pub contract_id: ContractID,
    pub label: Vec<u8>,
    pub account_address: AccountAddress,
}

/// TS `ThresholdVrfRequestPayload`. Layout: `fixed32(keypair_id) ++ u64(epoch) ++
/// contract_id ++ bytes(label) ++ fixed32(account_address) ++ response_enc_key`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ThresholdVrfRequestPayload {
    pub keypair_id: AccountAddress,
    pub epoch: u64,
    pub contract_id: ContractID,
    pub label: Vec<u8>,
    pub account_address: AccountAddress,
    pub response_enc_key: pke::EncryptionKey,
}

impl ThresholdVrfRequestPayload {
    pub fn serialize(&self, s: &mut Serializer) {
        self.keypair_id.serialize(s);
        s.u64(self.epoch);
        self.contract_id.serialize(s);
        s.bytes(&self.label);
        self.account_address.serialize(s);
        self.response_enc_key.serialize(s);
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        let keypair_id = AccountAddress::deserialize(d)?;
        let epoch = d.u64()?;
        let contract_id = ContractID::deserialize(d)?;
        let label = d.bytes()?;
        let account_address = AccountAddress::deserialize(d)?;
        let response_enc_key = pke::EncryptionKey::deserialize(d)?;
        Ok(Self {
            keypair_id,
            epoch,
            contract_id,
            label,
            account_address,
            response_enc_key,
        })
    }

    /// TS `toWebAuthnChallenge`: `sha3_256(sha3_256("ACE::ThresholdVrfRequestPayload") ++ bcs)`.
    pub fn to_webauthn_challenge(&self) -> [u8; 32] {
        let mut preimage = sha3_256(WEBAUTHN_CHALLENGE_SEED).to_vec();
        preimage.extend_from_slice(&self.to_bytes());
        sha3_256(&preimage)
    }

    /// TS `toVrfInputBytes`: the bytes hashed to G1 (epoch and enc key excluded).
    pub fn to_vrf_input_bytes(&self) -> Vec<u8> {
        let mut s = Serializer::new();
        s.str(VRF_INPUT_PURPOSE);
        self.keypair_id.serialize(&mut s);
        self.contract_id.serialize(&mut s);
        self.account_address.serialize(&mut s);
        s.bytes(&self.label);
        s.into_bytes()
    }
}
wire_via_serialize!(ThresholdVrfRequestPayload);

/// TS `AptosAccountSignatureProof`. Byte-for-byte the same layout as
/// [`AptosProofOfPermission`] (`fixed32(user_addr) ++ u8(pk_scheme) ++ pk ++ u8(sig_scheme)
/// ++ sig ++ str(full_message)`), so it is a plain alias.
pub type AptosAccountSignatureProof = AptosProofOfPermission;

/// TS `ThresholdVrfRequest`: `payload ++ auth_proof`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ThresholdVrfRequest {
    pub payload: ThresholdVrfRequestPayload,
    pub auth_proof: AptosAccountSignatureProof,
}

impl ThresholdVrfRequest {
    pub fn serialize(&self, s: &mut Serializer) {
        self.payload.serialize(s);
        self.auth_proof.serialize(s);
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(Self {
            payload: ThresholdVrfRequestPayload::deserialize(d)?,
            auth_proof: AptosAccountSignatureProof::deserialize(d)?,
        })
    }
}
wire_via_serialize!(ThresholdVrfRequest);

/// TS `ThresholdVrfShare`: `u64(eval_point) ++ tagged group::Element` (G1 for tVRF).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ThresholdVrfShare {
    pub eval_point: u64,
    pub share: Element,
}

impl ThresholdVrfShare {
    pub fn serialize(&self, s: &mut Serializer) {
        s.u64(self.eval_point);
        self.share.serialize(s);
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(Self {
            eval_point: d.u64()?,
            share: Element::deserialize(d)?,
        })
    }
}
wire_via_serialize!(ThresholdVrfShare);

// ── Pure crypto ────────────────────────────────────────────────────────────────────────

/// TS `verifyThresholdVrfShare`: `eval_point == sdk_idx + 1`, share is G1, base point and
/// `share_pks[sdk_idx]` are G2, and `e(share, basePoint) == e(H(vrf_input), sharePk)`.
/// Returns `false` (never errors) so callers can drop the share, like TS.
pub fn verify_threshold_vrf_share(
    share: &ThresholdVrfShare,
    sdk_idx: usize,
    session_pks: &CurrentSessionPks,
    vrf_input: &[u8],
) -> bool {
    if share.eval_point != sdk_idx as u64 + 1 {
        return false;
    }
    let Ok(share_g1) = share.share.as_bls12381g1() else {
        return false;
    };
    let Ok(base_g2) = session_pks.base_point.as_bls12381g2() else {
        return false;
    };
    let Some(share_pk) = session_pks.share_pks.get(sdk_idx) else {
        return false;
    };
    let Ok(share_pk_g2) = share_pk.as_bls12381g2() else {
        return false;
    };
    let Ok(input_point) = hash_vrf_input_to_g1(vrf_input) else {
        return false;
    };
    let lhs = Bls12_381::pairing(share_g1.pt, base_g2.pt);
    let rhs = Bls12_381::pairing(input_point.pt, share_pk_g2.pt);
    lhs == rhs
}

/// TS `reconstructThresholdVrf`: Lagrange-interpolate the G1 shares at zero and hash
/// `sha3_256(sha3_256("ACE::ThresholdVrfOutput") ++ compressed(full))`.
pub fn reconstruct_threshold_vrf(shares: &[ThresholdVrfShare]) -> Result<Vec<u8>> {
    if shares.is_empty() {
        return Err(AceError::crypto(
            "ACE.VRF_Aptos.reconstructThresholdVrf: no shares",
        ));
    }
    let xs: Vec<Fr> = shares.iter().map(|s| fr_from_u64(s.eval_point)).collect();
    for i in 0..xs.len() {
        for j in (i + 1)..xs.len() {
            if xs[i] == xs[j] {
                return Err(AceError::crypto(
                    "ACE.VRF_Aptos.reconstructThresholdVrf: duplicate evalPoint",
                ));
            }
        }
    }
    let mut full: Option<G1Projective> = None;
    for (i, share) in shares.iter().enumerate() {
        let mut lambda = Fr::one();
        for (j, xj) in xs.iter().enumerate() {
            if i == j {
                continue;
            }
            let denom = (xs[i] - xj).inverse().ok_or_else(|| {
                AceError::crypto("ACE.VRF_Aptos.reconstructThresholdVrf: non-invertible")
            })?;
            lambda *= -*xj * denom;
        }
        if lambda.is_zero() {
            continue;
        }
        let pt = share.share.as_bls12381g1()?.pt * lambda;
        full = Some(match full {
            None => pt,
            Some(acc) => acc + pt,
        });
    }
    let full = full.ok_or_else(|| {
        AceError::crypto(
            "ACE.VRF_Aptos.reconstructThresholdVrf: all Lagrange coefficients were zero",
        )
    })?;
    let point_bytes = G1Point { pt: full }.raw_bytes();
    let mut preimage = sha3_256(OUTPUT_SEED).to_vec();
    preimage.extend_from_slice(&point_bytes);
    Ok(sha3_256(&preimage).to_vec())
}

// ── Network flow ───────────────────────────────────────────────────────────────────────

struct VrfNodeInfo {
    node_addr: String,
    endpoint: String,
    node_enc_key: pke::EncryptionKey,
}

/// TS `fetchCurrentNodeInfos`.
async fn fetch_current_node_infos(
    reader: &dyn ChainReader,
    network_state: &NetworkState,
) -> Result<Vec<VrfNodeInfo>> {
    join_all(network_state.cur_nodes.iter().map(|addr| async move {
        let (endpoint, node_enc_key) =
            futures::future::try_join(reader.worker_endpoint(addr), reader.worker_enc_key(addr))
                .await?;
        Ok(VrfNodeInfo {
            node_addr: addr.to_string_long(),
            endpoint,
            node_enc_key,
        })
    }))
    .await
    .into_iter()
    .collect()
}

/// One worker round-trip: encrypt, POST hex, decrypt + parse + verify.
async fn fetch_one_vrf_share(
    http: &reqwest::Client,
    node: &VrfNodeInfo,
    req: &WorkerRequest,
    decryption_key: &pke::DecryptionKey,
    sdk_idx: usize,
    session_pks: &CurrentSessionPks,
    vrf_input: &[u8],
) -> Result<ThresholdVrfShare> {
    let enc_req_hex = encrypt_worker_request(req, &node.node_enc_key)?;
    let resp = http
        .post(&node.endpoint)
        .body(enc_req_hex)
        .send()
        .await
        .map_err(|e| AceError::Chain(format!("{}: fetch error: {e}", node.node_addr)))?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(AceError::Http {
            status: status.as_u16(),
            body: body.trim().chars().take(120).collect(),
        });
    }
    let resp_ct = pke::Ciphertext::from_hex(body.trim()).map_err(|e| {
        AceError::crypto(format!(
            "{}: response ciphertext parse failed: {e}",
            node.node_addr
        ))
    })?;
    let share_bytes = pke::decrypt(decryption_key, &resp_ct).map_err(|e| {
        AceError::crypto(format!(
            "{}: response decryption failed: {e}",
            node.node_addr
        ))
    })?;
    let share = ThresholdVrfShare::from_bytes(&share_bytes)
        .map_err(|e| AceError::crypto(format!("{}: share parse failed: {e}", node.node_addr)))?;
    if !verify_threshold_vrf_share(&share, sdk_idx, session_pks, vrf_input) {
        return Err(AceError::Verify(format!(
            "{}: invalid tVRF share",
            node.node_addr
        )));
    }
    Ok(share)
}

/// TS `DerivationSession`: two-phase derive (get message → sign externally → derive).
pub struct DerivationSession {
    pub ace_deployment: AceDeployment,
    pub keypair_id: AccountAddress,
    pub contract_id: ContractID,
    pub label: Vec<u8>,
    pub account_address: AccountAddress,
    pub response_encryption_key: pke::EncryptionKey,
    pub response_decryption_key: pke::DecryptionKey,
    pub network_state: Option<NetworkState>,
    pub payload: Option<ThresholdVrfRequestPayload>,
    pub message: Option<String>,
}

impl DerivationSession {
    /// TS `DerivationSession.create`: generate the ephemeral response PKE keypair.
    pub async fn create(args: RequestToSignArgs<'_>) -> Result<Self> {
        let dk = pke::keygen(pke::DEFAULT_SCHEME)?;
        let ek = pke::derive_encryption_key(&dk);
        Ok(Self {
            ace_deployment: args.ace_deployment.clone(),
            keypair_id: args.keypair_id,
            contract_id: args.contract_id,
            label: args.label,
            account_address: args.account_address,
            response_encryption_key: ek,
            response_decryption_key: dk,
            network_state: None,
            payload: None,
            message: None,
        })
    }

    /// Pure half of TS `refreshPayload`: build the payload for `network_state`, cache it
    /// and the `"0x" + hex(bcs(payload))` message.
    pub fn set_network_state(
        &mut self,
        network_state: NetworkState,
    ) -> &ThresholdVrfRequestPayload {
        let payload = ThresholdVrfRequestPayload {
            keypair_id: self.keypair_id,
            epoch: network_state.epoch,
            contract_id: self.contract_id.clone(),
            label: self.label.clone(),
            account_address: self.account_address,
            response_enc_key: self.response_encryption_key.clone(),
        };
        self.message = Some(format!("0x{}", encode_hex(&payload.to_bytes())));
        self.network_state = Some(network_state);
        self.payload.insert(payload)
    }

    /// TS `getRequestToSign`: refresh network state, return `"0x" + hex(bcs(payload))`.
    pub async fn get_request_to_sign(&mut self) -> Result<String> {
        let network_state = chain_reader(&self.ace_deployment).network_state().await?;
        self.set_network_state(network_state);
        Ok(self.message.clone().expect("set by set_network_state"))
    }

    /// TS `deriveWithSignature`. Fans out to every current node concurrently (8s per node),
    /// verifies each share and reconstructs from the first `cur_threshold` valid ones.
    pub async fn derive_with_signature(
        &self,
        pub_key: AptosPublicKey,
        signature: AptosSignature,
        full_message: String,
    ) -> Result<Vec<u8>> {
        const FN: &str = "ACE.VRF_Aptos.DerivationSession.deriveWithSignature";
        let (Some(payload), Some(network_state)) = (&self.payload, &self.network_state) else {
            return Err(AceError::Other(format!(
                "{FN}: call get_request_to_sign() first"
            )));
        };
        let auth_proof = AptosAccountSignatureProof {
            user_addr: self.account_address,
            public_key: pub_key,
            signature,
            full_message,
        };
        let req_body = ThresholdVrfRequest {
            payload: payload.clone(),
            auth_proof,
        }
        .to_bytes();
        let req = WorkerRequest::new_threshold_vrf(&req_body);

        let reader = chain_reader(&self.ace_deployment);
        let (node_infos, session_pks) = futures::future::try_join(
            fetch_current_node_infos(reader.as_ref(), network_state),
            crate::aptos::flows::fetch_current_session_pks(
                &self.ace_deployment,
                network_state,
                &self.keypair_id,
            ),
        )
        .await?;
        if session_pks.share_pks.len() != network_state.cur_nodes.len() {
            return Err(AceError::Chain(format!(
                "{FN}: sharePks length {} != curNodes length {}",
                session_pks.share_pks.len(),
                network_state.cur_nodes.len()
            )));
        }
        if session_pks.base_point.scheme() != SCHEME_BLS12381G2 {
            return Err(AceError::Chain(format!(
                "{FN}: threshold VRF requires a G2 keypair, got basePoint scheme {}",
                session_pks.base_point.scheme()
            )));
        }
        let vrf_input = payload.to_vrf_input_bytes();
        let http = reqwest::Client::builder()
            .timeout(WORKER_REQUEST_TIMEOUT)
            .build()
            .map_err(|e| AceError::Chain(format!("reqwest client: {e}")))?;
        let results = join_all(node_infos.iter().enumerate().map(|(i, node)| {
            fetch_one_vrf_share(
                &http,
                node,
                &req,
                &self.response_decryption_key,
                i,
                &session_pks,
                &vrf_input,
            )
        }))
        .await;
        let mut shares = Vec::new();
        for r in results {
            match r {
                Ok(s) => shares.push(s),
                // TS: `sawNotImplemented` → dedicated error.
                Err(AceError::Http { status: 501, .. }) => {
                    return Err(AceError::Other(format!(
                        "{FN}: threshold VRF worker handler is not implemented yet"
                    )));
                }
                Err(_) => {}
            }
        }
        let need = network_state.cur_threshold as usize;
        if shares.len() < need {
            return Err(AceError::InsufficientShares {
                need,
                got: shares.len(),
            });
        }
        reconstruct_threshold_vrf(&shares[..need])
    }
}

/// TS `derive` args: one-shot `create → get_request_to_sign → sign → derive_with_signature`.
/// `account_address` comes from `signer.account_address()`.
pub struct DeriveArgs<'a> {
    pub ace_deployment: &'a AceDeployment,
    pub keypair_id: AccountAddress,
    pub chain_id: u8,
    pub module_addr: AccountAddress,
    pub module_name: String,
    pub label: Vec<u8>,
    pub signer: &'a dyn MessageSigner,
}

/// TS `derive`.
pub async fn derive(args: DeriveArgs<'_>) -> Result<Vec<u8>> {
    let mut session = DerivationSession::create(RequestToSignArgs {
        ace_deployment: args.ace_deployment,
        keypair_id: args.keypair_id,
        contract_id: ContractID::new_aptos(args.chain_id, args.module_addr, args.module_name),
        label: args.label,
        account_address: args.signer.account_address(),
    })
    .await?;
    let message = session.get_request_to_sign().await?;
    let signed = args.signer.sign(&message).await?;
    session
        .derive_with_signature(signed.pub_key, signed.signature, signed.full_message)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aptos::flows::CurrentSessionPks;
    use crate::group::bls12381fr::{eval_poly, Fr};
    use crate::group::{bls12381g1, bls12381g2};
    use crate::wire::Wire;

    fn committee(secret: Fr, input: &[u8]) -> (CurrentSessionPks, Vec<ThresholdVrfShare>) {
        let coeffs = [secret, bls12381g2::sample().scalar];
        let h = hash_vrf_input_to_g1(input).unwrap();
        let g2 = bls12381g2::generator();
        let mut pks = vec![];
        let mut shares = vec![];
        for i in 1..=3u64 {
            let s = eval_poly(&coeffs, Fr::from(i));
            pks.push(Element::Bls12381G2(
                g2.scale(&bls12381g2::PrivateScalar::from_fr(s)),
            ));
            shares.push(ThresholdVrfShare {
                eval_point: i,
                share: Element::Bls12381G1(h.scale(&bls12381g1::PrivateScalar::from_fr(s))),
            });
        }
        (
            CurrentSessionPks {
                base_point: Element::Bls12381G2(g2),
                share_pks: pks,
            },
            shares,
        )
    }

    #[test]
    fn simulated_committee_verify_and_reconstruct() {
        let secret = bls12381g2::sample().scalar;
        let input = b"vrf-input";
        let (pks, shares) = committee(secret, input);
        for (i, s) in shares.iter().enumerate() {
            assert!(verify_threshold_vrf_share(s, i, &pks, input));
            assert!(!verify_threshold_vrf_share(s, (i + 1) % 3, &pks, input));
            assert!(!verify_threshold_vrf_share(s, i, &pks, b"other"));
        }
        let full = hash_vrf_input_to_g1(input)
            .unwrap()
            .scale(&bls12381g1::PrivateScalar::from_fr(secret));
        let mut pre = crate::utils::sha3_256(b"ACE::ThresholdVrfOutput").to_vec();
        pre.extend(full.raw_bytes());
        let expected = crate::utils::sha3_256(&pre).to_vec();
        assert_eq!(reconstruct_threshold_vrf(&shares[..2]).unwrap(), expected);
        assert_eq!(reconstruct_threshold_vrf(&shares[1..]).unwrap(), expected);
        assert_eq!(reconstruct_threshold_vrf(&shares).unwrap(), expected);
        assert_ne!(reconstruct_threshold_vrf(&shares[..1]).unwrap(), expected);
        assert!(reconstruct_threshold_vrf(&[]).is_err());
        assert!(reconstruct_threshold_vrf(&[shares[0].clone(), shares[0].clone()]).is_err());
        let b = shares[0].to_bytes();
        assert_eq!(b.len(), 8 + 1 + 1 + 48);
        assert_eq!(ThresholdVrfShare::from_bytes(&b).unwrap(), shares[0]);
    }
}
