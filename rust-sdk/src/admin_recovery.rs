// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Disaster-recovery master-secret reconstruction (admin-side client). Port of
//! `ts-sdk/src/admin-recovery/index.ts`.
//!
//! A trusted reconstructor (holding the deployment's dedicated `sig` signing key whose public
//! counterpart was pushed to every node as `--reconstructor-pk`) collects ≥ t raw Shamir scalar
//! shares directly from the committee nodes and Lagrange-interpolates the master secret `s`.
//! Intended to be run **right after each DKG** and the result stored in cold storage.
//!
//! Wire types mirror `worker-components/network-node/src/verify/mod.rs`
//! (`ReconstructionRequest*` / `ReconstructionResponse`) and go through the standard encrypted
//! `POST /` channel via `WorkerRequest` variant 3 ([`WorkerRequest::new_reconstruction`]).

use std::collections::BTreeMap;
use std::time::Duration;

use futures::future::join_all;

use crate::address::AccountAddress;
use crate::aptos::client::{chain_reader, ChainReader};
use crate::aptos::common::WorkerRequest;
use crate::aptos::deployment::AceDeployment;
use crate::aptos::flows::encrypt_worker_request;
use crate::error::{AceError, Result};
use crate::group::bls12381fr::{
    fr_from_le_bytes, fr_from_u64, fr_to_le_bytes, lagrange_at_zero, Fr,
};
use crate::group::{
    bls12381g1, bls12381g2, wire_via_serialize, Element, Scalar, SCHEME_BLS12381G1,
    SCHEME_BLS12381G2,
};
use crate::pke;
use crate::sig;
use crate::t_ibe;
use crate::wire::{from_bytes_exact, Deserializer, Serializer, Wire};

/// Fields the reconstructor signs over. BCS layout must match the node-side
/// `ReconstructionRequestPayload` (field order: chain_id, ace_addr, keypair_id, epoch,
/// eph_pke_ek). `ace_addr`/`keypair_id` serialize as 32 raw bytes.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReconstructionRequestPayload {
    pub chain_id: u8,
    pub ace_addr: AccountAddress,
    pub keypair_id: AccountAddress,
    pub epoch: u64,
    pub eph_pke_ek: pke::EncryptionKey,
}

impl ReconstructionRequestPayload {
    pub fn serialize(&self, s: &mut Serializer) {
        s.u8(self.chain_id);
        self.ace_addr.serialize(s);
        self.keypair_id.serialize(s);
        s.u64(self.epoch);
        self.eph_pke_ek.serialize(s);
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(Self {
            chain_id: d.u8()?,
            ace_addr: AccountAddress::deserialize(d)?,
            keypair_id: AccountAddress::deserialize(d)?,
            epoch: d.u64()?,
            eph_pke_ek: pke::EncryptionKey::deserialize(d)?,
        })
    }
}
wire_via_serialize!(ReconstructionRequestPayload);

/// `{ payload, sig }` — the inner body of `WorkerRequest::Reconstruction`. The signature is
/// the reconstructor's `sig::SigningKey` signature over exactly `payload.to_bytes()`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReconstructionRequest {
    pub payload: ReconstructionRequestPayload,
    pub signature: sig::Signature,
}

impl ReconstructionRequest {
    /// Build and sign the request (TS: `signingKey.sign(payload.toBytes())`).
    pub fn sign(payload: ReconstructionRequestPayload, signing_key: &sig::SigningKey) -> Self {
        let signature = signing_key.sign(&payload.to_bytes());
        Self { payload, signature }
    }

    pub fn serialize(&self, s: &mut Serializer) {
        self.payload.serialize(s);
        self.signature.serialize(s);
    }

    pub fn deserialize(d: &mut Deserializer<'_>) -> Result<Self> {
        Ok(Self {
            payload: ReconstructionRequestPayload::deserialize(d)?,
            signature: sig::Signature::deserialize(d)?,
        })
    }
}
wire_via_serialize!(ReconstructionRequest);

/// The decrypted reconstruction response (the whole struct is PKE-encrypted on the wire; this
/// is what you get after decrypting with the ephemeral key).
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReconstructionResponse {
    pub eval_point: u64,
    pub group_scheme: u8,
    /// Raw 32-byte LE Fr scalar — the node's Shamir share.
    pub scalar: [u8; 32],
}

/// Parse the *decrypted* response bytes (`bcs(ReconstructionResponse)`): `u64 eval_point ++
/// u8 group_scheme ++ [u8; 32] scalar`, no trailing bytes.
pub fn parse_reconstruction_response(bytes: &[u8]) -> Result<ReconstructionResponse> {
    from_bytes_exact(bytes, |d| {
        Ok(ReconstructionResponse {
            eval_point: d.u64()?,
            group_scheme: d.u8()?,
            scalar: d.fixed_array::<32>()?,
        })
    })
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct ReconstructResult {
    /// Master secret `s` as 0x-prefixed 32-byte little-endian hex.
    pub secret_hex: String,
    /// The epoch the shares were collected from.
    pub epoch: u64,
    /// Number of (distinct-eval-point) shares used (≥ threshold).
    pub shares_used: usize,
    /// `Some(true)` if `s·basePoint == masterPk` was checked and held; `Some(false)` if the check
    /// failed; `None` if it couldn't run (e.g. master pk unavailable).
    pub verified: Option<bool>,
}

/// Lagrange-interpolate the master secret at 0 from raw node responses (pure part of
/// [`reconstruct_secret`]). Errors on an empty slice, on duplicate eval points and on a
/// non-canonical scalar encoding. Callers wanting TS's "last one wins" dedup must do it first
/// (see [`dedup_by_eval_point`]).
pub fn reconstruct_from_responses(responses: &[ReconstructionResponse]) -> Result<Fr> {
    if responses.is_empty() {
        return Err(AceError::InsufficientShares { need: 1, got: 0 });
    }
    let mut seen = std::collections::BTreeSet::new();
    let mut points = Vec::with_capacity(responses.len());
    for r in responses {
        if !seen.insert(r.eval_point) {
            return Err(AceError::crypto(format!(
                "reconstruct_from_responses: duplicate eval_point {}",
                r.eval_point
            )));
        }
        points.push((fr_from_u64(r.eval_point), fr_from_le_bytes(&r.scalar)?));
    }
    lagrange_at_zero(&points)
}

/// TS: `byX.set(p.x.toString(), p)` — keep the last response per eval point, sorted by point.
pub fn dedup_by_eval_point(responses: Vec<ReconstructionResponse>) -> Vec<ReconstructionResponse> {
    let mut by_x: BTreeMap<u64, ReconstructionResponse> = BTreeMap::new();
    for r in responses {
        by_x.insert(r.eval_point, r);
    }
    by_x.into_values().collect()
}

/// `s · base_point == result_pk`, in whichever BLS12-381 group the session lives in.
pub fn verify_master_secret(base_point: &Element, result_pk: &Element, s: &Fr) -> Result<bool> {
    let scalar = match base_point.scheme() {
        SCHEME_BLS12381G1 => Scalar::Bls12381G1(bls12381g1::PrivateScalar::from_fr(*s)),
        SCHEME_BLS12381G2 => Scalar::Bls12381G2(bls12381g2::PrivateScalar::from_fr(*s)),
        other => return Err(AceError::UnsupportedScheme(other)),
    };
    Ok(base_point.scale(&scalar)? == *result_pk)
}

/// Master secret as 0x-prefixed 32-byte little-endian hex (TS `secretHex`).
pub fn secret_to_hex(s: &Fr) -> String {
    format!("0x{}", hex::encode(fr_to_le_bytes(s)))
}

/// Arguments of [`reconstruct_secret`].
pub struct ReconstructSecretArgs<'a> {
    pub ace_deployment: &'a AceDeployment,
    pub keypair_id: &'a AccountAddress,
    /// The deployment's reconstructor key (nodes must run with the matching `--reconstructor-pk`).
    pub signing_key: &'a sig::SigningKey,
    pub chain_id: u8,
    /// Defaults to `SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD`; only used for the `verified` check.
    pub tibe_scheme: Option<u8>,
    /// TS `perNodeTimeoutMs` (default 8s).
    pub per_node_timeout: Duration,
}

/// One node round-trip: resolve endpoint + enc key, encrypt, POST hex, decrypt with the
/// ephemeral key, parse. `Err` means the node is dropped (TS logs and returns `null`).
async fn fetch_one_response(
    http: &reqwest::Client,
    reader: &dyn ChainReader,
    node_addr: &AccountAddress,
    req: &WorkerRequest,
    eph_dk: &pke::DecryptionKey,
) -> Result<ReconstructionResponse> {
    let (endpoint, node_enc_key) = futures::future::try_join(
        reader.worker_endpoint(node_addr),
        reader.worker_enc_key(node_addr),
    )
    .await?;
    let enc_req_hex = encrypt_worker_request(req, &node_enc_key)?;
    let resp = http
        .post(&endpoint)
        .body(enc_req_hex)
        .send()
        .await
        .map_err(|e| {
            if e.is_timeout() {
                AceError::Timeout
            } else {
                AceError::Chain(format!("fetch error: {e}"))
            }
        })?;
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    if !status.is_success() {
        return Err(AceError::Http {
            status: status.as_u16(),
            body: body.trim().chars().take(120).collect(),
        });
    }
    // Body is hex(BCS(pke::Ciphertext)) over the whole encrypted response.
    let resp_ct = pke::Ciphertext::from_hex(body.trim())
        .map_err(|e| AceError::crypto(format!("response ciphertext parse failed: {e}")))?;
    let plain = pke::decrypt(eph_dk, &resp_ct)
        .map_err(|e| AceError::crypto(format!("response decryption failed: {e}")))?;
    parse_reconstruction_response(&plain)
}

/// TS `reconstructSecret`: collect raw scalar shares from all `cur_nodes`, drop failing nodes,
/// require ≥ `cur_threshold` distinct eval points, interpolate at 0 and (best-effort) verify
/// against the on-chain master public key.
pub async fn reconstruct_secret(args: ReconstructSecretArgs<'_>) -> Result<ReconstructResult> {
    let reader = chain_reader(args.ace_deployment);
    let network_state = reader.network_state().await?;
    let epoch = network_state.epoch;
    let need = network_state.cur_threshold as usize;

    let eph_dk = pke::keygen(pke::DEFAULT_SCHEME)?;
    let payload = ReconstructionRequestPayload {
        chain_id: args.chain_id,
        ace_addr: args.ace_deployment.contract_addr,
        keypair_id: *args.keypair_id,
        epoch,
        eph_pke_ek: pke::derive_encryption_key(&eph_dk),
    };
    let req = WorkerRequest::new_reconstruction(
        &ReconstructionRequest::sign(payload, args.signing_key).to_bytes(),
    );

    let http = reqwest::Client::builder()
        .timeout(args.per_node_timeout)
        .build()
        .map_err(|e| AceError::Chain(format!("reqwest client: {e}")))?;
    let results = join_all(
        network_state
            .cur_nodes
            .iter()
            .map(|addr| fetch_one_response(&http, reader.as_ref(), addr, &req, &eph_dk)),
    )
    .await;
    let responses = dedup_by_eval_point(results.into_iter().filter_map(|r| r.ok()).collect());
    if responses.len() < need {
        return Err(AceError::InsufficientShares {
            need,
            got: responses.len(),
        });
    }
    let s = reconstruct_from_responses(&responses)?;

    // Best-effort `verified` (TS swallows every error into `undefined`).
    let verified = match reader.session(args.keypair_id, true).await {
        Ok(pks) => match pks.result_pk {
            Some(result_pk) => {
                let scheme = args
                    .tibe_scheme
                    .unwrap_or(t_ibe::SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD);
                // Same compatibility check TS does via `fetchTibePublicKey`.
                if t_ibe::MasterPublicKey::from_group_elements(scheme, &pks.base_point, &result_pk)
                    .is_ok()
                {
                    verify_master_secret(&pks.base_point, &result_pk, &s).ok()
                } else {
                    None
                }
            }
            None => None,
        },
        Err(_) => None,
    };

    Ok(ReconstructResult {
        secret_hex: secret_to_hex(&s),
        epoch,
        shares_used: responses.len(),
        verified,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::group::bls12381fr::eval_poly;

    fn sample_payload() -> ReconstructionRequestPayload {
        let dk = pke::keygen(pke::DEFAULT_SCHEME).unwrap();
        ReconstructionRequestPayload {
            chain_id: 4,
            ace_addr: AccountAddress::from_bytes(&[0x11; 32]).unwrap(),
            keypair_id: AccountAddress::from_bytes(&[0x22; 32]).unwrap(),
            epoch: 7,
            eph_pke_ek: pke::derive_encryption_key(&dk),
        }
    }

    #[test]
    fn payload_wire_round_trip_and_layout() {
        let p = sample_payload();
        let bytes = p.to_bytes();
        // u8 chain_id ++ 32 ace_addr ++ 32 keypair_id ++ u64 epoch ++ ek
        assert_eq!(bytes[0], 4);
        assert_eq!(&bytes[1..33], &[0x11; 32]);
        assert_eq!(&bytes[33..65], &[0x22; 32]);
        assert_eq!(&bytes[65..73], &7u64.to_le_bytes());
        assert_eq!(&bytes[73..], &p.eph_pke_ek.to_bytes()[..]);
        assert_eq!(ReconstructionRequestPayload::from_bytes(&bytes).unwrap(), p);
        assert!(ReconstructionRequestPayload::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    }

    #[test]
    fn request_wire_round_trip_and_signature_over_payload_bytes() {
        let (pk, sk) = sig::keygen();
        let p = sample_payload();
        let req = ReconstructionRequest::sign(p.clone(), &sk);
        let bytes = req.to_bytes();
        let payload_bytes = p.to_bytes();
        assert_eq!(&bytes[..payload_bytes.len()], &payload_bytes[..]);
        assert_eq!(&bytes[payload_bytes.len()..], &req.signature.to_bytes()[..]);
        let back = ReconstructionRequest::from_bytes(&bytes).unwrap();
        assert_eq!(back, req);
        // Signed over exactly `payload.to_bytes()` (what TS signs).
        assert!(sig::verify(&payload_bytes, &back.signature, &pk));
        assert!(!sig::verify(&bytes, &back.signature, &pk));
        // Embeds as WorkerRequest variant 3.
        let wr = WorkerRequest::new_reconstruction(&bytes).to_bytes();
        assert_eq!(wr[0], 3);
    }

    #[test]
    fn parse_response_hand_built() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&5u64.to_le_bytes());
        bytes.push(1);
        let scalar = [0xab; 32];
        bytes.extend_from_slice(&scalar);
        let r = parse_reconstruction_response(&bytes).unwrap();
        assert_eq!(
            r,
            ReconstructionResponse {
                eval_point: 5,
                group_scheme: 1,
                scalar
            }
        );
        bytes.push(0);
        assert!(parse_reconstruction_response(&bytes).is_err());
        assert!(parse_reconstruction_response(&bytes[..40]).is_err());
    }

    fn share(x: u64, coeffs: &[Fr]) -> ReconstructionResponse {
        ReconstructionResponse {
            eval_point: x,
            group_scheme: SCHEME_BLS12381G2,
            scalar: fr_to_le_bytes(&eval_poly(coeffs, fr_from_u64(x))),
        }
    }

    #[test]
    fn reconstruct_from_shamir_shares() {
        let secret = fr_from_u64(0xdead_beef);
        let coeffs = [secret, fr_from_u64(31337)]; // degree 1 => threshold 2
        let shares: Vec<_> = (1..=3).map(|x| share(x, &coeffs)).collect();
        for pair in [[0, 1], [0, 2], [1, 2]] {
            let sub = [shares[pair[0]].clone(), shares[pair[1]].clone()];
            assert_eq!(reconstruct_from_responses(&sub).unwrap(), secret);
        }
        assert_eq!(reconstruct_from_responses(&shares).unwrap(), secret);
        assert_eq!(
            secret_to_hex(&secret),
            format!("0x{}", hex::encode(fr_to_le_bytes(&secret)))
        );
        // base·s == pk check
        let base = Element::Bls12381G2(bls12381g2::generator());
        let pk = base
            .scale(&Scalar::Bls12381G2(bls12381g2::PrivateScalar::from_fr(
                secret,
            )))
            .unwrap();
        assert!(verify_master_secret(&base, &pk, &secret).unwrap());
        assert!(!verify_master_secret(&base, &base, &secret).unwrap());
    }

    #[test]
    fn reconstruct_rejects_empty_and_duplicates() {
        assert!(matches!(
            reconstruct_from_responses(&[]),
            Err(AceError::InsufficientShares { .. })
        ));
        let coeffs = [fr_from_u64(1), fr_from_u64(2)];
        let dup = [share(1, &coeffs), share(1, &coeffs)];
        assert!(reconstruct_from_responses(&dup).is_err());
        assert_eq!(dedup_by_eval_point(dup.to_vec()).len(), 1);
    }
}
