// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Fail-closed policy for the c26t Confidential Space root-unlock flow.
//!
//! A root request is deliberately separate from the ordinary account-signed
//! threshold VRF. The exact VRF input is pinned by operator configuration;
//! a Google-signed OIDC attestation binds its response key and all request
//! fields through `eat_nonce`. The node never returns a plaintext share.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::signature::{RsaPublicKeyComponents, RSA_PKCS1_2048_8192_SHA256};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use vss_common::pke::EncryptionKey;

use crate::verify::{ContractId, ThresholdVrfRequestPayload};

const ISSUER: &str = "https://confidentialcomputing.googleapis.com";
const JWKS_URL: &str = "https://www.googleapis.com/service_accounts/v1/metadata/jwk/signer@confidentialspace-sign.iam.gserviceaccount.com";
const NONCE_DOMAIN: &[u8] = b"ace/c26t/cvm-root/attestation/v1\0";
const ROOT_LABEL: &[u8] = b"c26t/root/v1";
const MAX_JWT_BYTES: usize = 128 * 1024;
const MAX_JWKS_BYTES: usize = 1024 * 1024;
const MAX_TOKEN_AGE_SECONDS: i64 = 300;
const CLOCK_SKEW_SECONDS: i64 = 30;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyConfig {
    audience: String,
    image_digest: String,
    project_id: String,
    expected_env: BTreeMap<String, String>,
    expected_args: Vec<String>,
    keypair_id: String,
    chain_id: u8,
    module_addr: String,
    module_name: String,
    account_address: String,
}

#[derive(Clone)]
pub struct CvmRootPolicy {
    audience: String,
    image_digest: String,
    project_id: String,
    expected_env: BTreeMap<String, String>,
    expected_args: Vec<String>,
    keypair_id: [u8; 32],
    chain_id: u8,
    module_addr: [u8; 32],
    module_name: String,
    account_address: [u8; 32],
    http: reqwest::Client,
}

fn parse_hex32(name: &str, value: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(value.trim_start_matches("0x"))
        .with_context(|| format!("{} must be 32-byte hex", name))?;
    bytes
        .try_into()
        .map_err(|_| anyhow!("{} must be 32-byte hex", name))
}

impl CvmRootPolicy {
    /// No policy means the privileged flow is disabled. A configured policy
    /// must pin the exact ACE input and measured workload before startup.
    pub fn from_json(json: &str) -> Result<Self> {
        let cfg: PolicyConfig = serde_json::from_str(json).context("cvm root policy JSON")?;
        if cfg.audience.is_empty()
            || cfg.audience == "https://sts.google.com"
            || cfg.audience.len() > 512
        {
            bail!("cvm root policy requires a custom audience <= 512 bytes");
        }
        if cfg.image_digest.len() != 71
            || !cfg.image_digest.starts_with("sha256:")
            || !cfg.image_digest[7..]
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            bail!("cvm root policy requires pinned sha256 image digest");
        }
        if cfg.project_id.is_empty() || cfg.module_name.is_empty() {
            bail!("cvm root policy project_id and module_name are required");
        }
        if cfg.expected_env.keys().any(|k| k.is_empty())
            || cfg.expected_args.iter().any(|arg| arg.is_empty())
        {
            bail!("cvm root policy environment and args contain empty entries");
        }
        let http = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .context("cvm root JWKS HTTP client")?;
        Ok(Self {
            audience: cfg.audience,
            image_digest: cfg.image_digest,
            project_id: cfg.project_id,
            expected_env: cfg.expected_env,
            expected_args: cfg.expected_args,
            keypair_id: parse_hex32("keypair_id", &cfg.keypair_id)?,
            chain_id: cfg.chain_id,
            module_addr: parse_hex32("module_addr", &cfg.module_addr)?,
            module_name: cfg.module_name,
            account_address: parse_hex32("account_address", &cfg.account_address)?,
            http,
        })
    }

    pub fn validate_payload(&self, payload: &ThresholdVrfRequestPayload) -> Result<()> {
        if payload.keypair_id != self.keypair_id
            || payload.account_address != self.account_address
            || payload.label != ROOT_LABEL
        {
            bail!("cvm root VRF input is not approved");
        }
        match &payload.contract_id {
            ContractId::Aptos(contract)
                if contract.chain_id == self.chain_id
                    && contract.module_addr == self.module_addr
                    && contract.module_name == self.module_name => {}
            _ => bail!("cvm root contract is not approved"),
        }
        match &payload.response_enc_key {
            EncryptionKey::HpkeX25519ChaCha20Poly1305(key) if key.pk.len() == 32 => Ok(()),
            _ => bail!("cvm root response key must be X25519 HPKE with a 32-byte public key"),
        }
    }

    pub async fn verify_attestation(
        &self,
        payload: &ThresholdVrfRequestPayload,
        jwt: &str,
    ) -> Result<()> {
        self.validate_payload(payload)?;
        if jwt.len() > MAX_JWT_BYTES {
            bail!("cvm root attestation token exceeds size limit");
        }
        let response = self
            .http
            .get(JWKS_URL)
            .send()
            .await
            .context("fetch Google Confidential Space JWKS")?
            .error_for_status()
            .context("Google Confidential Space JWKS status")?;
        if response
            .content_length()
            .is_some_and(|n| n > MAX_JWKS_BYTES as u64)
        {
            bail!("Google Confidential Space JWKS exceeds size limit");
        }
        let bytes = response.bytes().await.context("read Google JWKS")?;
        if bytes.len() > MAX_JWKS_BYTES {
            bail!("Google Confidential Space JWKS exceeds size limit");
        }
        let jwks: Value = serde_json::from_slice(&bytes).context("parse Google JWKS")?;
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock before epoch")?
            .as_secs() as i64;
        self.verify_with_jwks(payload, jwt, &jwks, now)
    }

    fn verify_with_jwks(
        &self,
        payload: &ThresholdVrfRequestPayload,
        jwt: &str,
        jwks: &Value,
        now: i64,
    ) -> Result<()> {
        if jwt.len() > MAX_JWT_BYTES {
            bail!("cvm root attestation token exceeds size limit");
        }
        let mut parts = jwt.split('.');
        let (Some(header_b64), Some(claims_b64), Some(sig_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            bail!("invalid attestation JWT structure");
        };
        let header: Value = serde_json::from_slice(&decode_b64url(header_b64)?)?;
        if header.get("alg").and_then(Value::as_str) != Some("RS256")
            || header.get("crit").is_some()
        {
            bail!("attestation JWT must use RS256 without critical extensions");
        }
        let kid = header
            .get("kid")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty() && s.len() <= 256)
            .ok_or_else(|| anyhow!("attestation JWT missing key id"))?;
        let keys = jwks
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| anyhow!("Google JWKS has no keys"))?;
        let matching: Vec<_> = keys
            .iter()
            .filter(|key| key.get("kid").and_then(Value::as_str) == Some(kid))
            .collect();
        if matching.len() != 1 {
            bail!("attestation signing key not uniquely identified");
        }
        let key = matching[0];
        if key.get("kty").and_then(Value::as_str) != Some("RSA")
            || !matches!(key.get("use").and_then(Value::as_str), None | Some("sig"))
            || !matches!(key.get("alg").and_then(Value::as_str), None | Some("RS256"))
        {
            bail!("invalid attestation signing key parameters");
        }
        let n = decode_b64url(
            key.get("n")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("JWK n missing"))?,
        )?;
        let e = decode_b64url(
            key.get("e")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow!("JWK e missing"))?,
        )?;
        if n.len() < 256 || e.is_empty() {
            bail!("weak attestation signing key");
        }
        let signed = format!("{}.{}", header_b64, claims_b64);
        let sig = decode_b64url(sig_b64)?;
        RsaPublicKeyComponents { n: &n, e: &e }
            .verify(&RSA_PKCS1_2048_8192_SHA256, signed.as_bytes(), &sig)
            .map_err(|_| anyhow!("invalid attestation JWT signature"))?;
        let claims: Value = serde_json::from_slice(&decode_b64url(claims_b64)?)?;
        self.check_claims(payload, &claims, now)
    }

    fn check_claims(
        &self,
        payload: &ThresholdVrfRequestPayload,
        claims: &Value,
        now: i64,
    ) -> Result<()> {
        let time = |name: &str| {
            claims
                .get(name)
                .and_then(Value::as_i64)
                .ok_or_else(|| anyhow!("attestation JWT missing numeric {}", name))
        };
        let (iat, nbf, exp) = (time("iat")?, time("nbf")?, time("exp")?);
        if iat > now + CLOCK_SKEW_SECONDS
            || iat < now - MAX_TOKEN_AGE_SECONDS - CLOCK_SKEW_SECONDS
            || nbf > now + CLOCK_SKEW_SECONDS
            || exp <= now
            || !(iat <= nbf && nbf <= exp)
        {
            bail!("attestation JWT is stale or not yet valid");
        }
        if claims.get("iss").and_then(Value::as_str) != Some(ISSUER)
            || claims.get("aud").and_then(Value::as_str) != Some(&self.audience)
        {
            bail!("attestation issuer or audience mismatch");
        }
        let nonce = attestation_nonce(payload)?;
        let eat_nonce = claims.get("eat_nonce");
        if eat_nonce.and_then(Value::as_str) != Some(&nonce)
            && eat_nonce
                .and_then(Value::as_array)
                .filter(|arr| arr.len() == 1)
                .and_then(|arr| arr[0].as_str())
                != Some(&nonce)
        {
            bail!("attestation nonce does not bind CVM root request");
        }
        if claims.get("swname").and_then(Value::as_str) != Some("CONFIDENTIAL_SPACE")
            || claims.get("dbgstat").and_then(Value::as_str) != Some("disabled-since-boot")
            || claims.get("hwmodel").and_then(Value::as_str) != Some("GCP_INTEL_TDX")
            || claims.get("secboot").and_then(Value::as_bool) != Some(true)
            || claims.get("attester_tcb") != Some(&serde_json::json!(["INTEL"]))
        {
            bail!("attestation is not an approved production TDX CVM");
        }
        let submods = claims
            .get("submods")
            .ok_or_else(|| anyhow!("attestation has no submods"))?;
        let memory_monitoring = submods
            .pointer("/confidential_space/monitoring_enabled/memory")
            .and_then(Value::as_bool);
        if memory_monitoring != Some(false) {
            bail!("Confidential Space memory monitoring must be disabled");
        }
        let container = submods
            .get("container")
            .ok_or_else(|| anyhow!("attestation has no container"))?;
        if container.get("image_digest").and_then(Value::as_str) != Some(&self.image_digest) {
            bail!("CVM image digest not approved");
        }
        let env_override_ok = match container.get("env_override") {
            None | Some(Value::Null) => true,
            Some(Value::Object(overrides)) => overrides.iter().all(|(name, value)| {
                value.as_str().is_some_and(|v| {
                    self.expected_env
                        .get(name)
                        .is_some_and(|expected| expected == v)
                })
            }),
            _ => false,
        };
        let cmd_override_ok = matches!(container.get("cmd_override"), None | Some(Value::Null))
            || container.get("cmd_override") == Some(&serde_json::json!([]));
        if container.get("env") != Some(&serde_json::to_value(&self.expected_env)?)
            || container.get("args") != Some(&serde_json::to_value(&self.expected_args)?)
            || !env_override_ok
            || !cmd_override_ok
        {
            bail!("CVM runtime configuration not approved");
        }
        if submods.pointer("/gce/project_id").and_then(Value::as_str) != Some(&self.project_id) {
            bail!("CVM GCP project not approved");
        }
        Ok(())
    }
}

fn decode_b64url(input: &str) -> Result<Vec<u8>> {
    let bytes = URL_SAFE_NO_PAD
        .decode(input)
        .context("invalid JWT base64url encoding")?;
    if URL_SAFE_NO_PAD.encode(&bytes) != input {
        bail!("noncanonical JWT base64url encoding");
    }
    Ok(bytes)
}

/// The guest passes this 43-character string to the launcher as its sole
/// custom nonce. The BCS payload includes the response key, so substituting
/// an attacker-owned key invalidates the signed token.
pub fn attestation_nonce(payload: &ThresholdVrfRequestPayload) -> Result<String> {
    let mut hash = Sha256::new();
    hash.update(NONCE_DOMAIN);
    hash.update(bcs::to_bytes(payload)?);
    Ok(URL_SAFE_NO_PAD.encode(hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::verify::{AptosContractId, CvmRootVrfRequest, WorkerRequest};
    use openssl::{hash::MessageDigest, pkey::PKey, rsa::Rsa, sign::Signer};
    use vss_common::pke_hpke_x25519_chacha20poly1305 as hpke;

    fn policy() -> CvmRootPolicy {
        let json = serde_json::json!({
            "audience": "ace-c26t-cvm-root-v1",
            "image_digest": format!("sha256:{}", "a".repeat(64)),
            "project_id": "test-project",
            "expected_env": {"MODE": "test"},
            "expected_args": ["serve"],
            "keypair_id": hex::encode([1u8; 32]),
            "chain_id": 119,
            "module_addr": hex::encode([2u8; 32]),
            "module_name": "c26t_vault",
            "account_address": hex::encode([3u8; 32]),
        });
        CvmRootPolicy::from_json(&json.to_string()).unwrap()
    }

    fn sample_payload() -> ThresholdVrfRequestPayload {
        ThresholdVrfRequestPayload {
            keypair_id: [1u8; 32],
            epoch: 7,
            contract_id: ContractId::Aptos(AptosContractId {
                chain_id: 119,
                module_addr: [2u8; 32],
                module_name: "c26t_vault".to_string(),
            }),
            label: ROOT_LABEL.to_vec(),
            account_address: [3u8; 32],
            response_enc_key: EncryptionKey::HpkeX25519ChaCha20Poly1305(hpke::EncryptionKey {
                pk: vec![4u8; 32],
            }),
        }
    }

    fn claims(payload: &ThresholdVrfRequestPayload, now: i64) -> Value {
        serde_json::json!({
            "iss": ISSUER,
            "aud": "ace-c26t-cvm-root-v1",
            "iat": now - 10,
            "nbf": now - 10,
            "exp": now + 60,
            "eat_nonce": [attestation_nonce(payload).unwrap()],
            "swname": "CONFIDENTIAL_SPACE",
            "dbgstat": "disabled-since-boot",
            "hwmodel": "GCP_INTEL_TDX",
            "secboot": true,
            "attester_tcb": ["INTEL"],
            "submods": {
                "confidential_space": {"monitoring_enabled": {"memory": false}},
                "container": {
                    "image_digest": format!("sha256:{}", "a".repeat(64)),
                    "env": {"MODE": "test"},
                    "args": ["serve"],
                    "env_override": {},
                    "cmd_override": []
                },
                "gce": {"project_id": "test-project"}
            }
        })
    }

    fn signed_jwt(claims: &Value) -> (String, Value) {
        let rsa = Rsa::generate(2048).unwrap();
        let n = URL_SAFE_NO_PAD.encode(rsa.n().to_vec());
        let e = URL_SAFE_NO_PAD.encode(rsa.e().to_vec());
        let key = PKey::from_rsa(rsa).unwrap();
        let header = serde_json::json!({"alg": "RS256", "kid": "test-key"});
        let signed = format!(
            "{}.{}",
            URL_SAFE_NO_PAD.encode(header.to_string()),
            URL_SAFE_NO_PAD.encode(claims.to_string()),
        );
        let mut signer = Signer::new(MessageDigest::sha256(), &key).unwrap();
        signer.update(signed.as_bytes()).unwrap();
        let sig = signer.sign_to_vec().unwrap();
        let jwt = format!("{}.{}", signed, URL_SAFE_NO_PAD.encode(sig));
        (
            jwt,
            serde_json::json!({"keys": [{"kid":"test-key", "kty":"RSA", "alg":"RS256", "use":"sig", "n":n, "e":e}]}),
        )
    }

    #[test]
    fn valid_signed_attestation_binds_exact_response_key() {
        let now = 1_800_000_000;
        let policy = policy();
        let payload = sample_payload();
        let (jwt, jwks) = signed_jwt(&claims(&payload, now));
        policy.verify_with_jwks(&payload, &jwt, &jwks, now).unwrap();

        let mut changed = sample_payload();
        changed.response_enc_key =
            EncryptionKey::HpkeX25519ChaCha20Poly1305(hpke::EncryptionKey { pk: vec![5u8; 32] });
        assert!(policy.verify_with_jwks(&changed, &jwt, &jwks, now).is_err());
        assert!(policy
            .verify_with_jwks(&payload, &jwt, &jwks, now + 400)
            .is_err());
    }

    #[test]
    fn forged_signature_and_unapproved_workload_fail_closed() {
        let now = 1_800_000_000;
        let policy = policy();
        let payload = sample_payload();
        let (jwt, jwks) = signed_jwt(&claims(&payload, now));
        let mut forged = jwt.into_bytes();
        *forged.last_mut().unwrap() = b'A';
        assert!(policy
            .verify_with_jwks(&payload, std::str::from_utf8(&forged).unwrap(), &jwks, now)
            .is_err());

        let mut unapproved = claims(&payload, now);
        unapproved["submods"]["container"]["image_digest"] =
            Value::String(format!("sha256:{}", "b".repeat(64)));
        let (jwt, jwks) = signed_jwt(&unapproved);
        assert!(policy.verify_with_jwks(&payload, &jwt, &jwks, now).is_err());
    }

    #[test]
    fn root_input_and_wire_tag_are_separate_from_user_vrf() {
        let policy = policy();
        let payload = sample_payload();
        policy.validate_payload(&payload).unwrap();
        let root = WorkerRequest::CvmRootVrf(CvmRootVrfRequest {
            payload,
            attestation_jwt: "test.jwt".to_string(),
        });
        let bytes = bcs::to_bytes(&root).unwrap();
        assert_eq!(bytes[0], 4);
        assert_eq!(&bytes[1..33], &[1u8; 32]);
        assert_eq!(
            hex::encode(&bytes),
            format!(
                "04{}07000000000000000077{}0a633236745f7661756c740c633236742f726f6f742f7631{}0120{}08746573742e6a7774",
                "01".repeat(32),
                "02".repeat(32),
                "03".repeat(32),
                "04".repeat(32),
            )
        );
        assert_eq!(
            attestation_nonce(&sample_payload()).unwrap(),
            "V5aLE5kkgTxD2AaOrc1IoUbpslJFUPfsnprk0tJUqCU"
        );

        let mut changed = sample_payload();
        changed.label = b"other".to_vec();
        assert!(policy.validate_payload(&changed).is_err());
        changed = sample_payload();
        changed.epoch += 1;
        policy.validate_payload(&changed).unwrap();
    }
}
