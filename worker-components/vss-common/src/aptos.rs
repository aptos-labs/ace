// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::Signer;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;

use crate::session::Session;

/// Process-global nonce counter for orderless transactions.
/// Seeded from the current time in nanoseconds so that separate OS processes
/// (e.g. dkr-src and dkr-dst running as the same account) start at different offsets
/// and don't collide.
fn txn_nonce() -> &'static AtomicU64 {
    static TXN_NONCE: OnceLock<AtomicU64> = OnceLock::new();
    TXN_NONCE.get_or_init(|| {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(1);
        AtomicU64::new(seed)
    })
}

#[derive(Clone)]
pub struct AptosRpc {
    pub base_url: String,
    client: reqwest::Client,
}

#[derive(Deserialize)]
pub struct AccountInfo {
    pub sequence_number: String,
    pub authentication_key: String,
}

pub fn json_move_vec_u8_hex(bytes: &[u8]) -> Value {
    Value::String(format!("0x{}", hex::encode(bytes)))
}

impl AptosRpc {
    pub fn new(base_url: String) -> Self {
        Self::new_with_key(base_url, None)
    }

    pub fn new_with_key(base_url: String, api_key: Option<String>) -> Self {
        let mut builder = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30));
        if let Some(key) = api_key {
            let mut headers = reqwest::header::HeaderMap::new();
            let mut val = reqwest::header::HeaderValue::from_str(&format!("Bearer {}", key))
                .expect("api_key contains invalid header characters");
            val.set_sensitive(true);
            headers.insert(reqwest::header::AUTHORIZATION, val);
            builder = builder.default_headers(headers);
        }
        let client = builder.build().unwrap();
        Self { base_url, client }
    }

    pub async fn get_chain_id(&self) -> Result<u8> {
        let url = self.base_url.trim_end_matches('/');
        let resp = self.client.get(url).send().await?;
        if !resp.status().is_success() {
            let body = resp.text().await?;
            return Err(anyhow!("ledger info GET failed: {}", body));
        }
        let v: Value = resp.json().await?;
        let id = v["chain_id"]
            .as_u64()
            .ok_or_else(|| anyhow!("missing chain_id in ledger info"))?;
        Ok(id as u8)
    }

    pub async fn get_ledger_timestamp_micros(&self) -> Result<u64> {
        let url = self.base_url.trim_end_matches('/');
        let resp = self.client.get(url).send().await?;
        if !resp.status().is_success() {
            let body = resp.text().await?;
            return Err(anyhow!("ledger info GET failed: {}", body));
        }
        let v: Value = resp.json().await?;
        let s = v["ledger_timestamp"]
            .as_str()
            .ok_or_else(|| anyhow!("missing ledger_timestamp"))?;
        s.parse::<u64>()
            .with_context(|| format!("parse ledger_timestamp {:?}", s))
    }

    /// Fetch `ace::vss::Session` at `session_addr` (published under `ace_contract` module address).
    pub async fn get_vss_session_resource(
        &self,
        ace_contract: &str,
        session_addr: &str,
    ) -> Result<Session> {
        let ace = ace_contract.trim();
        let sess = session_addr.trim();
        let url = format!(
            "{}/accounts/{}/resource/{}::vss::Session",
            self.base_url.trim_end_matches('/'),
            sess,
            ace
        );
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            let body = resp.text().await?;
            return Err(anyhow!("get Session resource failed: {}", body));
        }
        let v: Value = resp.json().await?;
        Session::try_from_resource_json(&v)
    }

    pub async fn get_account(&self, addr: &str) -> Result<AccountInfo> {
        let url = format!(
            "{}/accounts/{}",
            self.base_url.trim_end_matches('/'),
            addr.trim()
        );
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            let body = resp.text().await?;
            return Err(anyhow!("get_account failed: {}", body));
        }
        Ok(resp.json::<AccountInfo>().await?)
    }

    pub async fn submit_txn(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
        verifying_key: &ed25519_dalek::VerifyingKey,
        sender_addr: &str,
        function: &str,
        type_args: &[&str],
        args: &[Value],
    ) -> Result<String> {
        // Orderless transaction: unique nonce instead of sequence number.
        // Multiple concurrent submissions from the same account are safe.
        let nonce = txn_nonce().fetch_add(1, Ordering::Relaxed);

        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60; // orderless transactions have a max 60s replay window

        let arg_array = Value::Array(args.iter().cloned().collect());
        let type_arguments = Value::Array(
            type_args
                .iter()
                .map(|t| Value::String((*t).to_string()))
                .collect(),
        );

        let mut payload = Map::new();
        payload.insert("type".to_string(), json!("entry_function_payload"));
        payload.insert("function".to_string(), Value::String(function.to_string()));
        payload.insert("type_arguments".to_string(), type_arguments);
        payload.insert("arguments".to_string(), arg_array);

        let mut txn_body = Map::new();
        txn_body.insert(
            "sender".to_string(),
            Value::String(sender_addr.trim().to_string()),
        );
        txn_body.insert("sequence_number".to_string(), Value::String("0".to_string()));
        txn_body.insert("replay_protection_nonce".to_string(), Value::String(nonce.to_string()));
        txn_body.insert(
            "max_gas_amount".to_string(),
            Value::String("200000".to_string()),
        );
        txn_body.insert(
            "gas_unit_price".to_string(),
            Value::String("100".to_string()),
        );
        txn_body.insert(
            "expiration_timestamp_secs".to_string(),
            Value::String(expiry.to_string()),
        );
        txn_body.insert("payload".to_string(), Value::Object(payload));
        let txn_body = Value::Object(txn_body);

        let encode_url = format!(
            "{}/transactions/encode_submission",
            self.base_url.trim_end_matches('/')
        );
        let encode_resp = self.client.post(&encode_url).json(&txn_body).send().await?;
        if !encode_resp.status().is_success() {
            let body = encode_resp.text().await?;
            return Err(anyhow!("encode_submission failed: {}", body));
        }
        let signing_msg_hex: String = encode_resp.json().await?;
        let signing_bytes = hex::decode(signing_msg_hex.trim_start_matches("0x"))?;

        let sig = signing_key.sign(&signing_bytes);

        let submit_url = format!("{}/transactions", self.base_url.trim_end_matches('/'));
        let mut submit_body = txn_body.clone();
        submit_body.as_object_mut().unwrap().insert(
            "signature".to_string(),
            json!({
                "type": "ed25519_signature",
                "public_key": format!("0x{}", hex::encode(verifying_key.as_bytes())),
                "signature": format!("0x{}", hex::encode(sig.to_bytes()))
            }),
        );

        let submit_resp = self.client.post(&submit_url).json(&submit_body).send().await?;
        if !submit_resp.status().is_success() {
            let body = submit_resp.text().await?;
            return Err(anyhow!("submit transaction failed: {}", body));
        }
        let result: Value = submit_resp.json().await?;
        let hash = result["hash"]
            .as_str()
            .ok_or_else(|| anyhow!("no hash in transaction response"))?
            .to_string();

        self.wait_for_txn(&hash).await?;
        Ok(hash)
    }

    /// Fetch and BCS-decode the full VSS session via the `get_session_bcs` view function.
    pub async fn get_session_bcs_decoded(
        &self,
        ace: &str,
        session_addr: &str,
    ) -> Result<crate::session::BcsSession> {
        let result = self
            .call_view(
                &format!("{}::vss::get_session_bcs", ace),
                &[serde_json::json!(session_addr)],
            )
            .await?;
        let hex = result
            .first()
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("expected string in get_session_bcs result"))?;
        let bytes = hex::decode(hex.trim_start_matches("0x"))?;
        bcs::from_bytes(&bytes).map_err(|e| anyhow!("bcs decode BcsSession: {}", e))
    }

    /// Fetch the inner `data` object of an Aptos resource at `(addr, resource_type)`.
    pub async fn get_resource_data(&self, addr: &str, resource_type: &str) -> Result<Value> {
        let url = format!(
            "{}/accounts/{}/resource/{}",
            self.base_url.trim_end_matches('/'),
            addr.trim(),
            resource_type
        );
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            let body = resp.text().await?;
            return Err(anyhow!("get resource '{}' failed: {}", resource_type, body));
        }
        let v: Value = resp.json().await?;
        Ok(v.get("data").cloned().unwrap_or(v))
    }

    /// Call a Move view function and return the JSON response values.
    pub async fn call_view(&self, function: &str, args: &[Value]) -> Result<Vec<Value>> {
        let url = format!("{}/view", self.base_url.trim_end_matches('/'));
        let body = json!({
            "function": function,
            "type_arguments": [],
            "arguments": args
        });
        let resp = self.client.post(&url).json(&body).send().await?;
        if !resp.status().is_success() {
            let body_text = resp.text().await?;
            return Err(anyhow!("view call failed: {}", body_text));
        }
        Ok(resp.json::<Vec<Value>>().await?)
    }

    /// Fetch a worker's PKE encryption key via the `get_pke_enc_key_bcs` view function.
    pub async fn get_pke_enc_key_bcs(
        &self,
        ace: &str,
        worker_addr: &str,
    ) -> Result<crate::pke::EncryptionKey> {
        let result = self
            .call_view(
                &format!("{}::worker_config::get_pke_enc_key_bcs", ace),
                &[json!(worker_addr)],
            )
            .await?;
        let hex = result
            .first()
            .and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("expected string in view result"))?;
        let bytes = hex::decode(hex.trim_start_matches("0x"))?;
        crate::pke::EncryptionKey::from_bytes(&bytes)
    }

    pub async fn wait_for_txn(&self, hash: &str) -> Result<()> {
        let url = format!(
            "{}/transactions/by_hash/{}",
            self.base_url.trim_end_matches('/'),
            hash
        );
        for _ in 0..60 {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            let resp = self.client.get(&url).send().await;
            if let Ok(r) = resp {
                if r.status().is_success() {
                    let v: Value = r.json().await?;
                    let success = v["success"].as_bool().unwrap_or(false);
                    let pending = v["type"]
                        .as_str()
                        .map(|t| t == "pending_transaction")
                        .unwrap_or(false);
                    if !pending {
                        if success {
                            return Ok(());
                        }
                        let vm_status = v["vm_status"].as_str().unwrap_or("unknown");
                        return Err(anyhow!("transaction failed: {}", vm_status));
                    }
                }
            }
        }
        Err(anyhow!("timeout waiting for transaction {}", hash))
    }
}
