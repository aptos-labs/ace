// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::Signer;
use serde::Deserialize;
use serde_json::{json, Map, Value};

use crate::session::Session;

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
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap();
        Self { base_url, client }
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
        let account = self
            .get_account(sender_addr)
            .await
            .with_context(|| format!("getting account for {}", sender_addr))?;
        let seq = account.sequence_number.parse::<u64>().unwrap_or(0);

        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;

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
        txn_body.insert("sequence_number".to_string(), Value::String(seq.to_string()));
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
