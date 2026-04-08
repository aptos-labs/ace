// Aptos REST API client

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};

#[derive(Clone)]
pub struct AptosRpc {
    pub base_url: String,
    client: reqwest::Client,
}

impl AptosRpc {
    pub fn new(base_url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .unwrap();
        Self { base_url, client }
    }

    /// GET /accounts/{address}
    pub async fn get_account(&self, addr: &str) -> Result<AccountInfo> {
        let url = format!("{}/accounts/{}", self.base_url, addr);
        let resp = self.client.get(&url).send().await?;
        if !resp.status().is_success() {
            let body = resp.text().await?;
            return Err(anyhow!("get_account failed: {}", body));
        }
        Ok(resp.json::<AccountInfo>().await?)
    }

    /// POST /view — call a view function
    pub async fn view(&self, function: &str, type_args: &[&str], args: &[Value]) -> Result<Vec<Value>> {
        let url = format!("{}/view", self.base_url);
        let body = json!({
            "function": function,
            "type_arguments": type_args,
            "arguments": args
        });
        let resp = self.client.post(&url).json(&body).send().await?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await?;
            return Err(anyhow!("view call failed ({}): {}", status, text));
        }
        Ok(resp.json::<Vec<Value>>().await?)
    }

    /// Submit a signed transaction using the JSON API
    pub async fn submit_txn(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
        verifying_key: &ed25519_dalek::VerifyingKey,
        sender_addr: &str,
        function: &str,
        type_args: &[&str],
        args: &[Value],
    ) -> Result<String> {
        use ed25519_dalek::Signer;

        // 1. Get sequence number
        let account = self.get_account(sender_addr).await
            .with_context(|| format!("getting account for {}", sender_addr))?;
        let seq = account.sequence_number.parse::<u64>()
            .unwrap_or(0);

        // 2. Build expiry timestamp
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 600;

        let txn_body = json!({
            "sender": sender_addr,
            "sequence_number": seq.to_string(),
            "max_gas_amount": "200000",
            "gas_unit_price": "100",
            "expiration_timestamp_secs": expiry.to_string(),
            "payload": {
                "type": "entry_function_payload",
                "function": function,
                "type_arguments": type_args,
                "arguments": args
            }
        });

        // 3. Encode for signing (do NOT add secondary_signers — that triggers multi-agent signing)
        let encode_url = format!("{}/transactions/encode_submission", self.base_url);
        let encode_resp = self.client.post(&encode_url).json(&txn_body).send().await?;
        if !encode_resp.status().is_success() {
            let body = encode_resp.text().await?;
            return Err(anyhow!("encode_submission failed: {}", body));
        }
        let signing_msg_hex: String = encode_resp.json::<String>().await?;
        let signing_bytes = hex::decode(signing_msg_hex.trim_start_matches("0x"))?;

        // 4. Sign
        let sig = signing_key.sign(&signing_bytes);

        // 5. Submit
        let submit_url = format!("{}/transactions", self.base_url);
        let mut submit_body = txn_body.clone();
        submit_body.as_object_mut().unwrap().insert("signature".to_string(), json!({
            "type": "ed25519_signature",
            "public_key": format!("0x{}", hex::encode(verifying_key.as_bytes())),
            "signature": format!("0x{}", hex::encode(sig.to_bytes()))
        }));

        let submit_resp = self.client.post(&submit_url).json(&submit_body).send().await?;
        if !submit_resp.status().is_success() {
            let body = submit_resp.text().await?;
            return Err(anyhow!("submit transaction failed: {}", body));
        }
        let result: Value = submit_resp.json().await?;
        let hash = result["hash"].as_str()
            .ok_or_else(|| anyhow!("no hash in transaction response"))?
            .to_string();

        // 6. Wait for transaction
        self.wait_for_txn(&hash).await?;
        Ok(hash)
    }

    pub async fn wait_for_txn(&self, hash: &str) -> Result<()> {
        let url = format!("{}/transactions/by_hash/{}", self.base_url, hash);
        for _ in 0..60 {
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
            let resp = self.client.get(&url).send().await;
            if let Ok(r) = resp {
                if r.status().is_success() {
                    let v: Value = r.json().await?;
                    let success = v["success"].as_bool().unwrap_or(false);
                    let pending = v["type"].as_str().map(|t| t == "pending_transaction").unwrap_or(false);
                    if !pending {
                        if success {
                            return Ok(());
                        } else {
                            let vm_status = v["vm_status"].as_str().unwrap_or("unknown");
                            return Err(anyhow!("transaction failed: {}", vm_status));
                        }
                    }
                }
            }
        }
        Err(anyhow!("timeout waiting for transaction {}", hash))
    }
}

#[derive(Deserialize)]
pub struct AccountInfo {
    pub sequence_number: String,
    pub authentication_key: String,
}
