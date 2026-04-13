// Aptos REST API client

use anyhow::{anyhow, Context, Result};
use serde::Deserialize;
use serde_json::{json, Map, Value};

// ── High-level summary returned by get_network_state_summary() ───────────────

#[derive(Debug, Clone)]
pub struct NetworkStateSummary {
    pub epoch: u64,
    pub workers: Vec<String>,
    pub next_epoch_workers: Vec<String>,
    pub active_secrets: Vec<String>,  // Secret Object addresses
    pub dkg_sessions: Vec<String>,    // in-progress DkgSession addresses
    pub dkr_sessions: Vec<String>,    // in-progress DkrSession addresses
}

#[derive(Debug, Clone)]
pub struct DkgSessionInfo {
    pub epoch: u64,
    pub status: u8,
    pub vss_sessions: Vec<String>,
    pub contributors: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct DkrSessionInfo {
    pub epoch: u64,
    pub new_nodes: Vec<String>,
    pub new_threshold: u64,
    pub old_threshold: u64,
    pub status: u8,
    pub vss_sessions: Vec<String>,
    pub resharing_counts: Vec<u64>,
    pub n_secrets: u64,
    pub secret_addrs: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct VssSessionInfo {
    pub parent: String,
    pub dealer: String,
    pub dealer_index: u64,
    pub secret_idx: u64,
    pub contribution: Vec<u8>,
    pub status: u8,
}

#[derive(Clone)]
pub struct AptosRpc {
    pub base_url: String,
    client: reqwest::Client,
}

/// Encode `vector<u8>` for REST `/transactions/encode_submission` JSON payloads as a JSON array of u8.
pub fn json_move_vec_u8(bytes: &[u8]) -> Value {
    Value::Array(
        bytes
            .iter()
            .map(|b| Value::Number((*b).into()))
            .collect(),
    )
}

/// Same as [`json_move_vec_u8`] but as a single `0x` hex string (required by some REST encode paths).
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

        let arg_array = Value::Array(args.iter().cloned().collect());
        let type_arguments = Value::Array(
            type_args
                .iter()
                .map(|t| Value::String((*t).to_string()))
                .collect(),
        );

        // Build JSON explicitly: `serde_json::json!` + nested `Value` interpolation has
        // been observed to drop `payload.arguments` entries against localnet encode API.
        let mut payload = Map::new();
        payload.insert("type".to_string(), json!("entry_function_payload"));
        payload.insert("function".to_string(), Value::String(function.to_string()));
        payload.insert("type_arguments".to_string(), type_arguments);
        payload.insert("arguments".to_string(), arg_array);

        let mut txn_body = Map::new();
        txn_body.insert("sender".to_string(), Value::String(sender_addr.to_string()));
        txn_body.insert("sequence_number".to_string(), Value::String(seq.to_string()));
        txn_body.insert("max_gas_amount".to_string(), Value::String("200000".to_string()));
        txn_body.insert("gas_unit_price".to_string(), Value::String("100".to_string()));
        txn_body.insert(
            "expiration_timestamp_secs".to_string(),
            Value::String(expiry.to_string()),
        );
        txn_body.insert("payload".to_string(), Value::Object(payload));
        let txn_body = Value::Object(txn_body);

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

    // ── High-level view helpers ───────────────────────────────────────────────

    /// Fetch all worker-relevant state in one view call.
    pub async fn get_network_state_summary(
        &self,
        contract_addr: &str,
    ) -> Result<NetworkStateSummary> {
        let vals = self
            .view(
                &format!("{}::ace_network::get_network_state_summary", contract_addr),
                &[],
                &[json!(contract_addr)],
            )
            .await?;
        // Returns a single struct value; the REST API serialises Move structs as objects.
        let obj = vals
            .get(0)
            .ok_or_else(|| anyhow!("empty summary response"))?;
        Ok(NetworkStateSummary {
            epoch: obj["epoch"].as_str().and_then(|s| s.parse().ok()).unwrap_or(0),
            workers: parse_addr_vec(&obj["workers"]),
            next_epoch_workers: parse_addr_vec(&obj["next_epoch_workers"]),
            active_secrets: parse_addr_vec(&obj["active_secrets"]),
            dkg_sessions: parse_addr_vec(&obj["dkg_sessions"]),
            dkr_sessions: parse_addr_vec(&obj["dkr_sessions"]),
        })
    }

    pub async fn get_dkg_session(&self, contract_addr: &str, session_addr: &str) -> Result<DkgSessionInfo> {
        let vals = self
            .view(
                &format!("{}::ace_network::get_dkg_session", contract_addr),
                &[],
                &[json!(session_addr)],
            )
            .await?;
        Ok(DkgSessionInfo {
            epoch: parse_u64(&vals, 0),
            status: vals.get(1).and_then(|v| v.as_u64()).unwrap_or(0) as u8,
            vss_sessions: vals.get(2).map(parse_addr_vec).unwrap_or_default(),
            contributors: vals.get(3).map(parse_addr_vec).unwrap_or_default(),
        })
    }

    pub async fn get_dkr_session(&self, contract_addr: &str, session_addr: &str) -> Result<DkrSessionInfo> {
        let vals = self
            .view(
                &format!("{}::ace_network::get_dkr_session", contract_addr),
                &[],
                &[json!(session_addr)],
            )
            .await?;
        let secret_addrs = self
            .view(
                &format!("{}::ace_network::get_dkr_secret_addrs", contract_addr),
                &[],
                &[json!(session_addr)],
            )
            .await
            .unwrap_or_default();
        Ok(DkrSessionInfo {
            epoch: parse_u64(&vals, 0),
            new_nodes: vals.get(1).map(parse_addr_vec).unwrap_or_default(),
            new_threshold: parse_u64(&vals, 2),
            old_threshold: parse_u64(&vals, 3),
            status: vals.get(4).and_then(|v| v.as_u64()).unwrap_or(0) as u8,
            vss_sessions: vals.get(5).map(parse_addr_vec).unwrap_or_default(),
            resharing_counts: vals
                .get(6)
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().and_then(|s| s.parse().ok()))
                        .collect()
                })
                .unwrap_or_default(),
            n_secrets: parse_u64(&vals, 7),
            secret_addrs: secret_addrs.get(0).map(parse_addr_vec).unwrap_or_default(),
        })
    }

    pub async fn get_vss_session(&self, contract_addr: &str, session_addr: &str) -> Result<VssSessionInfo> {
        let vals = self
            .view(
                &format!("{}::vss::get_vss_session", contract_addr),
                &[],
                &[json!(session_addr)],
            )
            .await?;
        let contribution = parse_move_byte_vec(vals.get(4));
        Ok(VssSessionInfo {
            parent: vals.get(0).and_then(|v| v.as_str()).unwrap_or("").to_lowercase(),
            dealer: vals.get(1).and_then(|v| v.as_str()).unwrap_or("").to_lowercase(),
            dealer_index: parse_u64(&vals, 2),
            secret_idx: parse_u64(&vals, 3),
            contribution,
            status: vals.get(5).and_then(|v| v.as_u64()).unwrap_or(0) as u8,
        })
    }

    pub async fn get_dealer_escrow(&self, contract_addr: &str, vss_session_addr: &str) -> Result<Vec<u8>> {
        let vals = self
            .view(
                &format!("{}::vss::get_dealer_escrow", contract_addr),
                &[],
                &[json!(vss_session_addr)],
            )
            .await?;
        Ok(parse_move_byte_vec(vals.get(0)))
    }

    /// Fetch the encrypted share posted for `recipient` in a VssSession.
    /// Returns empty vec if not yet posted.
    pub async fn get_encrypted_share(
        &self,
        vss_session_addr: &str,
        recipient: &str,
        contract_addr: &str,
    ) -> Result<Vec<u8>> {
        let vals = self
            .view(
                &format!("{}::vss::get_encrypted_share", contract_addr),
                &[],
                &[json!(vss_session_addr), json!(recipient)],
            )
            .await?;
        Ok(parse_move_byte_vec(vals.get(0)))
    }

    /// Fetch a node's BLS12-381 encryption public key (48-byte compressed G1).
    pub async fn get_node_encryption_pk(
        &self,
        contract_addr: &str,
        node_addr: &str,
    ) -> Result<Vec<u8>> {
        let vals = self
            .view(
                &format!("{}::ace_network::get_node_encryption_pk", contract_addr),
                &[],
                &[json!(contract_addr), json!(node_addr)],
            )
            .await?;
        let hex_str = vals
            .get(0)
            .and_then(|v| v.as_str())
            .unwrap_or("0x");
        Ok(hex::decode(hex_str.trim_start_matches("0x")).unwrap_or_default())
    }

    /// Fetch (mpk_bytes, source_session_addr) for a Secret Object.
    pub async fn get_secret(&self, contract_addr: &str, secret_addr: &str) -> Result<(Vec<u8>, String)> {
        let vals = self
            .view(
                &format!("{}::ace_network::get_secret", contract_addr),
                &[],
                &[json!(secret_addr)],
            )
            .await?;
        let mpk_hex = vals.get(0).and_then(|v| v.as_str()).unwrap_or("0x");
        let mpk = hex::decode(mpk_hex.trim_start_matches("0x")).unwrap_or_default();
        let source = vals.get(3).and_then(|v| v.as_str()).unwrap_or("").to_lowercase();
        Ok((mpk, source))
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

// ── Private helpers ───────────────────────────────────────────────────────────

fn parse_addr_vec(v: &Value) -> Vec<String> {
    v.as_array()
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_u64(vals: &[Value], idx: usize) -> u64 {
    vals.get(idx)
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Parse `vector<u8>` from a Move view (hex string or JSON number array).
fn parse_move_byte_vec(v: Option<&Value>) -> Vec<u8> {
    let Some(v) = v else {
        return Vec::new();
    };
    if let Some(s) = v.as_str() {
        return hex::decode(s.trim_start_matches("0x")).unwrap_or_default();
    }
    if let Some(arr) = v.as_array() {
        return arr
            .iter()
            .filter_map(|x| x.as_u64().map(|n| n as u8))
            .collect();
    }
    Vec::new()
}
