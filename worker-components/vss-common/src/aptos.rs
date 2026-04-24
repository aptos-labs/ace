// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::Signer;
use serde::Deserialize;
use serde_json::{json, Map, Value};
use sha3::{Digest, Sha3_256};
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

// ── TxnArg ───────────────────────────────────────────────────────────────────

/// Typed entry-function argument.
///
/// Used by both the REST API path (JSON) and the gas-station path (BCS).
pub enum TxnArg<'a> {
    /// An Aptos `address` — hex string with optional `0x` prefix.
    Address(&'a str),
    /// A Move `vector<u8>` — raw bytes.
    Bytes(&'a [u8]),
}

impl<'a> TxnArg<'a> {
    fn to_json(&self) -> Value {
        match self {
            TxnArg::Address(s) => json!(s),
            TxnArg::Bytes(b) => Value::String(format!("0x{}", hex::encode(b))),
        }
    }

    /// BCS encoding of the Move value itself (without the entry-function length prefix).
    fn bcs_inner(&self) -> Result<Vec<u8>> {
        match self {
            TxnArg::Address(s) => Ok(parse_addr(s)?.to_vec()),
            TxnArg::Bytes(b) => {
                let mut buf = Vec::new();
                write_bcs_bytes(&mut buf, b);
                Ok(buf)
            }
        }
    }
}

// ── BCS helpers ───────────────────────────────────────────────────────────────

fn write_uleb128(buf: &mut Vec<u8>, mut n: u64) {
    loop {
        let byte = (n & 0x7f) as u8;
        n >>= 7;
        if n != 0 {
            buf.push(byte | 0x80);
        } else {
            buf.push(byte);
            break;
        }
    }
}

/// Write `bytes` as a BCS byte vector: ULEB128(len) + raw bytes.
fn write_bcs_bytes(buf: &mut Vec<u8>, bytes: &[u8]) {
    write_uleb128(buf, bytes.len() as u64);
    buf.extend_from_slice(bytes);
}

fn write_bcs_str(buf: &mut Vec<u8>, s: &str) {
    write_bcs_bytes(buf, s.as_bytes());
}

/// Parse a hex address string (`0x`-optional) into a 32-byte big-endian array.
fn parse_addr(addr: &str) -> Result<[u8; 32]> {
    let hex = addr.trim_start_matches("0x");
    let bytes = hex::decode(hex).map_err(|e| anyhow!("address decode '{}': {}", addr, e))?;
    if bytes.len() > 32 {
        return Err(anyhow!("address too long ({} bytes): {}", bytes.len(), addr));
    }
    let mut out = [0u8; 32];
    out[32 - bytes.len()..].copy_from_slice(&bytes);
    Ok(out)
}

// ── BCS transaction serialization ─────────────────────────────────────────────

/// BCS-serialize an orderless entry-function `TransactionPayload`.
///
/// Produces: Payload(4) + V1(0) + EntryFunction(1) + EntryFunction body + ExtraConfigV1
fn serialize_orderless_entry_fn_payload(
    function: &str,
    args: &[TxnArg<'_>],
    nonce: u64,
) -> Result<Vec<u8>> {
    let mut buf = Vec::new();

    // TransactionPayload::Payload = 4
    write_uleb128(&mut buf, 4);
    // TransactionInnerPayload::V1 = 0
    write_uleb128(&mut buf, 0);
    // TransactionExecutable::EntryFunction = 1
    write_uleb128(&mut buf, 1);

    // Parse "0xaddr::module::function"
    let parts: Vec<&str> = function.splitn(3, "::").collect();
    if parts.len() != 3 {
        return Err(anyhow!("invalid function '{}': expected 'addr::module::fn'", function));
    }
    let module_addr = parse_addr(parts[0])?;
    let module_name = parts[1];
    let func_name = parts[2];

    // ModuleId: address (32 bytes fixed) + module name (BCS string)
    buf.extend_from_slice(&module_addr);
    write_bcs_str(&mut buf, module_name);

    // Function name (BCS string)
    write_bcs_str(&mut buf, func_name);

    // Type arguments: empty
    write_uleb128(&mut buf, 0);

    // Entry-function arguments: each is ULEB128(inner_len) + inner_bcs
    write_uleb128(&mut buf, args.len() as u64);
    for arg in args {
        let inner = arg.bcs_inner()?;
        write_bcs_bytes(&mut buf, &inner);
    }

    // TransactionExtraConfig::V1 = 0
    write_uleb128(&mut buf, 0);
    // multisig_address: None
    buf.push(0x00);
    // replay_protection_nonce: Some(nonce)
    buf.push(0x01);
    buf.extend_from_slice(&nonce.to_le_bytes());

    Ok(buf)
}

/// BCS-serialize a `RawTransaction` for an orderless transaction.
///
/// Uses the `0xDEADBEEF` sequence-number sentinel defined by the Aptos SDK for
/// nonce-based (orderless) transactions.
fn serialize_raw_txn(
    sender: &[u8; 32],
    payload_bcs: &[u8],
    max_gas: u64,
    gas_price: u64,
    expiry: u64,
    chain_id: u8,
) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend_from_slice(sender);
    buf.extend_from_slice(&0x0000_0000_DEAD_BEEFu64.to_le_bytes());
    buf.extend_from_slice(payload_bcs);
    buf.extend_from_slice(&max_gas.to_le_bytes());
    buf.extend_from_slice(&gas_price.to_le_bytes());
    buf.extend_from_slice(&expiry.to_le_bytes());
    buf.push(chain_id);
    buf
}

/// Wrap a `RawTransaction` BCS blob into a `FeePayerRawTransaction`.
///
/// The fee-payer address is all zeros — the gas station fills in its own address
/// before signing.
fn serialize_fee_payer_txn(raw_txn_bcs: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    write_uleb128(&mut buf, 1); // TransactionVariants::FeePayerTransaction
    buf.extend_from_slice(raw_txn_bcs);
    write_uleb128(&mut buf, 0); // secondary signers: empty vector
    buf.extend_from_slice(&[0u8; 32]); // fee_payer_address placeholder (all zeros)
    buf
}

/// Build the Ed25519 signing input for a fee-payer transaction.
///
/// Aptos signing input = SHA3-256("APTOS::RawTransactionWithData") || fee_payer_txn_bcs
/// (the hash is only of the domain separator; the BCS bytes are appended raw, not re-hashed)
fn fee_payer_signing_input(fee_payer_txn_bcs: &[u8]) -> Vec<u8> {
    let mut h = Sha3_256::new();
    h.update(b"APTOS::RawTransactionWithData");
    let prefix: [u8; 32] = h.finalize().into();

    let mut result = Vec::with_capacity(32 + fee_payer_txn_bcs.len());
    result.extend_from_slice(&prefix);
    result.extend_from_slice(fee_payer_txn_bcs);
    result
}

/// Encode a `SimpleTransaction` with fee-payer for the `transactionBytes` gas-station field.
///
/// Format: RawTransaction BCS || 0x01 (fee payer present) || [0u8; 32] (placeholder address)
fn serialize_simple_txn_with_fee_payer(raw_txn_bcs: &[u8]) -> Vec<u8> {
    let mut buf = raw_txn_bcs.to_vec();
    buf.push(0x01);                     // fee_payer_address present = true
    buf.extend_from_slice(&[0u8; 32]); // placeholder (gas station fills in its address)
    buf
}

/// BCS-serialize an Ed25519 `AccountAuthenticator`.
fn serialize_ed25519_authenticator(pk: &[u8; 32], sig: &[u8; 64]) -> Vec<u8> {
    let mut buf = Vec::new();
    write_uleb128(&mut buf, 0); // AccountAuthenticatorVariant::Ed25519
    write_bcs_bytes(&mut buf, pk);
    write_bcs_bytes(&mut buf, sig);
    buf
}

// ── AptosRpc ─────────────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AptosRpc {
    pub base_url: String,
    client: reqwest::Client,
    gas_key: Option<String>,
    gas_station_url: Option<String>,
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
        Self::new_with_gas_key(base_url, None, None)
    }

    pub fn new_with_key(base_url: String, api_key: Option<String>) -> Self {
        Self::new_with_gas_key(base_url, api_key, None)
    }

    pub fn new_with_gas_key(
        base_url: String,
        api_key: Option<String>,
        gas_key: Option<String>,
    ) -> Self {
        let mut builder =
            reqwest::Client::builder().timeout(std::time::Duration::from_secs(30));
        if let Some(key) = &api_key {
            let mut headers = reqwest::header::HeaderMap::new();
            let mut val =
                reqwest::header::HeaderValue::from_str(&format!("Bearer {}", key))
                    .expect("api_key contains invalid header characters");
            val.set_sensitive(true);
            headers.insert(reqwest::header::AUTHORIZATION, val);
            builder = builder.default_headers(headers);
        }
        let client = builder.build().unwrap();

        // Gas station URL: strip the last path segment from base_url and append /gs/v1.
        // e.g. "https://api.testnet.aptoslabs.com/v1" → "https://api.testnet.aptoslabs.com/gs/v1"
        let gas_station_url = gas_key.as_ref().map(|_| {
            let trimmed = base_url.trim_end_matches('/');
            match trimmed.rfind('/') {
                Some(pos) => format!("{}/gs/v1", &trimmed[..pos]),
                None => format!("{}/gs/v1", trimmed),
            }
        });

        Self { base_url, client, gas_key, gas_station_url }
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

    pub async fn get_apt_balance(&self, addr: &str) -> Result<u64> {
        let url = format!("{}/view", self.base_url.trim_end_matches('/'));
        let body = json!({
            "function": "0x1::coin::balance",
            "type_arguments": ["0x1::aptos_coin::AptosCoin"],
            "arguments": [addr.trim()]
        });
        let resp = self.client.post(&url).json(&body).send().await?;
        if !resp.status().is_success() {
            let text = resp.text().await?;
            return Err(anyhow!("get_apt_balance view failed: {}", text));
        }
        let v: Value = resp.json().await?;
        let raw = v.as_array()
            .and_then(|a| a.first())
            .and_then(|x| x.as_str())
            .ok_or_else(|| anyhow!("unexpected balance view response: {}", v))?;
        raw.parse::<u64>().map_err(|e| anyhow!("parse balance: {}", e))
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
        args: &[TxnArg<'_>],
    ) -> Result<String> {
        if let (Some(gas_key), Some(gs_url)) = (&self.gas_key, &self.gas_station_url) {
            return self
                .submit_txn_gas_station(
                    signing_key,
                    verifying_key,
                    sender_addr,
                    function,
                    args,
                    gas_key,
                    gs_url,
                )
                .await;
        }
        self.submit_txn_rest(signing_key, verifying_key, sender_addr, function, type_args, args)
            .await
    }

    async fn submit_txn_rest(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
        verifying_key: &ed25519_dalek::VerifyingKey,
        sender_addr: &str,
        function: &str,
        type_args: &[&str],
        args: &[TxnArg<'_>],
    ) -> Result<String> {
        let nonce = txn_nonce().fetch_add(1, Ordering::Relaxed);

        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;

        let arg_array = Value::Array(args.iter().map(|a| a.to_json()).collect());
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
        txn_body.insert(
            "replay_protection_nonce".to_string(),
            Value::String(nonce.to_string()),
        );
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

        let balance_str = match self.get_apt_balance(sender_addr).await {
            Ok(b) => format!("{} octas", b),
            Err(_) => "unknown".to_string(),
        };
        println!("[submit] {} sender={} balance={}", function, sender_addr, balance_str);

        let encode_url = format!(
            "{}/transactions/encode_submission",
            self.base_url.trim_end_matches('/')
        );
        let encode_resp = self.client.post(&encode_url).json(&txn_body).send().await?;
        if !encode_resp.status().is_success() {
            let body = encode_resp.text().await?;
            return Err(anyhow!("[{}] encode_submission failed: {}", function, body));
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
            return Err(anyhow!("[{}] submit transaction failed: {}", function, body));
        }
        let result: Value = submit_resp.json().await?;
        let hash = result["hash"]
            .as_str()
            .ok_or_else(|| anyhow!("no hash in transaction response"))?
            .to_string();

        self.wait_for_txn(&hash).await
            .map_err(|e| anyhow!("[{}] {}", function, e))?;
        Ok(hash)
    }

    async fn submit_txn_gas_station(
        &self,
        signing_key: &ed25519_dalek::SigningKey,
        verifying_key: &ed25519_dalek::VerifyingKey,
        sender_addr: &str,
        function: &str,
        args: &[TxnArg<'_>],
        gas_key: &str,
        gs_url: &str,
    ) -> Result<String> {
        let nonce = txn_nonce().fetch_add(1, Ordering::Relaxed);
        let chain_id = self.get_chain_id().await?;

        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
            + 60;

        let sender = parse_addr(sender_addr)?;
        let payload_bcs = serialize_orderless_entry_fn_payload(function, args, nonce)?;
        let raw_txn_bcs =
            serialize_raw_txn(&sender, &payload_bcs, 200_000, 100, expiry, chain_id);

        // Signing uses FeePayerRawTransaction BCS (variant(1) + raw_txn + [] + [0;32])
        let fee_payer_txn_bcs = serialize_fee_payer_txn(&raw_txn_bcs);
        let signing_input = fee_payer_signing_input(&fee_payer_txn_bcs);
        let sig = signing_key.sign(&signing_input);

        let pk: [u8; 32] = *verifying_key.as_bytes();
        let sig_bytes: [u8; 64] = sig.to_bytes();
        let sender_auth_bcs = serialize_ed25519_authenticator(&pk, &sig_bytes);

        // Gas station receives SimpleTransaction BCS (raw_txn + bool + fee_payer_placeholder)
        let simple_txn_bcs = serialize_simple_txn_with_fee_payer(&raw_txn_bcs);

        let body = json!({
            "transactionBytes": simple_txn_bcs,
            "senderAuth": sender_auth_bcs,
        });

        let endpoint = format!("{}/api/transaction/signAndSubmit", gs_url);
        let resp = self
            .client
            .post(&endpoint)
            .header("Authorization", format!("Bearer {}", gas_key))
            .json(&body)
            .send()
            .await
            .map_err(|e| anyhow!("gas station request failed: {}", e))?;

        if !resp.status().is_success() {
            let body_text = resp.text().await?;
            return Err(anyhow!("gas station error: {}", body_text));
        }

        let result: Value = resp.json().await?;
        let hash = result["transactionHash"]
            .as_str()
            .ok_or_else(|| anyhow!("no transactionHash in gas station response"))?
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
