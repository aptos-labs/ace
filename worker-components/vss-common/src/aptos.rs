// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Context, Result};
use ed25519_dalek::Signer;
use serde::{Deserialize, Serialize};
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
            TxnArg::Bytes(b) => bcs::to_bytes(b).map_err(|e| anyhow!("bcs Bytes arg: {}", e)),
        }
    }
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

// ── BCS mirror types ─────────────────────────────────────────────────────────
//
// These mirror the on-chain Aptos transaction types (the same shapes the Move
// VM and `aptos-types` define). Every type derives `Serialize` so the wire
// bytes are produced by `bcs::to_bytes(&...)`. Variant order on each enum
// matches the on-chain BCS discriminant layout — placeholder variants are
// declared (but never constructed) so the variants we *do* use land at the
// correct index. Mirroring `aptos-types` directly is impractical because
// that crate pulls in the full aptos-core consensus tree.

/// Mirrors `move_core_types::language_storage::ModuleId`.
#[derive(Serialize, Clone)]
struct ModuleId {
    address: [u8; 32],
    name: String,
}

/// Mirrors `move_core_types::language_storage::TypeTag`.
/// Uninhabited: we always produce empty `ty_args` lists, so no variant is ever
/// constructed. `bcs::to_bytes` of `Vec<TypeTag>` with zero elements emits
/// just `ULEB128(0)`.
#[derive(Serialize, Clone)]
enum TypeTag {}

/// Mirrors `aptos_types::transaction::EntryFunction`.
#[derive(Serialize, Clone)]
struct EntryFunction {
    module: ModuleId,
    function: String,
    ty_args: Vec<TypeTag>,
    args: Vec<Vec<u8>>,
}

/// Mirrors `aptos_types::transaction::TransactionExecutable` (variant 1 = EntryFunction).
#[derive(Serialize, Clone)]
#[allow(dead_code)]
enum TransactionExecutable {
    Script,                          // 0 (placeholder)
    EntryFunction(EntryFunction),    // 1
}

/// Mirrors `aptos_types::transaction::TransactionExtraConfig`.
#[derive(Serialize, Clone)]
enum TransactionExtraConfig {
    V1 {
        multisig_address: Option<[u8; 32]>,
        replay_protection_nonce: Option<u64>,
    },
}

/// Mirrors `aptos_types::transaction::TransactionInnerPayload`.
#[derive(Serialize, Clone)]
enum TransactionInnerPayload {
    V1 {
        executable: TransactionExecutable,
        extra_config: TransactionExtraConfig,
    },
}

/// Mirrors `aptos_types::transaction::TransactionPayload`.
/// Variants 0–3 are reserved indices for the legacy on-chain layouts (Script,
/// ModuleBundle, EntryFunction, Multisig). Declared as unit placeholders so
/// `Payload` lands at variant index 4 — the new orderless+fee-payer-capable
/// shape carrying `TransactionExtraConfig`.
#[derive(Serialize, Clone)]
#[allow(dead_code)]
enum TransactionPayload {
    LegacyScript,                        // 0
    LegacyModuleBundle,                  // 1
    LegacyEntryFunction,                 // 2
    LegacyMultisig,                      // 3
    Payload(TransactionInnerPayload),    // 4
}

/// Mirrors `aptos_types::transaction::RawTransaction`.
/// For orderless txns, `sequence_number` is `ORDERLESS_SEQUENCE_NUMBER` and
/// the actual nonce lives in `extra_config.replay_protection_nonce`.
#[derive(Serialize, Clone)]
struct RawTransaction {
    sender: [u8; 32],
    sequence_number: u64,
    payload: TransactionPayload,
    max_gas_amount: u64,
    gas_unit_price: u64,
    expiration_timestamp_secs: u64,
    chain_id: u8,
}

/// Mirrors `aptos_types::transaction::RawTransactionWithData` (variant 1 = FeePayerTransaction).
#[derive(Serialize, Clone)]
#[allow(dead_code)]
enum RawTransactionWithData {
    MultiAgent,                          // 0 (placeholder)
    FeePayerTransaction {                // 1
        raw_txn: RawTransaction,
        secondary_signer_addresses: Vec<[u8; 32]>,
        fee_payer_address: [u8; 32],
    },
}

/// Mirrors `aptos_types::transaction::authenticator::AccountAuthenticator`
/// (variant 0 = Ed25519). Only Ed25519 is constructed.
#[derive(Serialize)]
#[allow(dead_code)]
enum AccountAuthenticator {
    Ed25519 {
        public_key: Vec<u8>,  // 32 bytes
        signature: Vec<u8>,    // 64 bytes
    },
}

/// Wire format the Aptos gas station expects in its `transactionBytes` field:
/// `bcs(raw_txn) || option(fee_payer_address)`. The all-zero fee-payer is a
/// placeholder; the gas station substitutes its own address before signing.
#[derive(Serialize)]
struct GasStationTransactionBody {
    raw_txn: RawTransaction,
    fee_payer_address: Option<[u8; 32]>,
}

/// Sequence-number sentinel marking an orderless transaction. The real nonce
/// is carried in `TransactionExtraConfig::V1.replay_protection_nonce`.
const ORDERLESS_SEQUENCE_NUMBER: u64 = 0x0000_0000_DEAD_BEEF;

// ── Transaction builders ─────────────────────────────────────────────────────

fn build_orderless_payload(
    function: &str,
    args: &[TxnArg<'_>],
    nonce: u64,
) -> Result<TransactionPayload> {
    let parts: Vec<&str> = function.splitn(3, "::").collect();
    if parts.len() != 3 {
        return Err(anyhow!("invalid function '{}': expected 'addr::module::fn'", function));
    }
    let entry_fn = EntryFunction {
        module: ModuleId {
            address: parse_addr(parts[0])?,
            name: parts[1].to_string(),
        },
        function: parts[2].to_string(),
        ty_args: Vec::new(),
        args: args.iter().map(|a| a.bcs_inner()).collect::<Result<Vec<_>>>()?,
    };
    Ok(TransactionPayload::Payload(TransactionInnerPayload::V1 {
        executable: TransactionExecutable::EntryFunction(entry_fn),
        extra_config: TransactionExtraConfig::V1 {
            multisig_address: None,
            replay_protection_nonce: Some(nonce),
        },
    }))
}

/// Aptos signing input = SHA3-256("APTOS::RawTransactionWithData") || fee_payer_txn_bcs.
/// (Domain-separator hash is computed once; the BCS bytes are appended raw, not re-hashed.)
fn fee_payer_signing_input(fee_payer_txn_bcs: &[u8]) -> Vec<u8> {
    let mut h = Sha3_256::new();
    h.update(b"APTOS::RawTransactionWithData");
    let prefix: [u8; 32] = h.finalize().into();

    let mut result = Vec::with_capacity(32 + fee_payer_txn_bcs.len());
    result.extend_from_slice(&prefix);
    result.extend_from_slice(fee_payer_txn_bcs);
    result
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
        let payload = build_orderless_payload(function, args, nonce)?;
        let raw_txn = RawTransaction {
            sender,
            sequence_number: ORDERLESS_SEQUENCE_NUMBER,
            payload,
            max_gas_amount: 200_000,
            gas_unit_price: 100,
            expiration_timestamp_secs: expiry,
            chain_id,
        };

        // Signing uses FeePayerTransaction BCS with all-zero fee-payer placeholder.
        let fee_payer_txn = RawTransactionWithData::FeePayerTransaction {
            raw_txn: raw_txn.clone(),
            secondary_signer_addresses: Vec::new(),
            fee_payer_address: [0u8; 32],
        };
        let fee_payer_txn_bcs =
            bcs::to_bytes(&fee_payer_txn).map_err(|e| anyhow!("bcs FeePayer: {}", e))?;
        let signing_input = fee_payer_signing_input(&fee_payer_txn_bcs);
        let sig = signing_key.sign(&signing_input);

        let sender_auth = AccountAuthenticator::Ed25519 {
            public_key: verifying_key.as_bytes().to_vec(),
            signature: sig.to_bytes().to_vec(),
        };
        let sender_auth_bcs =
            bcs::to_bytes(&sender_auth).map_err(|e| anyhow!("bcs auth: {}", e))?;

        // Gas station body: bcs(raw_txn) || Some(fee_payer_placeholder).
        let simple_txn_bcs = bcs::to_bytes(&GasStationTransactionBody {
            raw_txn,
            fee_payer_address: Some([0u8; 32]),
        })
        .map_err(|e| anyhow!("bcs GasStation body: {}", e))?;

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
        bcs::from_bytes(&bytes).map_err(|e| anyhow!("EncryptionKey BCS decode: {}", e))
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

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Pins the exact BCS layout of `TransactionPayload::Payload(V1(...))` for an
    /// orderless entry function with one Address arg + one Bytes arg.
    #[test]
    fn orderless_payload_layout() {
        let args = [TxnArg::Address("0x0123"), TxnArg::Bytes(&[0xab, 0xcd])];
        let payload = build_orderless_payload("0x01::aptos_account::transfer", &args, 42).unwrap();
        let bytes = bcs::to_bytes(&payload).unwrap();

        let mut addr_1 = [0u8; 32];
        addr_1[31] = 0x01;
        let mut addr_123 = [0u8; 32];
        addr_123[30] = 0x01;
        addr_123[31] = 0x23;

        // [0x04]                               TransactionPayload::Payload (variant 4)
        // [0x00]                               TransactionInnerPayload::V1
        // [0x01]                               TransactionExecutable::EntryFunction
        // [...32B = 0x...01...]                module address (0x1)
        // [0x0d]"aptos_account"                module name
        // [0x08]"transfer"                     function name
        // [0x00]                               ty_args: empty
        // [0x02]                               args.len() = 2
        //   [0x20][...32B 0x...0123]           arg[0] = Vec<u8>(32) wrapping the address
        //   [0x03][0x02, 0xab, 0xcd]           arg[1] = Vec<u8>(3) wrapping bcs(Vec<u8>(2))
        // [0x00]                               TransactionExtraConfig::V1
        // [0x00]                               multisig_address: None
        // [0x01][...8B nonce LE]               replay_protection_nonce: Some(42)
        assert_eq!(bytes[0], 0x04);
        assert_eq!(bytes[1], 0x00);
        assert_eq!(bytes[2], 0x01);
        assert_eq!(&bytes[3..35], &addr_1);
        assert_eq!(bytes[35], 0x0d);
        assert_eq!(&bytes[36..49], b"aptos_account");
        assert_eq!(bytes[49], 0x08);
        assert_eq!(&bytes[50..58], b"transfer");
        assert_eq!(bytes[58], 0x00); // ty_args empty
        assert_eq!(bytes[59], 0x02); // 2 args
        assert_eq!(bytes[60], 0x20); // arg[0] inner-len = 32
        assert_eq!(&bytes[61..93], &addr_123);
        assert_eq!(bytes[93], 0x03); // arg[1] inner-len = 3
        assert_eq!(&bytes[94..97], &[0x02, 0xab, 0xcd]); // bcs(Vec<u8>(2)) = [0x02, 0xab, 0xcd]
        assert_eq!(bytes[97], 0x00); // ExtraConfig::V1
        assert_eq!(bytes[98], 0x00); // multisig: None
        assert_eq!(bytes[99], 0x01); // replay_nonce: Some
        assert_eq!(&bytes[100..108], &42u64.to_le_bytes());
        assert_eq!(bytes.len(), 108);
    }

    fn sample_raw_txn() -> RawTransaction {
        let mut sender = [0u8; 32];
        sender[31] = 0x42;
        let payload = TransactionPayload::Payload(TransactionInnerPayload::V1 {
            executable: TransactionExecutable::EntryFunction(EntryFunction {
                module: ModuleId { address: [0u8; 32], name: "m".to_string() },
                function: "f".to_string(),
                ty_args: Vec::new(),
                args: Vec::new(),
            }),
            extra_config: TransactionExtraConfig::V1 {
                multisig_address: None,
                replay_protection_nonce: Some(7),
            },
        });
        RawTransaction {
            sender,
            sequence_number: ORDERLESS_SEQUENCE_NUMBER,
            payload,
            max_gas_amount: 200_000,
            gas_unit_price: 100,
            expiration_timestamp_secs: 1_700_000_000,
            chain_id: 4,
        }
    }

    /// Verifies orderless `RawTransaction` BCS: 32B sender, then 0xDEADBEEF LE,
    /// then payload, then three u64 LE fields, then chain_id.
    #[test]
    fn raw_txn_layout() {
        let raw = sample_raw_txn();
        let bytes = bcs::to_bytes(&raw).unwrap();
        let mut expected_sender = [0u8; 32];
        expected_sender[31] = 0x42;
        assert_eq!(&bytes[0..32], &expected_sender);
        assert_eq!(&bytes[32..40], &0x0000_0000_DEAD_BEEFu64.to_le_bytes());
        // payload starts at byte 40 with TransactionPayload variant 4
        assert_eq!(bytes[40], 0x04);
        // chain_id is the last byte
        assert_eq!(*bytes.last().unwrap(), 0x04);
        // The three u64s precede chain_id: max_gas, gas_price, expiry.
        assert_eq!(&bytes[bytes.len() - 25..bytes.len() - 17], &200_000u64.to_le_bytes());
        assert_eq!(&bytes[bytes.len() - 17..bytes.len() - 9], &100u64.to_le_bytes());
        assert_eq!(&bytes[bytes.len() - 9..bytes.len() - 1], &1_700_000_000u64.to_le_bytes());
    }

    /// `RawTransactionWithData::FeePayerTransaction` lays out as:
    /// [0x01 variant] [bcs(raw_txn)] [0x00 empty secondary] [32B zeros].
    #[test]
    fn fee_payer_wrapper_layout() {
        let raw = sample_raw_txn();
        let raw_bcs = bcs::to_bytes(&raw).unwrap();
        let fp = RawTransactionWithData::FeePayerTransaction {
            raw_txn: raw,
            secondary_signer_addresses: Vec::new(),
            fee_payer_address: [0u8; 32],
        };
        let bytes = bcs::to_bytes(&fp).unwrap();
        assert_eq!(bytes[0], 0x01); // FeePayerTransaction variant
        assert_eq!(&bytes[1..1 + raw_bcs.len()], &raw_bcs[..]);
        let mid = 1 + raw_bcs.len();
        assert_eq!(bytes[mid], 0x00); // empty secondary signers
        assert_eq!(&bytes[mid + 1..mid + 33], &[0u8; 32]);
        assert_eq!(bytes.len(), mid + 33);
    }

    /// Gas-station body lays out as: bcs(raw_txn) || 0x01 || 32B zeros.
    #[test]
    fn gas_station_body_layout() {
        let raw = sample_raw_txn();
        let raw_bcs = bcs::to_bytes(&raw).unwrap();
        let body = GasStationTransactionBody {
            raw_txn: raw,
            fee_payer_address: Some([0u8; 32]),
        };
        let bytes = bcs::to_bytes(&body).unwrap();
        assert_eq!(&bytes[..raw_bcs.len()], &raw_bcs[..]);
        assert_eq!(bytes[raw_bcs.len()], 0x01); // Option::Some
        assert_eq!(&bytes[raw_bcs.len() + 1..], &[0u8; 32]);
    }

    /// `AccountAuthenticator::Ed25519` lays out as: 0x00 variant || ULEB128(32) || pk || ULEB128(64) || sig.
    #[test]
    fn ed25519_authenticator_layout() {
        let pk = [0xaau8; 32];
        let sig = [0xbbu8; 64];
        let auth = AccountAuthenticator::Ed25519 {
            public_key: pk.to_vec(),
            signature: sig.to_vec(),
        };
        let bytes = bcs::to_bytes(&auth).unwrap();
        assert_eq!(bytes[0], 0x00); // Ed25519 variant
        assert_eq!(bytes[1], 0x20); // ULEB128(32)
        assert_eq!(&bytes[2..34], &pk);
        assert_eq!(bytes[34], 0x40); // ULEB128(64)
        assert_eq!(&bytes[35..99], &sig);
        assert_eq!(bytes.len(), 99);
    }
}
