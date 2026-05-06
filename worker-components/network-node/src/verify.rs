// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Wire-format types for `RequestForDecryptionKey` and proof-of-permission verification.
//!
//! The on-the-wire request layout mirrors `ts-sdk/src/_internal/common.ts` and is decoded
//! in one shot via `bcs::from_bytes` (`#[derive(Serialize, Deserialize)]` on every nested
//! type). Adding a new variant — chain, proof scheme, flow — is one new enum arm.
//!
//! Verification entry points:
//!   - [`verify_basic`] — checks an `AptosProofOfPermission` (sig + auth-key + permission view)
//!     or `SolanaProofOfPermission` (txn structure + RPC simulation).
//!   - [`verify_custom`] — checks a custom-flow ACL view (Aptos) or Solana custom-instruction.
//!
//! Mirrors `verifyAndExtract` and its helpers in `ts-sdk/src/ace-ex/{aptos,solana}.ts`.
//!
//! Supported combinations:
//!   ContractId::Aptos  + ProofOfPermission::Aptos   → Ed25519 sig + on-chain auth key + permission view
//!   ContractId::Solana + ProofOfPermission::Solana  → instruction structure + RPC simulation (sigVerify=true)

use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use vss_common::pke::EncryptionKey;

use crate::ChainRpcConfig;

// ── Wire types ────────────────────────────────────────────────────────────────

/// Top-level request body. Outer enum tag picks between the basic and custom flows.
#[derive(Serialize, Deserialize)]
pub enum RequestForDecryptionKey {
    Basic(BasicFlowRequest),
    Custom(CustomFlowRequest),
}

#[derive(Serialize, Deserialize)]
pub struct BasicFlowRequest {
    pub keypair_id: [u8; 32],
    pub epoch: u64,
    pub contract_id: ContractId,
    pub domain: Vec<u8>,
    pub ephemeral_enc_key: EncryptionKey,
    pub proof: ProofOfPermission,
}

#[derive(Serialize, Deserialize)]
pub struct CustomFlowRequest {
    pub keypair_id: [u8; 32],
    pub epoch: u64,
    pub contract_id: ContractId,
    pub label: Vec<u8>,
    pub enc_pk: EncryptionKey,
    pub proof: CustomFlowProof,
}

#[derive(Serialize, Deserialize)]
pub enum ContractId {
    Aptos(AptosContractId),
    Solana(SolanaContractId),
}

#[derive(Serialize, Deserialize)]
pub struct AptosContractId {
    pub chain_id: u8,
    pub module_addr: [u8; 32],
    pub module_name: String,
    pub function_name: String,
}

#[derive(Serialize, Deserialize)]
pub struct SolanaContractId {
    pub known_chain_name: String,
    pub program_id: Vec<u8>, // 32 bytes
}

#[derive(Serialize, Deserialize)]
pub enum ProofOfPermission {
    Aptos(AptosProofOfPermission),
    Solana(SolanaProofOfPermission),
}

#[derive(Serialize, Deserialize)]
pub struct AptosProofOfPermission {
    pub user_addr: [u8; 32],
    pub pk_scheme: u8,
    pub public_key: Vec<u8>,
    pub sig_scheme: u8,
    pub signature: Vec<u8>,
    pub full_message: String,
}

#[derive(Serialize, Deserialize)]
pub struct SolanaProofOfPermission {
    pub inner_scheme: u8, // 0 = legacy/unversioned, 1 = versioned
    pub txn_bytes: Vec<u8>,
}

#[derive(Serialize, Deserialize)]
pub enum CustomFlowProof {
    /// Aptos custom flow carries a free-form payload that the configured ACL view
    /// will interpret. The worker just relays it.
    Aptos(Vec<u8>),
    Solana(SolanaProofOfPermission),
}

// ── Identity bytes ────────────────────────────────────────────────────────────

/// IBE identity = `keypair_id (32B raw) ++ BCS(contract_id) ++ BCS(domain)`. This is the
/// same identity TS computes when encrypting (`FullDecryptionDomain.toBytes()`).
pub fn identity_bytes(keypair_id: &[u8; 32], contract_id: &ContractId, domain: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(keypair_id);
    out.extend(bcs::to_bytes(contract_id).expect("BCS"));
    out.extend(bcs::to_bytes(domain).expect("BCS"));
    out
}

// ── Entry points ──────────────────────────────────────────────────────────────

/// Verify a basic-flow request: checks the proof-of-permission and binds it to the
/// keypair_id, epoch, contract_id, domain, and ephemeral encryption key in `req`.
pub async fn verify_basic(req: &BasicFlowRequest, chain_rpc: &ChainRpcConfig) -> Result<()> {
    let ephemeral_ek_bytes = bcs::to_bytes(&req.ephemeral_enc_key)
        .map_err(|e| anyhow!("verify_basic: serialize ephemeral_enc_key: {}", e))?;

    match (&req.contract_id, &req.proof) {
        (ContractId::Aptos(contract), ProofOfPermission::Aptos(proof)) => {
            verify_aptos(req, contract, proof, &ephemeral_ek_bytes, chain_rpc).await
        }
        (ContractId::Solana(contract), ProofOfPermission::Solana(proof)) => {
            verify_solana(req, contract, proof, &ephemeral_ek_bytes, chain_rpc).await
        }
        (contract, proof) => Err(anyhow!(
            "verify_basic: contract/proof scheme mismatch (contract={}, proof={})",
            contract.tag_name(),
            proof.tag_name()
        )),
    }
}

/// Verify a custom-flow request: dispatches to the chain-specific ACL check.
pub async fn verify_custom(req: &CustomFlowRequest, chain_rpc: &ChainRpcConfig) -> Result<()> {
    let enc_pk_bytes = bcs::to_bytes(&req.enc_pk)
        .map_err(|e| anyhow!("verify_custom: serialize enc_pk: {}", e))?;

    match (&req.contract_id, &req.proof) {
        (ContractId::Aptos(contract), CustomFlowProof::Aptos(payload)) => {
            verify_custom_aptos(contract, &req.label, &enc_pk_bytes, payload, chain_rpc).await
        }
        (ContractId::Solana(contract), CustomFlowProof::Solana(proof)) => {
            verify_custom_solana(req, contract, proof, &enc_pk_bytes, chain_rpc).await
        }
        (contract, proof) => Err(anyhow!(
            "verify_custom: contract/proof scheme mismatch (contract={}, proof={})",
            contract.tag_name(),
            proof.tag_name()
        )),
    }
}

impl ContractId {
    fn tag_name(&self) -> &'static str {
        match self {
            ContractId::Aptos(_) => "aptos",
            ContractId::Solana(_) => "solana",
        }
    }
}

impl ProofOfPermission {
    fn tag_name(&self) -> &'static str {
        match self {
            ProofOfPermission::Aptos(_) => "aptos",
            ProofOfPermission::Solana(_) => "solana",
        }
    }
}

impl CustomFlowProof {
    fn tag_name(&self) -> &'static str {
        match self {
            CustomFlowProof::Aptos(_) => "aptos",
            CustomFlowProof::Solana(_) => "solana",
        }
    }
}

// ── Aptos verification ────────────────────────────────────────────────────────

async fn verify_aptos(
    req: &BasicFlowRequest,
    contract: &AptosContractId,
    proof: &AptosProofOfPermission,
    ephemeral_ek_bytes: &[u8],
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    // Only legacy Ed25519 (pk_scheme=0, sig_scheme=0) is currently supported.
    if proof.pk_scheme != 0 {
        return Err(anyhow!("verify_aptos: unsupported public key scheme {}", proof.pk_scheme));
    }
    if proof.sig_scheme != 0 {
        return Err(anyhow!("verify_aptos: unsupported signature scheme {}", proof.sig_scheme));
    }
    if proof.public_key.len() != 32 {
        return Err(anyhow!(
            "verify_aptos: Ed25519 pubkey must be 32 bytes, got {}",
            proof.public_key.len()
        ));
    }
    if proof.signature.len() != 64 {
        return Err(anyhow!(
            "verify_aptos: Ed25519 sig must be 64 bytes, got {}",
            proof.signature.len()
        ));
    }

    let pk_arr: [u8; 32] = proof.public_key.as_slice().try_into().unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| anyhow!("verify_aptos: invalid Ed25519 pubkey: {}", e))?;

    let sig_arr: [u8; 64] = proof.signature.as_slice().try_into().unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    // verifySig is cheap and synchronous — fail fast before hitting RPC.
    verify_aptos_sig(req, contract, proof, ephemeral_ek_bytes, &vk, &sig)?;

    let rpc = chain_rpc.aptos_rpc_for_chain_id(contract.chain_id)?;

    // auth-key and permission checks are independent RPC calls; run them concurrently.
    let (auth_result, perm_result) = tokio::join!(
        check_aptos_auth_key(proof, &vk, rpc),
        check_aptos_permission(contract, &req.domain, proof, rpc),
    );
    auth_result?;
    perm_result?;

    Ok(())
}

/// Mirrors `verifySig` in `ts-sdk/src/ace-ex/aptos.ts`.
///
/// Checks that `fullMessage` contains the decryption request's pretty-printed representation
/// (or its hex encoding, to handle AptosConnect wallets), then verifies the Ed25519 signature.
fn verify_aptos_sig(
    req: &BasicFlowRequest,
    contract: &AptosContractId,
    proof: &AptosProofOfPermission,
    ephemeral_ek_bytes: &[u8],
    vk: &ed25519_dalek::VerifyingKey,
    sig: &ed25519_dalek::Signature,
) -> Result<()> {
    use ed25519_dalek::Verifier;

    let pretty_msg = aptos_decryption_request_message(req, contract, ephemeral_ek_bytes);
    // AptosConnect embeds hex(UTF-8(pretty_msg)) rather than the raw string.
    let pretty_msg_hex = hex::encode(pretty_msg.as_bytes());

    let full_msg = &proof.full_message;
    if !full_msg.contains(&pretty_msg) && !full_msg.contains(&pretty_msg_hex) {
        return Err(anyhow!(
            "verifySig: fullMessage does not contain expected decryption request content"
        ));
    }

    // Replicate `convertSigningMessage`: if fullMessage is not valid hex, sign/verify
    // over its UTF-8 bytes; otherwise hex-decode and use those bytes.
    let msg_bytes: Vec<u8> = if is_valid_hex(full_msg) {
        let stripped = full_msg.strip_prefix("0x").unwrap_or(full_msg.as_str());
        hex::decode(stripped)
            .map_err(|e| anyhow!("verifySig: hex decode fullMessage: {}", e))?
    } else {
        full_msg.as_bytes().to_vec()
    };

    vk.verify(&msg_bytes, sig)
        .map_err(|e| anyhow!("verifySig: Ed25519 verification failed: {}", e))?;

    Ok(())
}

/// Mirrors `checkAuthKey` in `ts-sdk/src/ace-ex/aptos.ts`.
///
/// Verifies that the Ed25519 public key's authentication key (SHA3-256(pk||0x00))
/// matches the on-chain `authentication_key` for `userAddr`.
async fn check_aptos_auth_key(
    proof: &AptosProofOfPermission,
    vk: &ed25519_dalek::VerifyingKey,
    rpc: &vss_common::AptosRpc,
) -> Result<()> {
    // For legacy Ed25519 (scheme=0): auth_key = SHA3-256(pubkey_bytes || 0x00)
    // This is identical to `vss_common::compute_account_address`.
    let computed = vss_common::compute_account_address(vk);

    let user_addr_str = format!("0x{}", hex::encode(proof.user_addr));
    let account = rpc
        .get_account(&user_addr_str)
        .await
        .map_err(|e| anyhow!("checkAuthKey: get_account {}: {}", user_addr_str, e))?;

    let onchain = hex::decode(account.authentication_key.trim_start_matches("0x"))
        .map_err(|e| anyhow!("checkAuthKey: parse onchain auth key: {}", e))?;

    if onchain.as_slice() != computed.as_ref() {
        return Err(anyhow!("checkAuthKey: auth key mismatch for {}", user_addr_str));
    }

    Ok(())
}

/// Mirrors `checkPermission` in `ts-sdk/src/ace-ex/aptos.ts`.
///
/// Calls the on-chain view function `{moduleAddr}::{moduleName}::{functionName}(userAddr, domain)`
/// and expects `true` to be returned.
async fn check_aptos_permission(
    contract: &AptosContractId,
    domain: &[u8],
    proof: &AptosProofOfPermission,
    rpc: &vss_common::AptosRpc,
) -> Result<()> {
    let func = format!(
        "0x{}::{}::{}",
        hex::encode(contract.module_addr),
        contract.module_name,
        contract.function_name,
    );
    let user_addr = format!("0x{}", hex::encode(proof.user_addr));
    let domain_hex = format!("0x{}", hex::encode(domain));

    let result = rpc
        .call_view(&func, &[json!(user_addr), json!(domain_hex)])
        .await
        .map_err(|e| anyhow!("checkPermission: view call failed for {}: {}", func, e))?;

    let returned = result
        .first()
        .ok_or_else(|| anyhow!("checkPermission: empty view result"))?;
    if returned.as_bool() != Some(true) && returned.to_string() != "true" {
        return Err(anyhow!("checkPermission: access denied (returned {:?})", returned));
    }

    Ok(())
}

// ── Solana verification ───────────────────────────────────────────────────────

async fn verify_solana(
    req: &BasicFlowRequest,
    contract: &SolanaContractId,
    proof: &SolanaProofOfPermission,
    ephemeral_ek_bytes: &[u8],
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let expected_program_id = solana_program_id(contract)?;

    // NOTE: do NOT detect is_versioned from the first byte of txn_bytes.  A serialized
    // VersionedTransaction starts with the compact-u16 signature count (e.g. 0x01 for
    // one signature), NOT the v0 prefix byte (0x80).  The v0 prefix byte lives inside
    // the serialised message, after the signatures.  Only `inner_scheme` is reliable.
    let is_versioned = proof.inner_scheme == 1;

    // 1. Structural validation: instruction count, program ID, full_request_bytes in data.
    let expected = ace_anchor_kit::build_full_request_bytes(
        &req.keypair_id,
        req.epoch,
        ephemeral_ek_bytes,
        &req.domain,
    );
    validate_solana_txn(&proof.txn_bytes, &expected_program_id, &expected, is_versioned)?;

    // 2. Signature + program execution via RPC simulation.
    let rpc_url = chain_rpc.solana_rpc_for_chain_name(&contract.known_chain_name)?;
    simulate_solana_txn(&proof.txn_bytes, &rpc_url, &chain_rpc.solana_client).await?;

    Ok(())
}

fn solana_program_id(contract: &SolanaContractId) -> Result<[u8; 32]> {
    contract
        .program_id
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("Solana programId must be 32 bytes, got {}", contract.program_id.len()))
}

fn validate_solana_txn(
    txn: &[u8],
    expected_program_id: &[u8; 32],
    expected_full_request_bytes: &[u8],
    is_versioned: bool,
) -> Result<()> {
    let (account_keys, instructions) = if is_versioned {
        parse_solana_txn_versioned(txn)?
    } else {
        parse_solana_txn_legacy(txn)?
    };

    if instructions.len() != 1 {
        return Err(anyhow!("Solana: expected exactly 1 instruction, got {}", instructions.len()));
    }
    let ix = &instructions[0];

    let prog_key = account_keys
        .get(ix.program_id_index as usize)
        .ok_or_else(|| anyhow!("Solana: program_id_index {} out of bounds", ix.program_id_index))?;

    if prog_key != expected_program_id {
        return Err(anyhow!("Solana: instruction program ID mismatch"));
    }

    // Anchor instruction format: [8B discriminator][u32-LE vec-length][vec bytes]
    if ix.data.len() < 12 {
        return Err(anyhow!("Solana: instruction data too short ({}B)", ix.data.len()));
    }
    let param = &ix.data[8..];
    let vec_len = u32::from_le_bytes([param[0], param[1], param[2], param[3]]) as usize;
    if param.len() != 4 + vec_len {
        return Err(anyhow!("Solana: instruction data length mismatch"));
    }
    if &param[4..4 + vec_len] != expected_full_request_bytes {
        return Err(anyhow!("Solana: full_request_bytes mismatch in instruction data"));
    }

    Ok(())
}

struct SolanaInstruction {
    program_id_index: u8,
    data: Vec<u8>,
}

fn parse_solana_txn_legacy(bytes: &[u8]) -> Result<(Vec<[u8; 32]>, Vec<SolanaInstruction>)> {
    let mut pos = 0usize;
    // Signatures section: compact-u16 count + count*64 bytes
    let (num_sigs, n) = read_compact_u16(bytes, pos)?;
    pos += n + num_sigs as usize * 64;
    // Message header: 3 bytes
    if bytes.len() < pos + 3 { return Err(anyhow!("Solana legacy: header truncated")); }
    pos += 3;
    // Static account keys
    let (num_keys, n) = read_compact_u16(bytes, pos)?;
    pos += n;
    let account_keys = read_solana_pubkeys(bytes, &mut pos, num_keys as usize)?;
    // Recent blockhash (32B)
    if bytes.len() < pos + 32 { return Err(anyhow!("Solana legacy: blockhash truncated")); }
    pos += 32;
    let instructions = read_solana_instructions(bytes, &mut pos)?;
    Ok((account_keys, instructions))
}

fn parse_solana_txn_versioned(bytes: &[u8]) -> Result<(Vec<[u8; 32]>, Vec<SolanaInstruction>)> {
    let mut pos = 0usize;
    // compact-u16 signature count + signatures (same layout as legacy)
    let (num_sigs, n) = read_compact_u16(bytes, pos)?;
    pos += n + num_sigs as usize * 64;
    // Version prefix byte (0x80 | version, e.g. 0x80 for v0) — sits between
    // the signatures section and the message header; absent in legacy transactions.
    if bytes.len() < pos + 1 { return Err(anyhow!("Solana versioned: version byte truncated")); }
    pos += 1;
    if bytes.len() < pos + 3 { return Err(anyhow!("Solana versioned: header truncated")); }
    pos += 3;
    let (num_keys, n) = read_compact_u16(bytes, pos)?;
    pos += n;
    let account_keys = read_solana_pubkeys(bytes, &mut pos, num_keys as usize)?;
    if bytes.len() < pos + 32 { return Err(anyhow!("Solana versioned: blockhash truncated")); }
    pos += 32;
    let instructions = read_solana_instructions(bytes, &mut pos)?;
    Ok((account_keys, instructions))
}

fn read_solana_pubkeys(bytes: &[u8], pos: &mut usize, count: usize) -> Result<Vec<[u8; 32]>> {
    let mut keys = Vec::with_capacity(count);
    for _ in 0..count {
        if bytes.len() < *pos + 32 {
            return Err(anyhow!("Solana: account key truncated"));
        }
        keys.push(bytes[*pos..*pos + 32].try_into().unwrap());
        *pos += 32;
    }
    Ok(keys)
}

fn read_solana_instructions(bytes: &[u8], pos: &mut usize) -> Result<Vec<SolanaInstruction>> {
    let (num_ixs, n) = read_compact_u16(bytes, *pos)?;
    *pos += n;
    let mut ixs = Vec::with_capacity(num_ixs as usize);
    for _ in 0..num_ixs {
        let program_id_index = *bytes
            .get(*pos)
            .ok_or_else(|| anyhow!("Solana: ix prog-id-index truncated"))?;
        *pos += 1;
        // Account indices: compact-u16 count + that many 1-byte indices
        let (num_accs, n) = read_compact_u16(bytes, *pos)?;
        *pos += n + num_accs as usize;
        // Instruction data: compact-u16 len + bytes
        let (data_len, n) = read_compact_u16(bytes, *pos)?;
        *pos += n;
        if bytes.len() < *pos + data_len as usize {
            return Err(anyhow!("Solana: ix data truncated"));
        }
        let data = bytes[*pos..*pos + data_len as usize].to_vec();
        *pos += data_len as usize;
        ixs.push(SolanaInstruction { program_id_index, data });
    }
    Ok(ixs)
}

/// Simulate the transaction with `sigVerify: true`.
///
/// For legacy transactions the blockhash must still be in the recent cache (~90 s on
/// mainnet), which is acceptable for a real-time decryption flow.
///
/// Use "confirmed" commitment so that recently-confirmed accounts (e.g. a Receipt PDA
/// created moments before) are visible to the simulation.
async fn simulate_solana_txn(txn_bytes: &[u8], rpc_url: &str, client: &reqwest::Client) -> Result<()> {
    use base64::engine::general_purpose::STANDARD as B64;
    use base64::Engine;

    let txn_b64 = B64.encode(txn_bytes);
    let sim_config = json!({ "encoding": "base64", "sigVerify": true, "commitment": "confirmed" });

    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "simulateTransaction",
        "params": [txn_b64, sim_config]
    });

    let resp_json: Value = client
        .post(rpc_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| anyhow!("simulateTransaction HTTP: {}", e))?
        .json()
        .await
        .map_err(|e| anyhow!("simulateTransaction parse JSON: {}", e))?;

    let err_val = &resp_json["result"]["value"]["err"];
    if !err_val.is_null() {
        let logs = &resp_json["result"]["value"]["logs"];
        return Err(anyhow!("simulateTransaction failed: {} | logs: {}", err_val, logs));
    }

    Ok(())
}

// ── Decryption request pretty-message (Aptos) ─────────────────────────────────

/// Produces `DecryptionRequestPayload.toPrettyMessage(0)` from `ts-sdk/src/_internal/common.ts`
/// for an Aptos ContractID.  Used by `verifySig` to check that `fullMessage` covers the correct
/// keypairId, epoch, contractId, domain, **and ephemeralEncKey**.
///
/// Binding the ephemeralEncKey is critical: it is the public key that the IDK share is encrypted
/// to in the response.  If it were not part of the signed message, anyone holding a valid proof
/// could replay it with a substituted ephemeralEncKey and have shares re-encrypted to themselves.
fn aptos_decryption_request_message(
    req: &BasicFlowRequest,
    contract: &AptosContractId,
    ephemeral_ek_bytes: &[u8],
) -> String {
    // moduleAddr.toStringLong() = "0x" + 64 lowercase hex chars (32 bytes)
    let module_addr = format!("0x{}", hex::encode(contract.module_addr));
    let domain_hex = format!("0x{}", hex::encode(&req.domain));
    // `pke.EncryptionKey.toHex()` = bytesToHex(toBytes()); does NOT prepend "0x".
    let ephemeral_ek_hex = hex::encode(ephemeral_ek_bytes);
    let keypair_id_hex = format!("0x{}", hex::encode(req.keypair_id));

    // Matches DecryptionRequestPayload.toPrettyMessage(indent=0) — see TS source for layout.
    format!(
        "ACE Decryption Request\nkeypairId: {}\nepoch: {}\ncontractId:\n  scheme: aptos\n  inner:\n      chainId: {}\n      moduleAddr: {}\n      moduleName: {}\n      functionName: {}\ndomain: {}\nephemeralEncKey: {}",
        keypair_id_hex,
        req.epoch,
        contract.chain_id,
        module_addr,
        contract.module_name,
        contract.function_name,
        domain_hex,
        ephemeral_ek_hex,
    )
}

// ── Custom-flow verification ──────────────────────────────────────────────────

async fn verify_custom_aptos(
    contract: &AptosContractId,
    label: &[u8],
    enc_pk_bytes: &[u8],
    payload: &[u8],
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let rpc = chain_rpc.aptos_rpc_for_chain_id(contract.chain_id)?;
    let func = format!(
        "0x{}::{}::{}",
        hex::encode(contract.module_addr),
        contract.module_name,
        contract.function_name,
    );
    let label_hex = format!("0x{}", hex::encode(label));
    let enc_pk_hex = format!("0x{}", hex::encode(enc_pk_bytes));
    let payload_hex = format!("0x{}", hex::encode(payload));

    let result = rpc
        .call_view(&func, &[json!(label_hex), json!(enc_pk_hex), json!(payload_hex)])
        .await
        .map_err(|e| anyhow!("check_aptos_acl: view call failed for {}: {}", func, e))?;

    let returned = result
        .first()
        .ok_or_else(|| anyhow!("check_aptos_acl: empty view result"))?;
    if returned.as_bool() != Some(true) && returned.to_string() != "true" {
        return Err(anyhow!("check_aptos_acl: access denied (returned {:?})", returned));
    }
    Ok(())
}

async fn verify_custom_solana(
    req: &CustomFlowRequest,
    contract: &SolanaContractId,
    proof: &SolanaProofOfPermission,
    enc_pk_bytes: &[u8],
    chain_rpc: &ChainRpcConfig,
) -> Result<()> {
    let expected_program_id = solana_program_id(contract)?;
    let is_versioned = proof.inner_scheme == 1;

    validate_solana_custom_txn(
        &proof.txn_bytes,
        &expected_program_id,
        &req.keypair_id,
        req.epoch,
        enc_pk_bytes,
        &req.label,
        is_versioned,
    )?;

    let rpc_url = chain_rpc.solana_rpc_for_chain_name(&contract.known_chain_name)?;
    simulate_solana_txn(&proof.txn_bytes, &rpc_url, &chain_rpc.solana_client).await?;
    Ok(())
}

/// Validate that the Solana transaction carries the expected `CustomFullRequestBytes`.
fn validate_solana_custom_txn(
    txn: &[u8],
    expected_program_id: &[u8; 32],
    expected_keypair_id: &[u8; 32],
    expected_epoch: u64,
    expected_enc_pk: &[u8],
    expected_label: &[u8],
    is_versioned: bool,
) -> Result<()> {
    let (account_keys, instructions) = if is_versioned {
        parse_solana_txn_versioned(txn)?
    } else {
        parse_solana_txn_legacy(txn)?
    };

    if instructions.len() != 1 {
        return Err(anyhow!("Solana custom: expected exactly 1 instruction, got {}", instructions.len()));
    }
    let ix = &instructions[0];

    let prog_key = account_keys
        .get(ix.program_id_index as usize)
        .ok_or_else(|| anyhow!("Solana custom: program_id_index {} out of bounds", ix.program_id_index))?;
    if prog_key != expected_program_id {
        return Err(anyhow!("Solana custom: instruction program ID mismatch"));
    }

    // Anchor format: [8B discriminator][u32-LE vec-length][vec bytes (BCS CustomFullRequestBytes)]
    if ix.data.len() < 12 {
        return Err(anyhow!("Solana custom: instruction data too short ({}B)", ix.data.len()));
    }
    let param = &ix.data[8..];
    let vec_len = u32::from_le_bytes([param[0], param[1], param[2], param[3]]) as usize;
    if param.len() != 4 + vec_len {
        return Err(anyhow!("Solana custom: instruction data length mismatch"));
    }
    let custom_req_bytes = &param[4..4 + vec_len];

    let decoded = ace_anchor_kit::decode_custom_request(custom_req_bytes)
        .map_err(|e| anyhow!("Solana custom: decode CustomFullRequestBytes: {}", e))?;

    if &decoded.keypair_id != expected_keypair_id {
        return Err(anyhow!("Solana custom: keypair_id mismatch"));
    }
    if decoded.epoch != expected_epoch {
        return Err(anyhow!("Solana custom: epoch mismatch"));
    }
    if decoded.enc_pk.as_slice() != expected_enc_pk {
        return Err(anyhow!("Solana custom: enc_pk mismatch"));
    }
    if decoded.label.as_slice() != expected_label {
        return Err(anyhow!("Solana custom: label mismatch"));
    }
    Ok(())
}

// ── Misc helpers ──────────────────────────────────────────────────────────────

fn read_compact_u16(bytes: &[u8], start: usize) -> Result<(u16, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    let mut i = start;
    loop {
        let b = *bytes.get(i).ok_or_else(|| anyhow!("compact-u16 out of bounds at {}", i))?;
        i += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 21 {
            return Err(anyhow!("compact-u16 overflow"));
        }
    }
    if result > u16::MAX as u64 {
        return Err(anyhow!("compact-u16 overflow: {}", result));
    }
    Ok((result as u16, i - start))
}

/// Returns true if `s` is a valid hex string (optional "0x" prefix, all hex digits).
///
/// Mirrors `Hex.isValid()` in the Aptos TS SDK: a string is valid hex if—after
/// stripping the "0x" prefix—every character is a valid hex digit.
fn is_valid_hex(s: &str) -> bool {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    hex.chars().all(|c| c.is_ascii_hexdigit())
}
