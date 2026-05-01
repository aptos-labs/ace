// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Proof-of-permission verification for `RequestForDecryptionKey`.
//!
//! Mirrors `verifyAndExtract` and its helpers from `ts-sdk/src/ace-ex/`:
//!   - `aptos.ts` — `verifyPermission` (verifySig + checkAuthKey + checkPermission)
//!   - `solana.ts` — `verifyPermission` (validateTxn + simulateTransaction)
//!
//! Supported combinations:
//!   Chain scheme 0 (Aptos) + proof scheme 0 (Aptos)
//!     → Ed25519 sig check, on-chain auth-key check, view-function permission check
//!   Chain scheme 1 (Solana) + proof scheme 1 (Solana)
//!     → Instruction structure check + Solana RPC simulation with sigVerify=true

use anyhow::{anyhow, Result};
use serde_json::{json, Value};

use crate::ChainRpcConfig;

// ── Parsed FDD ────────────────────────────────────────────────────────────────

/// Parsed `FullDecryptionDomain` (keypairId + ContractID + domain), extracted from the request.
pub struct ParsedFdd {
    pub keypair_id: [u8; 32],
    pub chain: ParsedChain,
    pub domain: Vec<u8>,
    /// Byte length of the ContractID+domain portion in the original request buffer (excludes keypairId).
    pub byte_len: usize,
}

pub enum ParsedChain {
    Aptos {
        chain_id: u8,
        module_addr_bytes: [u8; 32],
        module_name: String,
        function_name: String,
    },
    Solana {
        known_chain_name: String,
        program_id: [u8; 32],
    },
}

// ── Entry point ───────────────────────────────────────────────────────────────

/// Verify `proof_bytes` against `fdd`.
///
/// `chain_rpc` provides per-chain RPC endpoints for auth-key and permission checks.
pub async fn verify(fdd: &ParsedFdd, epoch: u64, ephemeral_enc_key_bytes: &[u8], proof_bytes: &[u8], chain_rpc: &ChainRpcConfig) -> Result<()> {
    let outer_scheme = proof_bytes
        .first()
        .copied()
        .ok_or_else(|| anyhow!("verify: empty proof bytes"))?;
    let inner = &proof_bytes[1..];

    match (outer_scheme, &fdd.chain) {
        (0, ParsedChain::Aptos { .. }) => {
            let proof = parse_aptos_proof(inner)?;
            verify_aptos(fdd, epoch, ephemeral_enc_key_bytes, &proof, chain_rpc).await
        }
        (1, ParsedChain::Solana { .. }) => {
            let proof = parse_solana_proof(inner)?;
            verify_solana(fdd, epoch, ephemeral_enc_key_bytes, &proof, chain_rpc).await
        }
        (s, chain) => Err(anyhow!(
            "verify: unsupported scheme combination proof={} chain={}",
            s,
            match chain {
                ParsedChain::Aptos { .. } => 0,
                ParsedChain::Solana { .. } => 1,
            }
        )),
    }
}

// ── FDD Parsing ───────────────────────────────────────────────────────────────

/// Parse the ContractID+domain portion of a `FullDecryptionDomain`.
///
/// `keypair_id` is already parsed separately (first 32 bytes of the request).
/// `bytes` points to the start of the ContractID (after keypairId and epoch).
///
/// Layout: `[outer_scheme(1B)][ContractID body][domain(BCS bytes)]`
///
/// Returns the parsed FDD, with `byte_len` = bytes consumed from `bytes` (excludes keypairId).
pub fn parse_fdd(keypair_id: [u8; 32], bytes: &[u8]) -> Result<ParsedFdd> {
    let mut pos = 0usize;

    let scheme = *bytes.get(pos).ok_or_else(|| anyhow!("FDD: missing scheme byte"))?;
    pos += 1;

    let chain = match scheme {
        0 => {
            // Aptos ContractID: chainId(1B) + moduleAddr(32B fixed) + moduleName(str) + functionName(str)
            if bytes.len() < pos + 1 + 32 {
                return Err(anyhow!("FDD: too short for Aptos ContractID"));
            }
            let chain_id = bytes[pos];
            pos += 1;
            let module_addr_bytes: [u8; 32] = bytes[pos..pos + 32]
                .try_into()
                .map_err(|_| anyhow!("FDD: moduleAddr slice"))?;
            pos += 32;
            let (module_name, n) = read_bcs_string(bytes, pos)?;
            pos += n;
            let (function_name, n) = read_bcs_string(bytes, pos)?;
            pos += n;
            ParsedChain::Aptos { chain_id, module_addr_bytes, module_name, function_name }
        }
        1 => {
            // Solana ContractID: knownChainName(str) + programId(BCS bytes = ULEB128(32)+32B)
            let (known_chain_name, n) = read_bcs_string(bytes, pos)?;
            pos += n;
            let (pid_len, n) = read_uleb128(bytes, pos)?;
            pos += n;
            if pid_len != 32 {
                return Err(anyhow!("FDD: Solana programId length {} != 32", pid_len));
            }
            if bytes.len() < pos + 32 {
                return Err(anyhow!("FDD: Solana programId truncated"));
            }
            let program_id: [u8; 32] = bytes[pos..pos + 32]
                .try_into()
                .map_err(|_| anyhow!("FDD: programId slice"))?;
            pos += 32;
            ParsedChain::Solana { known_chain_name, program_id }
        }
        _ => return Err(anyhow!("FDD: unknown chain scheme {}", scheme)),
    };

    // Domain: BCS bytes = ULEB128(len) + raw bytes
    let (domain_len, n) = read_uleb128(bytes, pos)?;
    pos += n;
    if bytes.len() < pos + domain_len as usize {
        return Err(anyhow!("FDD: domain truncated"));
    }
    let domain = bytes[pos..pos + domain_len as usize].to_vec();
    pos += domain_len as usize;

    Ok(ParsedFdd { keypair_id, chain, domain, byte_len: pos })
}

// ── Aptos Proof Parsing ───────────────────────────────────────────────────────

struct AptosProof {
    user_addr: [u8; 32],
    pk_scheme: u8,
    pubkey_bytes: Vec<u8>,  // raw bytes, no length prefix
    sig_scheme: u8,
    sig_bytes: Vec<u8>,     // raw bytes, no length prefix
    full_message: String,
}

/// Parse the inner `AptosProofOfPermission` bytes (outer scheme byte already consumed).
///
/// Layout:
///   userAddr (32B fixed AccountAddress)
///   publicKeyScheme (1B)
///   publicKey (BCS bytes: ULEB128(len)+raw)
///   signatureScheme (1B)
///   signature (BCS bytes: ULEB128(len)+raw)
///   fullMessage (BCS string: ULEB128(len)+UTF-8)
fn parse_aptos_proof(bytes: &[u8]) -> Result<AptosProof> {
    let mut pos = 0usize;

    if bytes.len() < pos + 32 {
        return Err(anyhow!("AptosProof: too short for userAddr"));
    }
    let user_addr: [u8; 32] = bytes[pos..pos + 32]
        .try_into()
        .map_err(|_| anyhow!("AptosProof: userAddr slice"))?;
    pos += 32;

    let pk_scheme = *bytes.get(pos).ok_or_else(|| anyhow!("AptosProof: missing pk scheme"))?;
    pos += 1;

    let (pk_len, n) = read_uleb128(bytes, pos)?;
    pos += n;
    if bytes.len() < pos + pk_len as usize {
        return Err(anyhow!("AptosProof: pubkey truncated"));
    }
    let pubkey_bytes = bytes[pos..pos + pk_len as usize].to_vec();
    pos += pk_len as usize;

    let sig_scheme = *bytes.get(pos).ok_or_else(|| anyhow!("AptosProof: missing sig scheme"))?;
    pos += 1;

    let (sig_len, n) = read_uleb128(bytes, pos)?;
    pos += n;
    if bytes.len() < pos + sig_len as usize {
        return Err(anyhow!("AptosProof: signature truncated"));
    }
    let sig_bytes = bytes[pos..pos + sig_len as usize].to_vec();
    pos += sig_len as usize;

    let (msg_len, n) = read_uleb128(bytes, pos)?;
    pos += n;
    if bytes.len() < pos + msg_len as usize {
        return Err(anyhow!("AptosProof: fullMessage truncated"));
    }
    let full_message = String::from_utf8(bytes[pos..pos + msg_len as usize].to_vec())
        .map_err(|e| anyhow!("AptosProof: fullMessage not UTF-8: {}", e))?;
    pos += msg_len as usize;

    if pos != bytes.len() {
        return Err(anyhow!(
            "AptosProof: trailing bytes ({} extra)",
            bytes.len() - pos
        ));
    }

    Ok(AptosProof { user_addr, pk_scheme, pubkey_bytes, sig_scheme, sig_bytes, full_message })
}

// ── Solana Proof Parsing ──────────────────────────────────────────────────────

struct SolanaProof {
    inner_scheme: u8, // 0 = legacy/unversioned, 1 = versioned
    txn_bytes: Vec<u8>,
}

/// Parse the inner `SolanaProofOfPermission` bytes (outer scheme byte already consumed).
///
/// Layout:
///   inner_scheme (1B: 0=unversioned, 1=versioned)
///   txn_bytes (BCS bytes: ULEB128(len)+raw)
fn parse_solana_proof(bytes: &[u8]) -> Result<SolanaProof> {
    let mut pos = 0usize;

    let inner_scheme =
        *bytes.get(pos).ok_or_else(|| anyhow!("SolanaProof: missing inner scheme"))?;
    pos += 1;

    let (txn_len, n) = read_uleb128(bytes, pos)?;
    pos += n;
    if bytes.len() < pos + txn_len as usize {
        return Err(anyhow!("SolanaProof: txn bytes truncated"));
    }
    let txn_bytes = bytes[pos..pos + txn_len as usize].to_vec();
    pos += txn_len as usize;

    if pos != bytes.len() {
        return Err(anyhow!(
            "SolanaProof: trailing bytes ({} extra)",
            bytes.len() - pos
        ));
    }

    Ok(SolanaProof { inner_scheme, txn_bytes })
}

// ── Aptos Verification ────────────────────────────────────────────────────────

async fn verify_aptos(fdd: &ParsedFdd, epoch: u64, ephemeral_enc_key_bytes: &[u8], proof: &AptosProof, chain_rpc: &ChainRpcConfig) -> Result<()> {
    // Only legacy Ed25519 (pk_scheme=0, sig_scheme=0) is currently supported.
    if proof.pk_scheme != 0 {
        return Err(anyhow!("verify_aptos: unsupported public key scheme {}", proof.pk_scheme));
    }
    if proof.sig_scheme != 0 {
        return Err(anyhow!("verify_aptos: unsupported signature scheme {}", proof.sig_scheme));
    }
    if proof.pubkey_bytes.len() != 32 {
        return Err(anyhow!(
            "verify_aptos: Ed25519 pubkey must be 32 bytes, got {}",
            proof.pubkey_bytes.len()
        ));
    }
    if proof.sig_bytes.len() != 64 {
        return Err(anyhow!(
            "verify_aptos: Ed25519 sig must be 64 bytes, got {}",
            proof.sig_bytes.len()
        ));
    }

    let pk_arr: [u8; 32] = proof.pubkey_bytes.as_slice().try_into().unwrap();
    let vk = ed25519_dalek::VerifyingKey::from_bytes(&pk_arr)
        .map_err(|e| anyhow!("verify_aptos: invalid Ed25519 pubkey: {}", e))?;

    let sig_arr: [u8; 64] = proof.sig_bytes.as_slice().try_into().unwrap();
    let sig = ed25519_dalek::Signature::from_bytes(&sig_arr);

    // Run 3 checks: sig, auth-key, permission.
    // verifySig is cheap and synchronous — fail fast before hitting RPC.
    verify_aptos_sig(fdd, epoch, ephemeral_enc_key_bytes, proof, &vk, &sig)?;

    let chain_id = match &fdd.chain {
        ParsedChain::Aptos { chain_id, .. } => *chain_id,
        _ => unreachable!(),
    };
    let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;

    // auth-key and permission checks are independent RPC calls; run them concurrently.
    let (auth_result, perm_result) = tokio::join!(
        check_aptos_auth_key(proof, &vk, rpc),
        check_aptos_permission(fdd, proof, rpc),
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
    fdd: &ParsedFdd,
    epoch: u64,
    ephemeral_enc_key_bytes: &[u8],
    proof: &AptosProof,
    vk: &ed25519_dalek::VerifyingKey,
    sig: &ed25519_dalek::Signature,
) -> Result<()> {
    use ed25519_dalek::Verifier;

    let pretty_msg = aptos_decryption_request_message(fdd, epoch, ephemeral_enc_key_bytes)?;
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
    proof: &AptosProof,
    vk: &ed25519_dalek::VerifyingKey,
    rpc: &vss_common::AptosRpc,
) -> Result<()> {
    // For legacy Ed25519 (scheme=0): auth_key = SHA3-256(pubkey_bytes || 0x00)
    // This is identical to `vss_common::compute_account_address`.
    let computed = vss_common::compute_account_address(vk);

    let user_addr_str = format!("0x{}", hex::encode(&proof.user_addr));
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
    fdd: &ParsedFdd,
    proof: &AptosProof,
    rpc: &vss_common::AptosRpc,
) -> Result<()> {
    let (module_addr_bytes, module_name, function_name) = match &fdd.chain {
        ParsedChain::Aptos { module_addr_bytes, module_name, function_name, .. } => {
            (module_addr_bytes, module_name.as_str(), function_name.as_str())
        }
        _ => return Err(anyhow!("check_aptos_permission: chain is not Aptos")),
    };

    let func = format!("0x{}::{}::{}", hex::encode(module_addr_bytes), module_name, function_name);
    let user_addr = format!("0x{}", hex::encode(&proof.user_addr));
    let domain_hex = format!("0x{}", hex::encode(&fdd.domain));

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

// ── Solana Verification ───────────────────────────────────────────────────────

async fn verify_solana(fdd: &ParsedFdd, epoch: u64, ephemeral_enc_key_bytes: &[u8], proof: &SolanaProof, chain_rpc: &ChainRpcConfig) -> Result<()> {
    let (known_chain_name, expected_program_id) = match &fdd.chain {
        ParsedChain::Solana { known_chain_name, program_id } => {
            (known_chain_name.as_str(), program_id)
        }
        _ => return Err(anyhow!("verify_solana: chain is not Solana")),
    };

    // NOTE: do NOT detect is_versioned from the first byte of txn_bytes.  A serialized
    // VersionedTransaction starts with the compact-u16 signature count (e.g. 0x01 for
    // one signature), NOT the v0 prefix byte (0x80).  The v0 prefix byte lives inside
    // the serialised message, after the signatures.  Only `inner_scheme` is reliable.
    let is_versioned = proof.inner_scheme == 1;

    // 1. Structural validation: instruction count, program ID, full_request_bytes in data.
    let expected = ace_anchor_kit::build_full_request_bytes(&fdd.keypair_id, epoch, ephemeral_enc_key_bytes, &fdd.domain);
    validate_solana_txn(&proof.txn_bytes, expected_program_id, &expected, is_versioned)?;

    // 2. Signature + program execution via RPC simulation.
    let rpc_url = chain_rpc.solana_rpc_for_chain_name(known_chain_name)?;
    simulate_solana_txn(&proof.txn_bytes, &rpc_url, &chain_rpc.solana_client).await?;

    Ok(())
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
    if param.len() < 4 + vec_len {
        return Err(anyhow!("Solana: instruction data truncated"));
    }
    if param.len() != 4 + vec_len {
        return Err(anyhow!("Solana: unexpected extra bytes in instruction data"));
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
fn aptos_decryption_request_message(fdd: &ParsedFdd, epoch: u64, ephemeral_enc_key_bytes: &[u8]) -> Result<String> {
    let (chain_id, module_addr_bytes, module_name, function_name) = match &fdd.chain {
        ParsedChain::Aptos { chain_id, module_addr_bytes, module_name, function_name } => {
            (chain_id, module_addr_bytes, module_name.as_str(), function_name.as_str())
        }
        _ => return Err(anyhow!("aptos_decryption_request_message: chain is not Aptos")),
    };

    // moduleAddr.toStringLong() = "0x" + 64 lowercase hex chars (32 bytes)
    let module_addr = format!("0x{}", hex::encode(module_addr_bytes));
    let domain_hex = format!("0x{}", hex::encode(&fdd.domain));
    // `pke.EncryptionKey.toHex()` = bytesToHex(toBytes()) where toBytes() writes
    // [scheme(1B)][inner...]; for scheme 0 the wire form is exactly 67 bytes, identical
    // to the slice carried in the request body.  Note: `toHex()` does NOT prepend "0x"
    // (unlike AccountAddress.toStringLong() or the explicit "0x" on the domain line).
    let ephemeral_ek_hex = hex::encode(ephemeral_enc_key_bytes);

    // Matches DecryptionRequestPayload.toPrettyMessage(indent=0):
    //   "ACE Decryption Request"
    //   "\nkeypairId: 0x{keypairIdHex}"
    //   "\nepoch: {epoch}"
    //   "\ncontractId:"
    //   ContractID.toPrettyMessage(indent=1):          pad="  "
    //     "\n  scheme: aptos"
    //     "\n  inner:"
    //     AptosContractID.toPrettyMessage(indent=3):   pad="      "
    //       "\n      chainId: {chainId}"
    //       "\n      moduleAddr: {moduleAddr}"
    //       "\n      moduleName: {moduleName}"
    //       "\n      functionName: {functionName}"
    //   "\ndomain: 0x{domainHex}"
    //   "\nephemeralEncKey: 0x{ephemeralEncKeyHex}"
    let keypair_id_hex = format!("0x{}", hex::encode(fdd.keypair_id));
    Ok(format!(
        "ACE Decryption Request\nkeypairId: {}\nepoch: {}\ncontractId:\n  scheme: aptos\n  inner:\n      chainId: {}\n      moduleAddr: {}\n      moduleName: {}\n      functionName: {}\ndomain: {}\nephemeralEncKey: {}",
        keypair_id_hex, epoch, chain_id, module_addr, module_name, function_name, domain_hex, ephemeral_ek_hex,
    ))
}

// ── Custom-flow verification ──────────────────────────────────────────────────

/// Verify a `CustomFlowProof` for a `CustomFlowRequest`.
///
/// `enc_pk_bytes` is the caller's PKE public key (67B), passed as-is to `check_acl`.
/// `proof_bytes` starts with the proof scheme byte.
pub async fn verify_custom(fdd: &ParsedFdd, epoch: u64, enc_pk_bytes: &[u8], proof_bytes: &[u8], chain_rpc: &ChainRpcConfig) -> Result<()> {
    let outer_scheme = proof_bytes
        .first()
        .copied()
        .ok_or_else(|| anyhow!("verify_custom: empty proof bytes"))?;
    let inner = &proof_bytes[1..];

    match (outer_scheme, &fdd.chain) {
        (0, ParsedChain::Aptos { .. }) => {
            let (payload, _) = read_bcs_bytes_at(inner, 0)?;
            verify_custom_aptos(fdd, enc_pk_bytes, &payload, chain_rpc).await
        }
        (1, ParsedChain::Solana { .. }) => {
            let proof = parse_solana_proof(inner)?;
            verify_custom_solana(fdd, epoch, enc_pk_bytes, &proof, chain_rpc).await
        }
        (s, chain) => Err(anyhow!(
            "verify_custom: unsupported scheme combination proof={} chain={}",
            s,
            match chain {
                ParsedChain::Aptos { .. } => 0,
                ParsedChain::Solana { .. } => 1,
            }
        )),
    }
}

async fn verify_custom_aptos(fdd: &ParsedFdd, enc_pk_bytes: &[u8], payload: &[u8], chain_rpc: &ChainRpcConfig) -> Result<()> {
    let (chain_id, module_addr_bytes, module_name, function_name) = match &fdd.chain {
        ParsedChain::Aptos { chain_id, module_addr_bytes, module_name, function_name } => {
            (*chain_id, module_addr_bytes, module_name.as_str(), function_name.as_str())
        }
        _ => return Err(anyhow!("verify_custom_aptos: chain is not Aptos")),
    };
    let rpc = chain_rpc.aptos_rpc_for_chain_id(chain_id)?;
    check_aptos_acl(fdd, enc_pk_bytes, payload, module_addr_bytes, module_name, function_name, rpc).await
}

/// Calls `{moduleAddr}::{moduleName}::{functionName}(label, encPk, payload)` and expects `true`.
async fn check_aptos_acl(
    fdd: &ParsedFdd,
    enc_pk_bytes: &[u8],
    payload: &[u8],
    module_addr_bytes: &[u8; 32],
    module_name: &str,
    function_name: &str,
    rpc: &vss_common::AptosRpc,
) -> Result<()> {
    let func = format!("0x{}::{}::{}", hex::encode(module_addr_bytes), module_name, function_name);
    let label_hex = format!("0x{}", hex::encode(&fdd.domain));
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

async fn verify_custom_solana(fdd: &ParsedFdd, epoch: u64, enc_pk_bytes: &[u8], proof: &SolanaProof, chain_rpc: &ChainRpcConfig) -> Result<()> {
    let (known_chain_name, expected_program_id) = match &fdd.chain {
        ParsedChain::Solana { known_chain_name, program_id } => (known_chain_name.as_str(), program_id),
        _ => return Err(anyhow!("verify_custom_solana: chain is not Solana")),
    };

    let is_versioned = proof.inner_scheme == 1;
    validate_solana_custom_txn(
        &proof.txn_bytes,
        expected_program_id,
        &fdd.keypair_id,
        epoch,
        enc_pk_bytes,
        &fdd.domain,
        is_versioned,
    )?;

    let rpc_url = chain_rpc.solana_rpc_for_chain_name(known_chain_name)?;
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

// ── BCS / binary helpers ──────────────────────────────────────────────────────

/// Read a BCS-encoded `Vec<u8>` (ULEB128 length + bytes) starting at `pos`.
///
/// Returns `(bytes, bytes_consumed)`.
fn read_bcs_bytes_at(bytes: &[u8], pos: usize) -> Result<(Vec<u8>, usize)> {
    let (len, n) = read_uleb128(bytes, pos)?;
    let end = pos + n + len as usize;
    if bytes.len() < end {
        return Err(anyhow!("BCS bytes truncated at pos {}", pos));
    }
    Ok((bytes[pos + n..end].to_vec(), n + len as usize))
}

fn read_bcs_string(bytes: &[u8], start: usize) -> Result<(String, usize)> {
    let (len, n) = read_uleb128(bytes, start)?;
    let end = start + n + len as usize;
    if bytes.len() < end {
        return Err(anyhow!("BCS string truncated at pos {}", start));
    }
    let s = std::str::from_utf8(&bytes[start + n..end])
        .map_err(|e| anyhow!("BCS string not UTF-8: {}", e))?
        .to_string();
    Ok((s, n + len as usize))
}

pub fn read_uleb128(bytes: &[u8], start: usize) -> Result<(u64, usize)> {
    let mut result = 0u64;
    let mut shift = 0u32;
    let mut i = start;
    loop {
        let b = *bytes.get(i).ok_or_else(|| anyhow!("ULEB128 out of bounds at {}", i))?;
        i += 1;
        result |= ((b & 0x7f) as u64) << shift;
        if b & 0x80 == 0 {
            break;
        }
        shift += 7;
        if shift > 63 {
            return Err(anyhow!("ULEB128 overflow"));
        }
    }
    Ok((result, i - start))
}

fn read_compact_u16(bytes: &[u8], start: usize) -> Result<(u16, usize)> {
    let (v, n) = read_uleb128(bytes, start)?;
    if v > u16::MAX as u64 {
        return Err(anyhow!("compact-u16 overflow: {}", v));
    }
    Ok((v as u16, n))
}

/// Returns true if `s` is a valid hex string (optional "0x" prefix, all hex digits).
///
/// Mirrors `Hex.isValid()` in the Aptos TS SDK: a string is valid hex if—after
/// stripping the "0x" prefix—every character is a valid hex digit.
fn is_valid_hex(s: &str) -> bool {
    let hex = s.strip_prefix("0x").unwrap_or(s);
    hex.chars().all(|c| c.is_ascii_hexdigit())
}
