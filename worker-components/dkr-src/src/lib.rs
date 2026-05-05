// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Programmatic API for the DKR old-committee dealer client.
//! Each old-committee member:
//!   1. Reconstructs their DKG share by decrypting sub-shares from DKG VSS sessions.
//!   2. Spawns one VSS dealer (for their DKR VSS session), using the DKG share as the secret.
//!   3. Polls the DKR session until it completes.
//!
//! VSS sessions are created lazily on-chain (one per `dkr::touch`), so the dealer is only
//! spawned once `vss_sessions[my_src_idx]` appears on-chain.

use anyhow::{anyhow, Result};
use ark_bls12_381::Fr;
use serde_json::Value;
use tokio::sync::oneshot;
use vss_common::{
    crypto::{fr_from_le_bytes, fr_to_le_bytes},
    normalize_account_addr,
    pke::pke_decrypt_bcs,
    parse_ed25519_signing_key_hex,
    reconstruct_share,
    AptosRpc,
    TxnArg,
};

const STATE_DONE: u8 = 4;
const STATE_FAIL: u8 = 5;

#[derive(Debug, Clone)]
struct DkrSession {
    original_session: String,
    previous_session: String,
    current_nodes: Vec<String>,
    vss_sessions: Vec<String>,
    state_code: u8,
}

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub rpc_url: String,
    pub rpc_api_key: Option<String>,
    pub rpc_gas_key: Option<String>,
    pub ace_contract: String,
    pub dkr_session: String,
    pub account_addr: String,
    pub account_sk_hex: String,
    pub pke_dk_hex: String,
}

async fn fetch_dkr_session(rpc: &AptosRpc, ace: &str, session_addr: &str) -> Result<DkrSession> {
    let data = rpc
        .get_resource_data(session_addr, &format!("{}::dkr::Session", ace))
        .await?;
    parse_dkr_session_data(&data)
}

fn parse_dkr_session_data(data: &Value) -> Result<DkrSession> {
    let original_session = normalize_account_addr(
        data["original_session"]
            .as_str()
            .ok_or_else(|| anyhow!("missing original_session in DKR session"))?,
    );

    let previous_session = normalize_account_addr(
        data["previous_session"]
            .as_str()
            .ok_or_else(|| anyhow!("missing previous_session in DKR session"))?,
    );

    let current_nodes = data["current_nodes"]
        .as_array()
        .ok_or_else(|| anyhow!("missing current_nodes in DKR session"))?
        .iter()
        .map(|v| normalize_account_addr(v.as_str().unwrap_or("")))
        .collect();

    let vss_sessions = data["vss_sessions"]
        .as_array()
        .ok_or_else(|| anyhow!("missing vss_sessions in DKR session"))?
        .iter()
        .map(|v| normalize_account_addr(v.as_str().unwrap_or("")))
        .collect();

    let state_code: u8 = match &data["state_code"] {
        Value::Number(n) => n.as_u64().unwrap_or(0) as u8,
        Value::String(s) => s.parse().unwrap_or(0),
        _ => return Err(anyhow!("missing or invalid state_code in DKR session")),
    };

    Ok(DkrSession { original_session, previous_session, current_nodes, vss_sessions, state_code })
}

/// Reconstruct the old committee member's DKG share by summing decrypted sub-shares
/// from the contributing DKG VSS sessions.
///
/// Looks up `my_addr`'s position in the VSS session's `share_holders` so the correct
/// index is used regardless of which epoch committee is calling.
async fn reconstruct_dkg_share(
    rpc: &AptosRpc,
    ace: &str,
    original_dkg_session: &str,
    my_addr: &str,
    pke_dk_bytes: &[u8],
) -> Result<[u8; 32]> {
    let my_addr_bytes: [u8; 32] = hex::decode(my_addr.trim_start_matches("0x"))
        .map_err(|e| anyhow!("my_addr hex decode '{}': {}", my_addr, e))?
        .try_into()
        .map_err(|_| anyhow!("my_addr '{}' must be 32 bytes", my_addr))?;

    // Fetch DKG session JSON.
    let dkg_data = rpc
        .get_resource_data(original_dkg_session, &format!("{}::dkg::Session", ace))
        .await?;

    let dkg_vss_sessions: Vec<String> = dkg_data["vss_sessions"]
        .as_array()
        .ok_or_else(|| anyhow!("missing vss_sessions in DKG session"))?
        .iter()
        .map(|v| normalize_account_addr(v.as_str().unwrap_or("")))
        .collect();

    // Parse done_flags to know which VSS sessions contributed to the DKG secret.
    let done_flags: Vec<bool> = dkg_data["done_flags"]
        .as_array()
        .ok_or_else(|| anyhow!("missing done_flags in DKG session"))?
        .iter()
        .map(|v| v.as_bool().unwrap_or(false))
        .collect();

    if dkg_vss_sessions.len() != done_flags.len() {
        return Err(anyhow!(
            "DKG vss_sessions length {} != done_flags length {}",
            dkg_vss_sessions.len(),
            done_flags.len()
        ));
    }

    // Sum sub-shares from contributing VSS sessions.
    let mut dkg_share_fr = Fr::from(0u64);
    let mut my_dkg_idx: Option<usize> = None;

    for (k, vss_addr) in dkg_vss_sessions.iter().enumerate() {
        if !done_flags[k] {
            continue; // Skip non-contributing VSS sessions.
        }

        let bcs_session = rpc.get_session_bcs_decoded(ace, vss_addr).await
            .map_err(|e| anyhow!("failed to BCS-decode DKG VSS session {}: {}", vss_addr, e))?;

        // Find my position in share_holders on the first done session.
        if my_dkg_idx.is_none() {
            my_dkg_idx = bcs_session.share_holders.iter().position(|h| h == &my_addr_bytes);
            if my_dkg_idx.is_none() {
                return Err(anyhow!(
                    "my_addr {} not found in share_holders of DKG VSS {}",
                    my_addr, vss_addr
                ));
            }
        }
        let idx = my_dkg_idx.unwrap();

        let dc0 = bcs_session
            .dealer_contribution_0
            .ok_or_else(|| anyhow!("DKG VSS session {} (done_flags[{}]=true) has no DC0", vss_addr, k))?;

        let ct = dc0
            .private_share_messages
            .get(idx)
            .ok_or_else(|| anyhow!(
                "DKG VSS session {} has only {} share messages, need index {}",
                vss_addr, dc0.private_share_messages.len(), idx
            ))?;

        let plaintext = pke_decrypt_bcs(pke_dk_bytes, ct)
            .map_err(|e| anyhow!("DKG VSS session {} decryption failed: {}", vss_addr, e))?;

        // Parse private share message: [u8 scheme][ULEB128(32)=0x20][32B Fr LE].
        // Scheme byte may be 0x00 (G1) or 0x01 (G2); Fr is the same field so the y-bytes are
        // identical regardless of which group's commitment they were Feldman-checked against.
        if plaintext.len() < 34
            || (plaintext[0] != vss_common::session::SCHEME_BLS12381G1
                && plaintext[0] != vss_common::session::SCHEME_BLS12381G2)
            || plaintext[1] != 0x20
        {
            return Err(anyhow!(
                "DKG VSS session {} invalid share message format (len={}, prefix={:02x} {:02x})",
                vss_addr, plaintext.len(),
                plaintext.get(0).copied().unwrap_or(0xff),
                plaintext.get(1).copied().unwrap_or(0xff),
            ));
        }
        let y_bytes: [u8; 32] = plaintext[2..34]
            .try_into()
            .map_err(|_| anyhow!("share bytes wrong length"))?;

        dkg_share_fr += fr_from_le_bytes(y_bytes);
    }

    if my_dkg_idx.is_none() {
        return Err(anyhow!("no done VSS sessions in DKG {}", original_dkg_session));
    }

    Ok(fr_to_le_bytes(dkg_share_fr))
}

pub async fn run(config: RunConfig, mut shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
    let rpc = AptosRpc::new_with_gas_key(config.rpc_url.clone(), config.rpc_api_key.clone(), config.rpc_gas_key.clone());
    let sk = parse_ed25519_signing_key_hex(&config.account_sk_hex)?;
    let vk = sk.verifying_key();
    let account_addr = normalize_account_addr(&config.account_addr);
    let dkr_session_addr = normalize_account_addr(&config.dkr_session);
    let ace = normalize_account_addr(&config.ace_contract);

    let pke_dk_bytes = hex::decode(config.pke_dk_hex.trim_start_matches("0x"))
        .map_err(|e| anyhow!("invalid pke_dk_hex: {}", e))?;

    println!(
        "dkr-src: starting (account={} dkr_session={} ace={})",
        account_addr, dkr_session_addr, ace
    );

    let session = fetch_dkr_session(&rpc, &ace, &dkr_session_addr).await?;

    let my_src_idx = session
        .current_nodes
        .iter()
        .position(|n| *n == account_addr)
        .ok_or_else(|| anyhow!("account {} not found in DKR current_nodes", account_addr))?;

    // Reconstruct share immediately — previous_session is always DONE when dkr::new_session runs.
    println!("dkr-src: reconstructing share from previous session={}", session.previous_session);
    let (dkg_share_bytes, _, _) = reconstruct_share(
        &rpc,
        &ace,
        &session.previous_session,
        &account_addr,
        &pke_dk_bytes,
    )
    .await?;
    println!("dkr-src: share reconstructed successfully (my_src_idx={})", my_src_idx);

    // Dealer is spawned once vss_sessions[my_src_idx] appears on-chain (lazy VSS fan-out).
    let mut dealer_shutdown_tx: Option<oneshot::Sender<()>> = None;

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                println!("dkr-src: shutdown signal received.");
                if let Some(tx) = dealer_shutdown_tx { let _ = tx.send(()); }
                return Ok(());
            }
            _ = interval.tick() => {}
        }

        // touch advances START_VSSS (one VSS per call) and later other DKR states.
        if let Err(e) = rpc.submit_txn(
            &sk, &vk, &account_addr,
            &format!("{}::dkr::touch_entry", ace), &[],
            &[TxnArg::Address(&dkr_session_addr)],
        ).await {
            eprintln!("dkr-src: touch_entry error: {:#}", e);
        }

        let session = match fetch_dkr_session(&rpc, &ace, &dkr_session_addr).await {
            Ok(s) => s,
            Err(e) => { eprintln!("dkr-src: poll error: {:#}", e); continue; }
        };

        // Spawn dealer for vss_sessions[my_src_idx] once it appears.
        if dealer_shutdown_tx.is_none() && session.vss_sessions.len() > my_src_idx {
            let (tx, rx) = oneshot::channel::<()>();
            dealer_shutdown_tx = Some(tx);
            let dealer_cfg = vss_dealer::RunConfig {
                rpc_url: config.rpc_url.clone(),
                rpc_api_key: config.rpc_api_key.clone(),
                rpc_gas_key: config.rpc_gas_key.clone(),
                ace_contract: ace.clone(),
                vss_session: session.vss_sessions[my_src_idx].clone(),
                pke_dk_hex: config.pke_dk_hex.clone(),
                account_addr: account_addr.clone(),
                account_sk_hex: config.account_sk_hex.clone(),
                secret_override: Some(dkg_share_bytes),
            };
            println!("dkr-src: spawning dealer for vss_sessions[{}]={}", my_src_idx, session.vss_sessions[my_src_idx]);
            tokio::spawn(async move {
                if let Err(e) = vss_dealer::run(dealer_cfg, rx).await {
                    eprintln!("dkr-src: dealer sub-task error: {:#}", e);
                }
            });
        }

        if session.state_code == STATE_DONE {
            println!("dkr-src: DKR session reached DONE.");
            if let Some(tx) = dealer_shutdown_tx { let _ = tx.send(()); }
            return Ok(());
        }
        if session.state_code >= STATE_FAIL {
            if let Some(tx) = dealer_shutdown_tx { let _ = tx.send(()); }
            return Err(anyhow!("dkr-src: DKR session failed (state_code={})", session.state_code));
        }
        println!("dkr-src: DKR in progress (state_code={}, vss_sessions={})", session.state_code, session.vss_sessions.len());
    }
}
