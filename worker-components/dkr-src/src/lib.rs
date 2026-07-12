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
use ark_ff::{Field, Zero};
use serde_json::Value;
use tokio::sync::oneshot;
use vss_common::crypto::fr_to_le_bytes;
use vss_common::vss_types::{opening_eval_value_p_fr, opening_eval_value_r_fr};
use vss_common::{
    normalize_account_addr, parse_ed25519_signing_key_hex, should_submit_rotating_touch, AptosRpc,
    TxnArg,
};
use vss_store::{connect_vss_store, read_verified_holder_opening, VssStore};

const STATE_START_VSSS: u8 = 0;
const STATE_VSS_IN_PROGRESS: u8 = 1;
const STATE_CALC_LAGRANGE_COEFFS: u8 = 2;
const STATE_AGGREGATE_SHARE_PKS: u8 = 3;
const STATE_DONE: u8 = 4;
const STATE_FAIL: u8 = 5;

#[derive(Debug, Clone, Copy)]
struct PreviousShareOpening {
    secret: [u8; 32],
    blinding: [u8; 32],
}

#[derive(Debug, Clone)]
struct DkrSession {
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
    pub sig_sk_hex: String,
    pub vss_store_url: String,
    pub node_msg_listen: String,
}

async fn fetch_dkr_session(rpc: &AptosRpc, ace: &str, session_addr: &str) -> Result<DkrSession> {
    let data = rpc
        .get_resource_data(session_addr, &format!("{}::dkr::Session", ace))
        .await?;
    parse_dkr_session_data(&data)
}

fn parse_dkr_session_data(data: &Value) -> Result<DkrSession> {
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

    Ok(DkrSession {
        previous_session,
        current_nodes,
        vss_sessions,
        state_code,
    })
}

pub async fn run(config: RunConfig, mut shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
    let rpc = AptosRpc::new_with_gas_key(
        config.rpc_url.clone(),
        config.rpc_api_key.clone(),
        config.rpc_gas_key.clone(),
    );
    let sk = parse_ed25519_signing_key_hex(&config.account_sk_hex)?;
    let vk = sk.verifying_key();
    let account_addr = normalize_account_addr(&config.account_addr);
    let dkr_session_addr = normalize_account_addr(&config.dkr_session);
    let ace = normalize_account_addr(&config.ace_contract);
    let store = connect_vss_store(&config.vss_store_url)?;
    let _gateway =
        vss_dealer::ensure_vss_share_gateway(&rpc, &ace, &account_addr, &config.node_msg_listen)
            .await?;

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
    println!(
        "dkr-src: reconstructing share from previous session={}",
        session.previous_session
    );
    let previous_share = reconstruct_previous_share_from_store(
        &rpc,
        &ace,
        &session.previous_session,
        &account_addr,
        store.as_ref(),
    )
    .await?;
    println!(
        "dkr-src: share reconstructed successfully (my_src_idx={})",
        my_src_idx
    );

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

        let mut session = match fetch_dkr_session(&rpc, &ace, &dkr_session_addr).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("dkr-src: poll error: {:#}", e);
                continue;
            }
        };

        if session.state_code == STATE_DONE {
            println!("dkr-src: DKR session reached DONE.");
            if let Some(tx) = dealer_shutdown_tx {
                let _ = tx.send(());
            }
            return Ok(());
        }
        if session.state_code >= STATE_FAIL {
            if let Some(tx) = dealer_shutdown_tx {
                let _ = tx.send(());
            }
            return Err(anyhow!(
                "dkr-src: DKR session failed (state_code={})",
                session.state_code
            ));
        }

        let should_touch = match session.state_code {
            STATE_START_VSSS | STATE_CALC_LAGRANGE_COEFFS | STATE_AGGREGATE_SHARE_PKS => true,
            STATE_VSS_IN_PROGRESS => {
                should_submit_rotating_touch(my_src_idx, session.current_nodes.len())
            }
            _ => true,
        };
        if should_touch {
            if let Err(e) = rpc
                .submit_txn(
                    &sk,
                    &vk,
                    &account_addr,
                    &format!("{}::dkr::touch_entry", ace),
                    &[],
                    &[TxnArg::Address(&dkr_session_addr)],
                )
                .await
            {
                eprintln!("dkr-src: touch_entry error: {:#}", e);
            }

            session = match fetch_dkr_session(&rpc, &ace, &dkr_session_addr).await {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("dkr-src: poll error: {:#}", e);
                    continue;
                }
            };
        }

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
                secret_override: Some(previous_share.secret),
                previous_blinding_override: Some(previous_share.blinding),
                sig_sk_hex: Some(config.sig_sk_hex.clone()),
                vss_store_url: Some(config.vss_store_url.clone()),
                node_msg_listen: Some(config.node_msg_listen.clone()),
            };
            println!(
                "dkr-src: spawning dealer for vss_sessions[{}]={}",
                my_src_idx, session.vss_sessions[my_src_idx]
            );
            tokio::spawn(async move {
                if let Err(e) = vss_dealer::run(dealer_cfg, rx).await {
                    eprintln!("dkr-src: dealer sub-task error: {:#}", e);
                }
            });
        }

        println!(
            "dkr-src: DKR in progress (state_code={}, vss_sessions={})",
            session.state_code,
            session.vss_sessions.len()
        );
    }
}

async fn reconstruct_previous_share_from_store(
    rpc: &AptosRpc,
    ace: &str,
    session_addr: &str,
    my_addr: &str,
    store: &dyn VssStore,
) -> Result<PreviousShareOpening> {
    let session_addr = normalize_account_addr(session_addr);
    let my_addr = normalize_account_addr(my_addr);

    match rpc
        .get_resource_data(&session_addr, &format!("{}::dkr::Session", ace))
        .await
    {
        Ok(dkr_data) => reconstruct_from_dkr_store(rpc, ace, &dkr_data, &my_addr, store).await,
        Err(_) => {
            let dkg_data = rpc
                .get_resource_data(&session_addr, &format!("{}::dkg::Session", ace))
                .await
                .map_err(|e| anyhow!("not DKR and not DKG at {}: {}", session_addr, e))?;
            reconstruct_from_dkg_store(rpc, ace, &session_addr, &dkg_data, &my_addr, store).await
        }
    }
}

async fn reconstruct_from_dkg_store(
    rpc: &AptosRpc,
    ace: &str,
    session_addr: &str,
    dkg_data: &Value,
    my_addr: &str,
    store: &dyn VssStore,
) -> Result<PreviousShareOpening> {
    let workers: Vec<String> = parse_addr_array(&dkg_data["workers"])?;
    let my_idx = workers
        .iter()
        .position(|n| n == my_addr)
        .ok_or_else(|| anyhow!("my_addr {} not found in DKG workers", my_addr))?;

    let vss_sessions: Vec<String> = parse_addr_array(&dkg_data["vss_sessions"])?;
    let done_flags: Vec<bool> = parse_bool_array(&dkg_data["done_flags"])?;
    if vss_sessions.len() != done_flags.len() {
        return Err(anyhow!(
            "DKG vss_sessions.len()={} != done_flags.len()={}",
            vss_sessions.len(),
            done_flags.len()
        ));
    }

    let mut secret = Fr::zero();
    let mut blinding = Fr::zero();
    let mut num_contributions = 0usize;
    for (idx, vss_addr) in vss_sessions.iter().enumerate() {
        if !done_flags[idx] {
            continue;
        }
        let opening =
            read_verified_holder_opening(rpc, ace, store, vss_addr, my_idx as u64).await?;
        if opening.eval_position != my_idx as u64 + 1 {
            return Err(anyhow!(
                "holder opening position {} != expected {} for DKG {}",
                opening.eval_position,
                my_idx + 1,
                session_addr
            ));
        }
        secret += opening_eval_value_p_fr(&opening)?;
        blinding += opening_eval_value_r_fr(&opening)?;
        num_contributions += 1;
    }
    if num_contributions == 0 {
        return Err(anyhow!("no done VSS sessions in DKG {}", session_addr));
    }
    Ok(PreviousShareOpening {
        secret: fr_to_le_bytes(secret),
        blinding: fr_to_le_bytes(blinding),
    })
}

async fn reconstruct_from_dkr_store(
    rpc: &AptosRpc,
    ace: &str,
    dkr_data: &Value,
    my_addr: &str,
    store: &dyn VssStore,
) -> Result<PreviousShareOpening> {
    let new_nodes: Vec<String> = parse_addr_array(&dkr_data["new_nodes"])?;
    let my_idx = new_nodes
        .iter()
        .position(|n| n == my_addr)
        .ok_or_else(|| anyhow!("my_addr {} not found in DKR new_nodes", my_addr))?;

    let vss_sessions: Vec<String> = parse_addr_array(&dkr_data["vss_sessions"])?;
    let vss_contribution_flags: Vec<bool> = parse_bool_array(&dkr_data["vss_contribution_flags"])?;
    if vss_sessions.len() != vss_contribution_flags.len() {
        return Err(anyhow!(
            "DKR vss_sessions.len()={} != vss_contribution_flags.len()={}",
            vss_sessions.len(),
            vss_contribution_flags.len()
        ));
    }

    let mut secret_points = Vec::new();
    let mut blinding_points = Vec::new();
    for (idx, vss_addr) in vss_sessions.iter().enumerate() {
        if !vss_contribution_flags[idx] {
            continue;
        }
        let opening =
            read_verified_holder_opening(rpc, ace, store, vss_addr, my_idx as u64).await?;
        if opening.eval_position != my_idx as u64 + 1 {
            return Err(anyhow!(
                "holder opening position {} != expected {} for DKR VSS {}",
                opening.eval_position,
                my_idx + 1,
                vss_addr
            ));
        }
        let old_eval_position = idx as u64 + 1;
        secret_points.push((old_eval_position, opening_eval_value_p_fr(&opening)?));
        blinding_points.push((old_eval_position, opening_eval_value_r_fr(&opening)?));
    }
    if secret_points.is_empty() {
        return Err(anyhow!("no contributing VSS sessions in previous DKR"));
    }

    Ok(PreviousShareOpening {
        secret: fr_to_le_bytes(lagrange_at_zero(&secret_points)?),
        blinding: fr_to_le_bytes(lagrange_at_zero(&blinding_points)?),
    })
}

fn lagrange_at_zero(points: &[(u64, Fr)]) -> Result<Fr> {
    if points.is_empty() {
        return Err(anyhow!("lagrange_at_zero: no points"));
    }
    let mut acc = Fr::zero();
    for (i, (x_i_raw, y_i)) in points.iter().enumerate() {
        let x_i = Fr::from(*x_i_raw);
        let mut numerator = Fr::from(1u64);
        let mut denominator = Fr::from(1u64);
        for (j, (x_j_raw, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            let x_j = Fr::from(*x_j_raw);
            numerator *= -x_j;
            denominator *= x_i - x_j;
        }
        let denominator_inv = denominator
            .inverse()
            .ok_or_else(|| anyhow!("duplicate interpolation point {}", x_i_raw))?;
        acc += *y_i * numerator * denominator_inv;
    }
    Ok(acc)
}

fn parse_addr_array(v: &Value) -> Result<Vec<String>> {
    v.as_array()
        .ok_or_else(|| anyhow!("expected address array, got {:?}", v))?
        .iter()
        .map(|a| {
            a.as_str()
                .map(normalize_account_addr)
                .ok_or_else(|| anyhow!("expected string address"))
        })
        .collect()
}

fn parse_bool_array(v: &Value) -> Result<Vec<bool>> {
    v.as_array()
        .ok_or_else(|| anyhow!("expected bool array, got {:?}", v))?
        .iter()
        .map(|b| {
            b.as_bool()
                .ok_or_else(|| anyhow!("expected bool, got {:?}", b))
        })
        .collect()
}
