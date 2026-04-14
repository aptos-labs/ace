// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Programmatic API for the on-chain VSS dealer client.
//! `main.rs` is a thin CLI wrapper over [`run`].

use anyhow::{anyhow, Result};
use ark_bls12_381::Fr;
use serde_json::json;
use tokio::sync::oneshot;
use vss_common::aptos::json_move_vec_u8_hex;
use vss_common::crypto::{fr_from_dk_bytes, fr_to_le_bytes, g1_compressed, pke_encrypt, poly_eval};
use vss_common::session::{ACK_WINDOW_MICROS, STATE_DEALER_DEAL, STATE_FAILED, STATE_RECIPIENT_ACK, STATE_SUCCESS};
use vss_common::vss_types::{
    dc0_bytes, dc1_bytes, private_share_message_bytes, DealerState, PcsBatchOpening, PcsCommitment,
    PcsOpening, SecretShare,
};
use vss_common::{normalize_account_addr, parse_ed25519_signing_key_hex, AptosRpc};

pub const POLL_SECS: u64 = 5;

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub rpc_url: String,
    pub ace_contract: String,
    pub vss_session: String,
    pub account_addr: String,
    pub account_sk_hex: String,
    /// BCS-encoded PKE decryption key (scheme byte + inner), hex with optional 0x prefix.
    pub pke_dk_hex: String,
}

/// Dealer state machine.
///
/// Performs real BLS12-381 Fr polynomial dealing:
/// - STATE_DEALER_DEAL: fetches recipient enc keys, computes polynomial, encrypts shares,
///   encrypts dealer state, builds and submits `dealer_contribution_0`.
/// - STATE_RECIPIENT_ACK: re-derives polynomial, builds batch opening, submits `on_dealer_open`.
///
/// Exits cleanly when the session reaches `STATE__SUCCESS`.
/// Returns `Err` on `STATE__FAILED`, wrong dealer, or unrecoverable errors.
pub async fn run(config: RunConfig, mut shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
    let rpc = AptosRpc::new(config.rpc_url.clone());
    let sk = parse_ed25519_signing_key_hex(&config.account_sk_hex)?;
    let vk = sk.verifying_key();

    let account_addr = normalize_account_addr(&config.account_addr);
    let session_addr = normalize_account_addr(&config.vss_session);
    let ace = normalize_account_addr(&config.ace_contract);

    // Parse the PKE decryption key bytes (used as seed for polynomial derivation).
    let pke_dk_bytes = hex::decode(config.pke_dk_hex.trim_start_matches("0x"))
        .map_err(|e| anyhow!("invalid pke_dk_hex: {}", e))?;

    println!(
        "vss-dealer: starting (account={} session={} ace={})",
        account_addr, session_addr, ace
    );

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(POLL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // Wait for next poll tick or shutdown — first tick fires immediately.
        tokio::select! {
            _ = &mut shutdown_rx => {
                println!("vss-dealer: shutdown signal received, exiting.");
                return Ok(());
            }
            _ = interval.tick() => {}
        }

        let session = match rpc.get_vss_session_resource(&ace, &session_addr).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("vss-dealer: poll error: {:#}", e);
                continue;
            }
        };

        if session.dealer != account_addr {
            return Err(anyhow!(
                "vss-dealer: I am not the dealer (session.dealer={}, me={})",
                session.dealer,
                account_addr
            ));
        }

        match session.state_code {
            STATE_DEALER_DEAL => {
                if session.dealer_contribution_0.is_empty() {
                    println!("vss-dealer: building dealer_contribution_0");
                    match build_and_submit_dc0(
                        &rpc,
                        &sk,
                        &vk,
                        &account_addr,
                        &session_addr,
                        &ace,
                        &session,
                        &pke_dk_bytes,
                    )
                    .await
                    {
                        Ok(h) => println!("vss-dealer: on_dealer_contribution_0 confirmed: {}", h),
                        Err(e) => eprintln!("vss-dealer: on_dealer_contribution_0 error: {:#}", e),
                    }
                }
            }
            STATE_RECIPIENT_ACK => {
                let ledger_ts = match rpc.get_ledger_timestamp_micros().await {
                    Ok(ts) => ts,
                    Err(e) => {
                        eprintln!("vss-dealer: get_ledger_timestamp_micros error: {:#}", e);
                        0 // will fail the gate below; retry next poll
                    }
                };
                let open_after = session.deal_time_micros + ACK_WINDOW_MICROS;
                if ledger_ts > open_after {
                    if session.dealer_contribution_1.is_empty() {
                        println!(
                            "vss-dealer: building on_dealer_open (ledger_ts={} open_after={})",
                            ledger_ts, open_after
                        );
                        match build_and_submit_dc1(
                            &rpc,
                            &sk,
                            &vk,
                            &account_addr,
                            &session_addr,
                            &ace,
                            &session,
                            &pke_dk_bytes,
                        )
                        .await
                        {
                            Ok(h) => println!("vss-dealer: on_dealer_open confirmed: {}", h),
                            Err(e) => eprintln!("vss-dealer: on_dealer_open error: {:#}", e),
                        }
                    }
                } else {
                    println!(
                        "vss-dealer: waiting for ack window (ledger_ts={} open_after={})",
                        ledger_ts, open_after
                    );
                }
            }
            STATE_SUCCESS => {
                println!("vss-dealer: session reached SUCCESS.");
                return Ok(());
            }
            STATE_FAILED => {
                return Err(anyhow!("vss-dealer: session FAILED"));
            }
            other => {
                return Err(anyhow!("vss-dealer: unknown state_code {}", other));
            }
        }
    }
}

/// Fetch enc keys, build polynomial, encrypt shares + dealer state, submit dc0.
async fn build_and_submit_dc0(
    rpc: &AptosRpc,
    sk: &ed25519_dalek::SigningKey,
    vk: &ed25519_dalek::VerifyingKey,
    account_addr: &str,
    session_addr: &str,
    ace: &str,
    session: &vss_common::Session,
    pke_dk_bytes: &[u8],
) -> Result<String> {
    let n = session.share_holders.len();
    let threshold = session.threshold as usize;

    // Derive polynomial coefficients from the DK (deterministic).
    let coefs: Vec<Fr> = (0..threshold)
        .map(|i| fr_from_dk_bytes(pke_dk_bytes, i))
        .collect();

    // Fetch each recipient's encryption key.
    let mut enc_keys = Vec::with_capacity(n);
    for holder_addr in &session.share_holders {
        let ek = rpc.get_pke_enc_key_bcs(ace, holder_addr).await
            .map_err(|e| anyhow!("failed to fetch enc key for {}: {}", holder_addr, e))?;
        enc_keys.push(ek);
    }

    // Build per-recipient encrypted share messages.
    let share_ciphertexts: Vec<vss_common::pke::Ciphertext> = (0..n)
        .map(|i| {
            let x_fr = Fr::from((i + 1) as u64);
            let y_fr = poly_eval(&coefs, x_fr);
            let x_bytes = fr_to_le_bytes(x_fr);
            let y_bytes = fr_to_le_bytes(y_fr);

            let share = SecretShare::Bls12381Fr { x: x_bytes, y: y_bytes };
            let opening = PcsOpening::Bls12381Fr { p_eval: y_bytes, r_eval: [0u8; 32] };
            let plaintext = private_share_message_bytes(&share, &opening);
            pke_encrypt(&enc_keys[i], &plaintext)
        })
        .collect();

    // Encrypt dealer state with enc_keys[0] (dealer = share_holders[0]).
    let dealer_state = DealerState::Bls12381Fr {
        n: n as u64,
        coefs_poly_p: coefs.iter().map(|c| fr_to_le_bytes(*c)).collect(),
        coefs_poly_r: vec![[0u8; 32]; threshold],
    };
    let dealer_state_ct = pke_encrypt(&enc_keys[0], &dealer_state.to_bytes());

    // Build PCS commitment: v_j = coef[j] * G1::generator.
    let commitment = PcsCommitment::Bls12381Fr {
        v_values: coefs.iter().map(|c| g1_compressed(*c)).collect(),
    };

    let payload = dc0_bytes(&commitment, &share_ciphertexts, &dealer_state_ct);
    println!(
        "vss-dealer: dc0 payload {} bytes, {} shares, threshold {}",
        payload.len(), n, threshold
    );

    let args = [json!(session_addr), json_move_vec_u8_hex(&payload)];
    rpc.submit_txn(
        sk,
        vk,
        account_addr,
        &format!("{}::vss::on_dealer_contribution_0", ace),
        &[],
        &args,
    )
    .await
}

/// Re-derive polynomial, build batch opening, submit dc1.
async fn build_and_submit_dc1(
    rpc: &AptosRpc,
    sk: &ed25519_dalek::SigningKey,
    vk: &ed25519_dalek::VerifyingKey,
    account_addr: &str,
    session_addr: &str,
    ace: &str,
    session: &vss_common::Session,
    pke_dk_bytes: &[u8],
) -> Result<String> {
    let n = session.share_holders.len();
    let threshold = session.threshold as usize;

    // Re-derive the same polynomial coefficients.
    let coefs: Vec<Fr> = (0..threshold)
        .map(|i| fr_from_dk_bytes(pke_dk_bytes, i))
        .collect();

    // Build batch opening: p_evals[i] = p(i+1), r_evals[i] = 0 (no blinding).
    let p_evals: Vec<[u8; 32]> = (0..n)
        .map(|i| fr_to_le_bytes(poly_eval(&coefs, Fr::from((i + 1) as u64))))
        .collect();
    let r_evals = vec![[0u8; 32]; n];

    let batch_opening = PcsBatchOpening::Bls12381Fr { p_evals, r_evals };
    let payload = dc1_bytes(&batch_opening);

    println!("vss-dealer: dc1 payload {} bytes", payload.len());

    let args = [json!(session_addr), json_move_vec_u8_hex(&payload)];
    rpc.submit_txn(
        sk,
        vk,
        account_addr,
        &format!("{}::vss::on_dealer_open", ace),
        &[],
        &args,
    )
    .await
}
