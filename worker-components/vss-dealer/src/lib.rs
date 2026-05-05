// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Programmatic API for the on-chain VSS dealer client.
//! `main.rs` is a thin CLI wrapper over [`run`].

use anyhow::{anyhow, Result};
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use tokio::sync::oneshot;
use vss_common::crypto::{fr_from_dk_bytes, fr_to_le_bytes, group_compressed_with_base, pke_encrypt, poly_eval};
use vss_common::sigma_dlog_eq;
use vss_common::TxnArg;
use vss_common::session::{
    ACK_WINDOW_MICROS, STATE_DEALER_DEAL, STATE_FAILED, STATE_RECIPIENT_ACK, STATE_SUCCESS,
    STATE_VERIFY_DEALER_OPENING,
};
use vss_common::vss_types::{dc0_bytes, dc1_bytes, private_share_message_bytes, DealerState};
use vss_common::{normalize_account_addr, parse_ed25519_signing_key_hex, AptosRpc};

pub const POLL_SECS: u64 = 1;

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub rpc_url: String,
    pub rpc_api_key: Option<String>,
    pub rpc_gas_key: Option<String>,
    pub ace_contract: String,
    pub vss_session: String,
    pub account_addr: String,
    pub account_sk_hex: String,
    /// BCS-encoded PKE decryption key (scheme byte + inner), hex with optional 0x prefix.
    pub pke_dk_hex: String,
    /// Optional explicit secret to use as coefs[0] (32-byte Fr LE).
    /// When Some, overrides the DK-derived secret. DKR dealers must provide their DKG share here.
    pub secret_override: Option<[u8; 32]>,
}

/// Dealer state machine.
///
/// Performs real BLS12-381 Fr polynomial dealing:
/// - STATE_DEALER_DEAL: fetches recipient enc keys, computes polynomial, encrypts shares,
///   encrypts dealer state, builds and submits `dealer_contribution_0`.
/// - STATE_RECIPIENT_ACK: re-derives polynomial, builds shares-to-reveal vector, submits `on_dealer_open`.
///
/// Exits cleanly when the session reaches `STATE__SUCCESS`.
/// Returns `Err` on `STATE__FAILED`, wrong dealer, or unrecoverable errors.
pub async fn run(config: RunConfig, mut shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
    let rpc = AptosRpc::new_with_gas_key(config.rpc_url.clone(), config.rpc_api_key.clone(), config.rpc_gas_key.clone());
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
                        config.secret_override,
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
                            config.secret_override,
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
            STATE_VERIFY_DEALER_OPENING => {
                if let Err(e) = rpc.submit_txn(
                    &sk, &vk, &account_addr,
                    &format!("{}::vss::touch", ace), &[],
                    &[vss_common::TxnArg::Address(session_addr.as_str())],
                ).await {
                    eprintln!("vss-dealer: touch error: {:#}", e);
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
    secret_override: Option<[u8; 32]>,
) -> Result<String> {
    let n = session.share_holders.len();
    let threshold = session.threshold as usize;

    // Derive polynomial coefficients. coefs[0] = secret = f(0).
    // If secret_override is provided (e.g. DKR dealer using their DKG share), use it for coefs[0].
    // All other coefficients are derived deterministically from the DK.
    let coefs: Vec<Fr> = {
        let secret = if let Some(s) = secret_override {
            Fr::from_le_bytes_mod_order(&s)
        } else {
            fr_from_dk_bytes(pke_dk_bytes, 0)
        };
        let mut v = vec![secret];
        for i in 1..threshold {
            v.push(fr_from_dk_bytes(pke_dk_bytes, i));
        }
        v
    };

    // Fetch the BCS session to get the actual base_point for the Feldman commitment.
    let bcs_session = rpc.get_session_bcs_decoded(ace, session_addr).await
        .map_err(|e| anyhow!("failed to fetch BCS session: {}", e))?;
    let scheme = bcs_session.base_point.scheme();
    let base_point_bytes: Vec<u8> = bcs_session.base_point.point_bytes().to_vec();

    // Fetch each recipient's encryption key.
    let mut enc_keys = Vec::with_capacity(n);
    for holder_addr in &session.share_holders {
        let ek = rpc.get_pke_enc_key_bcs(ace, holder_addr).await
            .map_err(|e| anyhow!("failed to fetch enc key for {}: {}", holder_addr, e))?;
        enc_keys.push(ek);
    }

    // Build per-recipient encrypted share messages.
    // Holder at index i (0-based) gets share y = f(i+1) (1-indexed evaluation point).
    let share_ciphertexts: Vec<vss_common::pke::Ciphertext> = (0..n)
        .map(|i| -> Result<vss_common::pke::Ciphertext> {
            let x_fr = Fr::from((i + 1) as u64);
            let y_fr = poly_eval(&coefs, x_fr);
            let y_bytes = fr_to_le_bytes(y_fr);

            let plaintext = private_share_message_bytes(scheme, &y_bytes)?;
            Ok(pke_encrypt(&enc_keys[i], &plaintext))
        })
        .collect::<Result<Vec<_>>>()?;

    // Encrypt dealer state with enc_keys[0] (dealer = share_holders[0]).
    let dealer_state = DealerState::bls12381_fr(
        n as u64,
        coefs.iter().map(|c| fr_to_le_bytes(*c)).collect(),
    );
    let dealer_state_ct = pke_encrypt(&enc_keys[0], &dealer_state.to_bytes());

    // Build Feldman PCS commitment: v_k = coefs[k] * base_point for k = 0..threshold.
    // Use the session's actual base_point (not necessarily group::generator).
    let commitment_v_values: Vec<Vec<u8>> = coefs.iter()
        .map(|c| group_compressed_with_base(scheme, *c, &base_point_bytes))
        .collect::<Result<Vec<_>>>()?;

    // Build optional resharing response if the session has a resharing challenge.
    let resharing_resp = if let Some(challenge) = &bcs_session.resharing_challenge {
        let chain_id = rpc.get_chain_id().await
            .map_err(|e| anyhow!("failed to get chain_id: {}", e))?;
        if challenge.another_base_element.scheme() != scheme {
            return Err(anyhow!(
                "resharing_challenge scheme mismatch (base={}, another_base={})",
                scheme,
                challenge.another_base_element.scheme()
            ));
        }

        let ace_hex = ace.trim_start_matches("0x");
        let ace_raw = hex::decode(ace_hex)?;
        let mut ace_bytes = [0u8; 32];
        let start = 32usize.saturating_sub(ace_raw.len());
        ace_bytes[start..].copy_from_slice(&ace_raw);

        let b1_bytes = challenge.another_base_element.point_bytes();
        let commitment_p0 = &commitment_v_values[0];

        let (p1, t0, t1, s_proof) = sigma_dlog_eq::prove(
            scheme, chain_id, &ace_bytes, &base_point_bytes, commitment_p0, b1_bytes, coefs[0],
        )?;
        Some((p1, t0, t1, s_proof))
    } else {
        None
    };

    let payload = dc0_bytes(
        scheme,
        &commitment_v_values,
        &share_ciphertexts,
        &dealer_state_ct,
        resharing_resp
            .as_ref()
            .map(|(p1, t0, t1, s)| (p1.as_slice(), t0.as_slice(), t1.as_slice(), s)),
    )?;
    println!(
        "vss-dealer: dc0 payload {} bytes, {} shares, threshold {} (scheme={})",
        payload.len(), n, threshold, scheme
    );

    let args = [TxnArg::Address(session_addr), TxnArg::Bytes(&payload)];
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


/// Re-derive polynomial, build shares-to-reveal vector, submit dc1.
///
/// For each holder: if they acked, put None (they already have their share);
/// if they did not ack, reveal their share scalar publicly.
async fn build_and_submit_dc1(
    rpc: &AptosRpc,
    sk: &ed25519_dalek::SigningKey,
    vk: &ed25519_dalek::VerifyingKey,
    account_addr: &str,
    session_addr: &str,
    ace: &str,
    session: &vss_common::Session,
    pke_dk_bytes: &[u8],
    secret_override: Option<[u8; 32]>,
) -> Result<String> {
    let n = session.share_holders.len();
    let threshold = session.threshold as usize;

    // Look up the session's group scheme.
    let bcs_session = rpc.get_session_bcs_decoded(ace, session_addr).await
        .map_err(|e| anyhow!("failed to fetch BCS session: {}", e))?;
    let scheme = bcs_session.base_point.scheme();

    // Re-derive the same polynomial (must match DC0 exactly).
    let coefs: Vec<Fr> = {
        let secret = if let Some(s) = secret_override {
            Fr::from_le_bytes_mod_order(&s)
        } else {
            fr_from_dk_bytes(pke_dk_bytes, 0)
        };
        let mut v = vec![secret];
        for i in 1..threshold {
            v.push(fr_from_dk_bytes(pke_dk_bytes, i));
        }
        v
    };

    // Build shares-to-reveal: None if holder acked, Some(y_bytes) if not acked.
    let shares_to_reveal: Vec<Option<[u8; 32]>> = (0..n)
        .map(|i| {
            let acked = session.share_holder_acks.get(i).copied().unwrap_or(false);
            if acked {
                None
            } else {
                let x_fr = Fr::from((i + 1) as u64);
                let y_fr = poly_eval(&coefs, x_fr);
                Some(fr_to_le_bytes(y_fr))
            }
        })
        .collect();

    let payload = dc1_bytes(scheme, &shares_to_reveal)?;
    println!("vss-dealer: dc1 payload {} bytes (scheme={})", payload.len(), scheme);

    let args = [TxnArg::Address(session_addr), TxnArg::Bytes(&payload)];
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
