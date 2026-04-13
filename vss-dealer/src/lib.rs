// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Programmatic API for the on-chain VSS dealer client.
//! `main.rs` is a thin CLI wrapper over [`run`].

use anyhow::{anyhow, Result};
use serde_json::json;
use tokio::sync::oneshot;
use vss_common::aptos::json_move_vec_u8_hex;
use vss_common::session::{ACK_WINDOW_MICROS, STATE_DEALER_DEAL, STATE_FAILED, STATE_RECIPIENT_ACK, STATE_SUCCESS};
use vss_common::{normalize_account_addr, parse_ed25519_signing_key_hex, AptosRpc};

pub const POLL_SECS: u64 = 5;

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub rpc_url: String,
    pub ace_contract: String,
    pub vss_session: String,
    pub account_addr: String,
    pub account_sk_hex: String,
    /// Reserved for real dealing; unused by dummy payloads.
    pub pke_dk_hex: String,
}

/// Dealer state machine.
///
/// Submits dummy `dealer_contribution_0` / `dealer_contribution_1` payloads (single byte `0x00`).
/// Real cryptographic payloads must match the TS wire format before the e2e crypto checks pass.
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
                // Submit contribution_0 if not yet posted.
                if session.dealer_contribution_0.is_empty() {
                    println!("vss-dealer: submitting on_dealer_contribution_0 (dummy)");
                    // Dummy payload — replace with real dealing before crypto checks pass.
                    let payload = vec![0x00u8];
                    let args = [json!(session_addr), json_move_vec_u8_hex(&payload)];
                    match rpc
                        .submit_txn(
                            &sk,
                            &vk,
                            &account_addr,
                            &format!("{}::vss::on_dealer_contribution_0", ace),
                            &[],
                            &args,
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
                    // Submit contribution_1 (open) if not yet posted.
                    if session.dealer_contribution_1.is_empty() {
                        println!(
                            "vss-dealer: submitting on_dealer_open (dummy) \
                             ledger_ts={} deal_time={} ack_window={}",
                            ledger_ts, session.deal_time_micros, ACK_WINDOW_MICROS
                        );
                        // Dummy payload — replace with real batch-open before crypto checks pass.
                        let payload = vec![0x00u8];
                        let args = [json!(session_addr), json_move_vec_u8_hex(&payload)];
                        match rpc
                            .submit_txn(
                                &sk,
                                &vk,
                                &account_addr,
                                &format!("{}::vss::on_dealer_open", ace),
                                &[],
                                &args,
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
