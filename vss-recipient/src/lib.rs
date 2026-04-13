// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Programmatic API for the on-chain VSS recipient client.
//! `main.rs` is a thin CLI wrapper over [`run`].

use anyhow::{anyhow, Result};
use serde_json::json;
use tokio::sync::oneshot;
use vss_common::session::{STATE_DEALER_DEAL, STATE_FAILED, STATE_RECIPIENT_ACK, STATE_SUCCESS};
use vss_common::{normalize_account_addr, parse_ed25519_signing_key_hex, AptosRpc};

pub const POLL_SECS: u64 = 5;

#[derive(Debug, Clone)]
pub struct RunConfig {
    pub rpc_url: String,
    pub ace_contract: String,
    pub vss_session: String,
    pub account_addr: String,
    pub account_sk_hex: String,
    /// Reserved for real share decryption; unused by skeleton.
    pub pke_dk_hex: String,
}

/// Recipient state machine.
///
/// Submits `on_share_holder_ack` when the session enters `STATE__RECIPIENT_ACK`
/// and this account has not yet acked.
///
/// Exits cleanly on `STATE__SUCCESS`.
/// Returns `Err` on `STATE__FAILED`, account not in share_holders, or unrecoverable errors.
pub async fn run(config: RunConfig, mut shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
    let rpc = AptosRpc::new(config.rpc_url.clone());
    let sk = parse_ed25519_signing_key_hex(&config.account_sk_hex)?;
    let vk = sk.verifying_key();

    let account_addr = normalize_account_addr(&config.account_addr);
    let session_addr = normalize_account_addr(&config.vss_session);
    let ace = normalize_account_addr(&config.ace_contract);

    println!(
        "vss-recipient: starting (account={} session={} ace={})",
        account_addr, session_addr, ace
    );

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(POLL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        // Wait for next poll tick or shutdown — first tick fires immediately.
        tokio::select! {
            _ = &mut shutdown_rx => {
                println!("vss-recipient: shutdown signal received, exiting.");
                return Ok(());
            }
            _ = interval.tick() => {}
        }

        let session = match rpc.get_vss_session_resource(&ace, &session_addr).await {
            Ok(s) => s,
            Err(e) => {
                eprintln!("vss-recipient: poll error: {:#}", e);
                continue;
            }
        };

        // Ensure this account is a share holder.
        let my_idx = match session
            .share_holders
            .iter()
            .position(|h| h == &account_addr)
        {
            Some(i) => i,
            None => {
                return Err(anyhow!(
                    "vss-recipient: account {} is not a share holder in session {}",
                    account_addr,
                    session_addr
                ));
            }
        };

        match session.state_code {
            STATE_DEALER_DEAL => {
                println!("vss-recipient: session in DEALER_DEAL, waiting...");
            }
            STATE_RECIPIENT_ACK => {
                let already_acked = session
                    .share_holder_acks
                    .get(my_idx)
                    .copied()
                    .unwrap_or(false);
                if already_acked {
                    println!("vss-recipient: already acked, waiting for dealer to open...");
                } else {
                    println!("vss-recipient: submitting on_share_holder_ack");
                    let args = [json!(session_addr)];
                    match rpc
                        .submit_txn(
                            &sk,
                            &vk,
                            &account_addr,
                            &format!("{}::vss::on_share_holder_ack", ace),
                            &[],
                            &args,
                        )
                        .await
                    {
                        Ok(h) => println!("vss-recipient: on_share_holder_ack confirmed: {}", h),
                        Err(e) => eprintln!("vss-recipient: on_share_holder_ack error: {:#}", e),
                    }
                }
            }
            STATE_SUCCESS => {
                println!("vss-recipient: session reached SUCCESS.");
                return Ok(());
            }
            STATE_FAILED => {
                return Err(anyhow!("vss-recipient: session FAILED"));
            }
            other => {
                return Err(anyhow!("vss-recipient: unknown state_code {}", other));
            }
        }
    }
}
