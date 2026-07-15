// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Programmatic API for the on-chain VSS recipient client.
//! `main.rs` is a thin CLI wrapper over [`run`].

use anyhow::{anyhow, Result};
use node_msg_gateway::{send_vss_share_request, sign_vss_share_request, GatewayContext};
use tokio::sync::oneshot;
use vss_common::offchain::{decrypt_share_response_ciphertext, ShareRequest};
use vss_common::session::{
    STATE_DEALER_DEAL, STATE_FAILED, STATE_RECIPIENT_ACK, STATE_SUCCESS,
    STATE_VERIFY_DEALER_OPENING,
};
use vss_common::vss_types::pedersen_verify_private_share;
use vss_common::{normalize_account_addr, parse_ed25519_signing_key_hex, AptosRpc, TxnArg};
use vss_store::{connect_vss_store, HolderShareRecord, VssStore};

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
    pub pke_dk_hex: String,
    pub sig_sk_hex: Option<String>,
    pub vss_store_url: Option<String>,
}

/// Recipient state machine.
///
/// Submits `on_share_holder_ack` when the session enters `STATE__RECIPIENT_ACK`
/// and this account has not yet acked.
///
/// Exits cleanly on `STATE__SUCCESS`.
/// Returns `Err` on `STATE__FAILED`, account not in share_holders, or unrecoverable errors.
pub async fn run(config: RunConfig, mut shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
    let rpc = AptosRpc::new_with_gas_key(
        config.rpc_url.clone(),
        config.rpc_api_key.clone(),
        config.rpc_gas_key.clone(),
    );
    let sk = parse_ed25519_signing_key_hex(&config.account_sk_hex)?;
    let vk = sk.verifying_key();
    let sig_sk = config
        .sig_sk_hex
        .as_ref()
        .map(|hex| parse_ed25519_signing_key_hex(hex))
        .transpose()?;
    let store = match config.vss_store_url.as_ref() {
        Some(url) => Some(connect_vss_store(url)?),
        None => None,
    };

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
                    let store = match store.as_deref() {
                        Some(store) => store,
                        None => {
                            eprintln!("vss-recipient: --vss-store-url is required for offchain VSS shares");
                            continue;
                        }
                    };
                    let sig_sk = match sig_sk.as_ref() {
                        Some(sk) => sk,
                        None => {
                            eprintln!(
                                "vss-recipient: --sig-sk is required for offchain VSS shares"
                            );
                            continue;
                        }
                    };
                    let share_result = ensure_verified_offchain_share(
                        &rpc,
                        store,
                        sig_sk,
                        &ace,
                        &session_addr,
                        &account_addr,
                        &session,
                        my_idx,
                    )
                    .await;

                    if let Err(e) = share_result {
                        eprintln!("vss-recipient: share fetch/verification failed: {:#}", e);
                        continue;
                    }

                    println!("vss-recipient: Pedersen opening verification passed, submitting on_share_holder_ack");
                    let args = [TxnArg::Address(session_addr.as_str())];
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
            STATE_VERIFY_DEALER_OPENING => {
                println!("vss-recipient: dealer opening is being verified, waiting...");
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

/// Ensures this holder's opening is present in the store and verified against
/// the current on-chain DC0 commitment before the caller submits its ACK.
async fn ensure_verified_offchain_share(
    rpc: &AptosRpc,
    store: &dyn VssStore,
    sig_sk: &ed25519_dalek::SigningKey,
    ace: &str,
    session_addr: &str,
    account_addr: &str,
    session: &vss_common::Session,
    my_idx: usize,
) -> Result<()> {
    let bcs_session = rpc.get_session_bcs_decoded(ace, session_addr).await?;
    let dc0 = bcs_session
        .dealer_contribution_0
        .as_ref()
        .ok_or_else(|| anyhow!("dc0 missing in bcs session"))?;
    if let Some(record) = store.get_holder_share(session_addr, my_idx as u64)? {
        if pedersen_verify_private_share(
            &record.share_bcs,
            &bcs_session.pcs_context,
            &dc0.pcs_commitment,
            (my_idx + 1) as u64,
        )
        .is_ok()
        {
            return Ok(());
        }
        eprintln!("vss-recipient: cached share failed current DC0 verification; fetching it again");
    }

    let endpoint = rpc
        .get_worker_node_msg_endpoint(ace, &session.dealer)
        .await?;
    let chain_id = rpc.get_chain_id().await?;
    let context = GatewayContext::new(chain_id, ace, &session.dealer);
    let (request, response_dk) = ShareRequest::new(session_addr, my_idx as u64);
    let request_id = request.request_id()?;
    let message = sign_vss_share_request(&context, sig_sk, account_addr, request.clone())?;
    let encrypted_response = send_vss_share_request(endpoint, &message).await?;
    let plaintext = decrypt_share_response_ciphertext(
        &request,
        &response_dk,
        account_addr,
        &session.dealer,
        &request_id,
        &encrypted_response,
    )?;
    pedersen_verify_private_share(
        &plaintext,
        &bcs_session.pcs_context,
        &dc0.pcs_commitment,
        (my_idx + 1) as u64,
    )?;
    store.put_holder_share(HolderShareRecord {
        session_addr: session_addr.to_string(),
        holder_index: my_idx as u64,
        share_bcs: plaintext.clone(),
    })?;
    Ok(())
}
