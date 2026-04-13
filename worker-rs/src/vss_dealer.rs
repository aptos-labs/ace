//! Standalone on-chain VSS dealer: two-phase dealing (encrypted shares + escrowed polynomial)
//! then, after a wall-clock delay, partial MPK contribution — no local persistence (state on chain).

use anyhow::{anyhow, Context, Result};
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use rand::RngCore;
use serde_json::json;
use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::{
    aptos_rpc::{json_move_vec_u8_hex, AptosRpc},
    share_crypto::{
        decrypt_share_80, derive_vss_dk, encrypt_share_80, encryption_pk_compressed,
        xor_symmetric_stream,
    },
    vss::{self, Polynomial},
};

const STATUS_IN_PROGRESS: u8 = 0;
const STATUS_DONE: u8 = 1;

pub struct VssDealerConfig {
    pub rpc_url: String,
    pub contract_addr: String,
    pub vss_session: String,
    pub recipients: Vec<String>,
    pub recipient_pks_hex: Vec<String>,
    pub recipient_indices: Vec<u64>,
    pub threshold: u64,
    pub poll_secs: u64,
    pub phase2_delay_secs: u64,
    pub vss_dk_hex: Option<String>,
}

fn parse_fr_hex(s: &str) -> Result<Fr> {
    let raw = hex::decode(s.trim_start_matches("0x")).context("decode vss-dk hex")?;
    if raw.len() != 32 {
        return Err(anyhow!("vss-dk must be 32 bytes"));
    }
    Ok(Fr::from_le_bytes_mod_order(&raw))
}

pub async fn run_dealer(
    cfg: VssDealerConfig,
    signing_key: &ed25519_dalek::SigningKey,
    verifying_key: &ed25519_dalek::VerifyingKey,
    my_lower: &str,
) -> Result<()> {
    let n = cfg.recipients.len();
    if n != cfg.recipient_pks_hex.len() || n != cfg.recipient_indices.len() {
        return Err(anyhow!(
            "recipients, recipient-pks-hex, and recipient-indices must have same length"
        ));
    }

    let dk = match &cfg.vss_dk_hex {
        Some(h) => parse_fr_hex(h)?,
        None => derive_vss_dk(signing_key),
    };
    let dealer_enc_pk = encryption_pk_compressed(&dk);
    let dealer_enc_pk_arr: [u8; 48] = dealer_enc_pk;

    let contract = cfg.contract_addr.trim().to_string();
    if !contract.starts_with("0x") {
        return Err(anyhow!("ace-contract must be 0x-prefixed address"));
    }
    let rpc = AptosRpc::new(cfg.rpc_url.clone());
    let vss = cfg.vss_session.trim().to_lowercase();
    let threshold = cfg.threshold.max(2);
    let degree = (threshold - 1) as usize;

    let mut phase2_gate: Option<Instant> = None;
    // In-memory polynomial between polls until phase-1 chain state is complete.
    let mut pending_poly: Option<Polynomial> = None;

    loop {
        let info = rpc
            .get_vss_session(&contract, &vss)
            .await
            .with_context(|| format!("get_vss_session {}", vss))?;
        if info.dealer != my_lower {
            return Err(anyhow!(
                "signer {} is not dealer {} for this VssSession",
                my_lower,
                info.dealer
            ));
        }
        if info.status == STATUS_DONE {
            info!("vss-dealer: session {} finalized (status=DONE)", vss);
            return Ok(());
        }
        if info.status != STATUS_IN_PROGRESS {
            warn!("vss-dealer: unexpected status {}", info.status);
            tokio::time::sleep(Duration::from_secs(cfg.poll_secs)).await;
            continue;
        }

        let mut all_recipient_rows = true;
        for recv in &cfg.recipients {
            let ct = rpc
                .get_encrypted_share(&vss, &recv.to_lowercase(), &contract)
                .await
                .unwrap_or_default();
            if ct.len() != 80 {
                all_recipient_rows = false;
                break;
            }
        }
        let escrow = rpc
            .get_dealer_escrow(&contract, &vss)
            .await
            .unwrap_or_default();
        let self_ct = rpc
            .get_encrypted_share(&vss, my_lower, &contract)
            .await
            .unwrap_or_default();
        let phase1_on_chain = all_recipient_rows && !escrow.is_empty() && self_ct.len() == 80;

        if !phase1_on_chain {
            if pending_poly.is_none() {
                let mut rng = rand::thread_rng();
                pending_poly = Some(Polynomial::random(degree, &mut rng));
                info!("vss-dealer: generated degree-{} polynomial for phase 1", degree);
            }
            let poly = pending_poly.as_ref().unwrap();

            for i in 0..n {
                let recv = cfg.recipients[i].to_lowercase();
                let idx = cfg.recipient_indices[i];
                if idx == info.dealer_index {
                    continue;
                }
                let ct = rpc
                    .get_encrypted_share(&vss, &recv, &contract)
                    .await
                    .unwrap_or_default();
                if ct.len() == 80 {
                    continue;
                }
                let pk_bytes = hex::decode(cfg.recipient_pks_hex[i].trim_start_matches("0x"))
                    .with_context(|| format!("recipient pk hex {}", i))?;
                if pk_bytes.len() != 48 {
                    return Err(anyhow!("recipient {} pk must be 48 bytes G1 compressed", i));
                }
                let mut pk_arr = [0u8; 48];
                pk_arr.copy_from_slice(&pk_bytes);
                let share_fr = poly.eval(idx);
                let share_b = vss::fr_to_le32(share_fr);
                let row = encrypt_share_80(&share_b, &pk_arr)?;
                info!("vss-dealer: post_encrypted_share → recipient index {} addr {}", idx, recv);
                rpc.submit_txn(
                    signing_key,
                    verifying_key,
                    my_lower,
                    &format!("{}::vss::post_encrypted_share", contract),
                    &[],
                    &[json!(&vss), json!(&recv), json_move_vec_u8_hex(&row)],
                )
                .await?;
            }

            if escrow.is_empty() {
                let mut sym_key = [0u8; 32];
                rand::thread_rng().fill_bytes(&mut sym_key);
                let plain = poly.serialize_for_escrow();
                let obscured = xor_symmetric_stream(&plain, &sym_key);
                info!(
                    "vss-dealer: post_dealer_escrow ({} bytes) + self-encrypted symmetric key row",
                    obscured.len()
                );
                rpc.submit_txn(
                    signing_key,
                    verifying_key,
                    my_lower,
                    &format!("{}::vss::post_dealer_escrow", contract),
                    &[],
                    &[json!(&vss), json_move_vec_u8_hex(&obscured)],
                )
                .await?;
                let sym_ct = encrypt_share_80(&sym_key, &dealer_enc_pk_arr)?;
                rpc.submit_txn(
                    signing_key,
                    verifying_key,
                    my_lower,
                    &format!("{}::vss::post_encrypted_share", contract),
                    &[],
                    &[json!(&vss), json!(my_lower), json_move_vec_u8_hex(&sym_ct)],
                )
                .await?;
            }

            tokio::time::sleep(Duration::from_secs(cfg.poll_secs)).await;
            continue;
        }

        pending_poly = None;

        if phase2_gate.is_none() {
            phase2_gate = Some(Instant::now());
            info!(
                "vss-dealer: phase-1 complete on-chain; waiting {}s before phase-2 contribution",
                cfg.phase2_delay_secs
            );
        }
        let gate = phase2_gate
            .as_ref()
            .expect("phase2_gate set when phase-1 chain complete");
        if gate.elapsed() < Duration::from_secs(cfg.phase2_delay_secs) {
            tokio::time::sleep(Duration::from_secs(cfg.poll_secs)).await;
            continue;
        }

        let sym_plain = decrypt_share_80(&self_ct, &dk)?;
        let sym_key: [u8; 32] = sym_plain;
        let plain = xor_symmetric_stream(&escrow, &sym_key);
        let poly = Polynomial::deserialize_from_escrow(&plain)
            .context("deserialize polynomial from escrow")?;
        let mut contribution = vec![0x02u8];
        contribution.extend_from_slice(&vss::g1_to_bytes48(poly.partial_mpk()));
        info!(
            "vss-dealer: dealer_post_final_contribution ({} bytes partial MPK)",
            contribution.len()
        );
        rpc.submit_txn(
            signing_key,
            verifying_key,
            my_lower,
            &format!("{}::vss::dealer_post_final_contribution", contract),
            &[],
            &[json!(&vss), json_move_vec_u8_hex(&contribution)],
        )
        .await?;
        info!("vss-dealer: phase-2 submitted; exiting.");
        return Ok(());
    }
}
