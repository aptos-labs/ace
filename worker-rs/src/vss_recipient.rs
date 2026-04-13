//! On-chain VSS recipient: poll until the dealer posts this account's 80-byte row, decrypt the
//! Shamir share, then poll until the session reaches `DONE` (dealer phase-2). No local persistence.

use anyhow::{anyhow, Context, Result};
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use std::time::{Duration, Instant};
use tracing::{info, warn};

use crate::{
    aptos_rpc::AptosRpc,
    share_crypto::{decrypt_share_80, derive_vss_dk},
};

const STATUS_IN_PROGRESS: u8 = 0;
const STATUS_DONE: u8 = 1;

fn parse_fr_hex(s: &str) -> Result<Fr> {
    let raw = hex::decode(s.trim_start_matches("0x")).context("decode vss-dk hex")?;
    if raw.len() != 32 {
        return Err(anyhow!("vss-dk must be 32 bytes"));
    }
    Ok(Fr::from_le_bytes_mod_order(&raw))
}

pub struct VssRecipientConfig {
    pub rpc_url: String,
    pub contract_addr: String,
    pub vss_session: String,
    pub poll_secs: u64,
    pub max_wait_secs: u64,
    pub vss_dk_hex: Option<String>,
}

pub async fn run_recipient(
    cfg: VssRecipientConfig,
    signing_key: &ed25519_dalek::SigningKey,
    my_lower: &str,
) -> Result<()> {
    let contract = cfg.contract_addr.trim().to_string();
    if !contract.starts_with("0x") {
        return Err(anyhow!("ace-contract must be 0x-prefixed address"));
    }
    let rpc = AptosRpc::new(cfg.rpc_url.clone());
    let vss = cfg.vss_session.trim().to_lowercase();

    let dk = match &cfg.vss_dk_hex {
        Some(h) => parse_fr_hex(h)?,
        None => derive_vss_dk(signing_key),
    };

    let deadline = Instant::now() + Duration::from_secs(cfg.max_wait_secs.max(1));
    let mut decrypted_share = false;

    loop {
        if Instant::now() > deadline {
            return Err(anyhow!(
                "vss-recipient: exceeded max_wait_secs={}",
                cfg.max_wait_secs
            ));
        }

        let info = rpc
            .get_vss_session(&contract, &vss)
            .await
            .with_context(|| format!("get_vss_session {}", vss))?;

        if info.status == STATUS_DONE {
            if !decrypted_share {
                return Err(anyhow!(
                    "vss-recipient: session DONE but no 80-byte ciphertext was received for {}",
                    my_lower
                ));
            }
            info!("vss-recipient: session {} finalized (status=DONE)", vss);
            return Ok(());
        }
        if info.status != STATUS_IN_PROGRESS {
            warn!("vss-recipient: unexpected status {}", info.status);
        }

        let ct = rpc
            .get_encrypted_share(&vss, my_lower, &contract)
            .await
            .unwrap_or_default();
        if ct.len() == 80 && !decrypted_share {
            let plain = decrypt_share_80(&ct, &dk).context("decrypt_share_80")?;
            decrypted_share = true;
            info!(
                "vss-recipient: decrypted 32-byte Shamir share (first octets 0x{})",
                hex::encode(&plain[..8.min(32)])
            );
        }

        tokio::time::sleep(Duration::from_secs(cfg.poll_secs.max(1))).await;
    }
}
