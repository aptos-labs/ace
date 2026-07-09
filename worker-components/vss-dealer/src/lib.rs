// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Programmatic API for the on-chain VSS dealer client.
//! `main.rs` is a thin CLI wrapper over [`run`].

use anyhow::{anyhow, Result};
use ark_bls12_381::Fr;
use ark_ff::PrimeField;
use hkdf::Hkdf;
use sha2::Sha256;
use tokio::sync::oneshot;
use vss_common::crypto::{
    fr_to_le_bytes, group_compressed_with_base, group_identity_compressed,
    pedersen_commit_compressed, pke_encrypt, poly_eval,
};
use vss_common::group::BcsElement;
use vss_common::session::{
    BcsPcsOpening, BcsSigmaDlogLinearProof, ACK_WINDOW_MICROS, STATE_DEALER_DEAL, STATE_FAILED,
    STATE_RECIPIENT_ACK, STATE_SUCCESS, STATE_VERIFY_DEALER_OPENING,
};
use vss_common::sigma_dlog_linear;
use vss_common::vss_types::{
    dc0_bytes, dc1_bytes, opening_for_scheme, private_share_message_bytes,
};
use vss_common::{normalize_account_addr, parse_ed25519_signing_key_hex, AptosRpc, TxnArg};

pub const POLL_SECS: u64 = 1;

const P_COEF_DST: &[u8] = b"vss-secret-sharing-coef-v2/";
const R_COEF_DST: &[u8] = b"vss-pedersen-blinding-coef-v2/";
const VSS_SEED_INFO: &[u8] = b"ace::vss-dealer-seed::v1";

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
    /// When Some, overrides the context-derived secret. DKR dealers must provide their DKG share here.
    pub secret_override: Option<[u8; 32]>,
}

struct DealingData {
    evals_p: Vec<Fr>,
    evals_r: Vec<Fr>,
    commitment_points: Vec<Vec<u8>>,
    public_keys: Vec<Vec<u8>>,
}

/// Dealer state machine.
pub async fn run(config: RunConfig, mut shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
    let rpc = AptosRpc::new_with_gas_key(
        config.rpc_url.clone(),
        config.rpc_api_key.clone(),
        config.rpc_gas_key.clone(),
    );
    let sk = parse_ed25519_signing_key_hex(&config.account_sk_hex)?;
    let vk = sk.verifying_key();

    let account_addr = normalize_account_addr(&config.account_addr);
    let session_addr = normalize_account_addr(&config.vss_session);
    let ace = normalize_account_addr(&config.ace_contract);

    let pke_dk_bytes = hex::decode(config.pke_dk_hex.trim_start_matches("0x"))
        .map_err(|e| anyhow!("invalid pke_dk_hex: {}", e))?;

    println!(
        "vss-dealer: starting (account={} session={} ace={})",
        account_addr, session_addr, ace
    );

    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(POLL_SECS));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
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
                } else if let Err(e) = rpc
                    .submit_txn(
                        &sk,
                        &vk,
                        &account_addr,
                        &format!("{}::vss::touch", ace),
                        &[],
                        &[TxnArg::Address(session_addr.as_str())],
                    )
                    .await
                {
                    eprintln!("vss-dealer: touch dealer commitment error: {:#}", e);
                }
            }
            STATE_RECIPIENT_ACK => {
                let ledger_ts = match rpc.get_ledger_timestamp_micros().await {
                    Ok(ts) => ts,
                    Err(e) => {
                        eprintln!("vss-dealer: get_ledger_timestamp_micros error: {:#}", e);
                        0
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
                if let Err(e) = rpc
                    .submit_txn(
                        &sk,
                        &vk,
                        &account_addr,
                        &format!("{}::vss::touch", ace),
                        &[],
                        &[TxnArg::Address(session_addr.as_str())],
                    )
                    .await
                {
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

    let bcs_session = rpc
        .get_session_bcs_decoded(ace, session_addr)
        .await
        .map_err(|e| anyhow!("failed to fetch BCS session: {}", e))?;
    let scheme = bcs_session.base_point.scheme();
    let base_point_bytes = bcs_session.base_point.point_bytes().to_vec();
    let generator_g_bytes = bcs_session.pcs_context.generator_g.point_bytes().to_vec();
    let generator_h_bytes = bcs_session.pcs_context.generator_h.point_bytes().to_vec();
    let chain_id = rpc
        .get_chain_id()
        .await
        .map_err(|e| anyhow!("failed to get chain_id: {}", e))?;
    let derivation_context = polynomial_derivation_context(chain_id, ace, session_addr)?;

    let dealing = build_dealing_data(
        scheme,
        n,
        threshold,
        pke_dk_bytes,
        &derivation_context,
        secret_override,
        &base_point_bytes,
        &generator_g_bytes,
        &generator_h_bytes,
    )?;

    let mut enc_keys = Vec::with_capacity(n);
    for holder_addr in &session.share_holders {
        let ek = rpc
            .get_pke_enc_key_bcs(ace, holder_addr)
            .await
            .map_err(|e| anyhow!("failed to fetch enc key for {}: {}", holder_addr, e))?;
        enc_keys.push(ek);
    }

    let share_ciphertexts: Vec<vss_common::pke::Ciphertext> = (0..n)
        .map(|i| -> Result<vss_common::pke::Ciphertext> {
            let eval_position = (i + 1) as u64;
            let y_bytes = fr_to_le_bytes(dealing.evals_p[i + 1]);
            let r_bytes = fr_to_le_bytes(dealing.evals_r[i + 1]);
            let plaintext = private_share_message_bytes(scheme, eval_position, &y_bytes, &r_bytes)?;
            Ok(pke_encrypt(&enc_keys[i], &plaintext))
        })
        .collect::<Result<Vec<_>>>()?;

    let consistency_proof = if let Some(previous_public_key) = &bcs_session.previous_public_key {
        Some(
            prove_public_key_binding(
                rpc,
                ace,
                session_addr,
                scheme,
                b"vss::dc0-consistency",
                0,
                &base_point_bytes,
                &generator_g_bytes,
                &generator_h_bytes,
                previous_public_key.point_bytes(),
                &dealing.commitment_points[0],
                dealing.evals_p[0],
                dealing.evals_r[0],
            )
            .await?,
        )
    } else {
        None
    };

    let payload = dc0_bytes(
        scheme,
        &dealing.commitment_points,
        &share_ciphertexts,
        None,
        consistency_proof,
    )?;
    println!(
        "vss-dealer: dc0 payload {} bytes, {} shares, threshold {} (scheme={})",
        payload.len(),
        n,
        threshold,
        scheme
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

    let bcs_session = rpc
        .get_session_bcs_decoded(ace, session_addr)
        .await
        .map_err(|e| anyhow!("failed to fetch BCS session: {}", e))?;
    let scheme = bcs_session.base_point.scheme();
    let base_point_bytes = bcs_session.base_point.point_bytes().to_vec();
    let generator_g_bytes = bcs_session.pcs_context.generator_g.point_bytes().to_vec();
    let generator_h_bytes = bcs_session.pcs_context.generator_h.point_bytes().to_vec();
    let chain_id = rpc
        .get_chain_id()
        .await
        .map_err(|e| anyhow!("failed to get chain_id: {}", e))?;
    let derivation_context = polynomial_derivation_context(chain_id, ace, session_addr)?;

    let dealing = build_dealing_data(
        scheme,
        n,
        threshold,
        pke_dk_bytes,
        &derivation_context,
        secret_override,
        &base_point_bytes,
        &generator_g_bytes,
        &generator_h_bytes,
    )?;

    let mut shares_to_reveal: Vec<Option<BcsPcsOpening>> = vec![None];
    let mut public_key_proofs: Vec<Option<BcsSigmaDlogLinearProof>> = Vec::with_capacity(n + 1);
    public_key_proofs.push(Some(
        prove_public_key_binding(
            rpc,
            ace,
            session_addr,
            scheme,
            b"vss::dc1-public-key",
            0,
            &base_point_bytes,
            &generator_g_bytes,
            &generator_h_bytes,
            &dealing.public_keys[0],
            &dealing.commitment_points[0],
            dealing.evals_p[0],
            dealing.evals_r[0],
        )
        .await?,
    ));

    for i in 0..n {
        let eval_position = (i + 1) as u64;
        let acked = session.share_holder_acks.get(i).copied().unwrap_or(false);
        if acked {
            shares_to_reveal.push(None);
            public_key_proofs.push(Some(
                prove_public_key_binding(
                    rpc,
                    ace,
                    session_addr,
                    scheme,
                    b"vss::dc1-public-key",
                    eval_position,
                    &base_point_bytes,
                    &generator_g_bytes,
                    &generator_h_bytes,
                    &dealing.public_keys[i + 1],
                    &dealing.commitment_points[i + 1],
                    dealing.evals_p[i + 1],
                    dealing.evals_r[i + 1],
                )
                .await?,
            ));
        } else {
            let y_bytes = fr_to_le_bytes(dealing.evals_p[i + 1]);
            let r_bytes = fr_to_le_bytes(dealing.evals_r[i + 1]);
            shares_to_reveal.push(Some(opening_for_scheme(
                scheme,
                eval_position,
                &y_bytes,
                &r_bytes,
            )?));
            public_key_proofs.push(None);
        }
    }

    let payload = dc1_bytes(
        scheme,
        &shares_to_reveal,
        &dealing.public_keys,
        &public_key_proofs,
    )?;
    println!(
        "vss-dealer: dc1 payload {} bytes (scheme={})",
        payload.len(),
        scheme
    );

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

fn build_dealing_data(
    scheme: u8,
    n: usize,
    threshold: usize,
    pke_dk_bytes: &[u8],
    derivation_context: &[u8],
    secret_override: Option<[u8; 32]>,
    public_base_bytes: &[u8],
    generator_g_bytes: &[u8],
    generator_h_bytes: &[u8],
) -> Result<DealingData> {
    let (coefs_p, coefs_r) =
        derive_polynomials(threshold, pke_dk_bytes, derivation_context, secret_override)?;
    build_dealing_data_from_polys(
        scheme,
        n,
        threshold,
        coefs_p,
        coefs_r,
        public_base_bytes,
        generator_g_bytes,
        generator_h_bytes,
    )
}

fn build_dealing_data_from_polys(
    scheme: u8,
    n: usize,
    threshold: usize,
    coefs_p: Vec<Fr>,
    coefs_r: Vec<Fr>,
    public_base_bytes: &[u8],
    generator_g_bytes: &[u8],
    generator_h_bytes: &[u8],
) -> Result<DealingData> {
    validate_polynomial_lengths(&coefs_p, &coefs_r, threshold)?;

    let mut evals_p = Vec::with_capacity(n + 1);
    let mut evals_r = Vec::with_capacity(n + 1);
    let mut commitment_points = Vec::with_capacity(n + 1);
    let mut public_keys = Vec::with_capacity(n + 1);

    for i in 0..=n {
        let x = Fr::from(i as u64);
        let p_i = poly_eval(&coefs_p, x);
        let r_i = poly_eval(&coefs_r, x);
        evals_p.push(p_i);
        evals_r.push(r_i);
        commitment_points.push(pedersen_commit_compressed(
            scheme,
            p_i,
            r_i,
            generator_g_bytes,
            generator_h_bytes,
        )?);
        public_keys.push(group_compressed_with_base(scheme, p_i, public_base_bytes)?);
    }

    Ok(DealingData {
        evals_p,
        evals_r,
        commitment_points,
        public_keys,
    })
}

fn derive_polynomials(
    threshold: usize,
    pke_dk_bytes: &[u8],
    derivation_context: &[u8],
    secret_override: Option<[u8; 32]>,
) -> Result<(Vec<Fr>, Vec<Fr>)> {
    if threshold == 0 {
        return Err(anyhow!("VSS threshold must be positive"));
    }
    let vss_seed = derive_vss_seed(pke_dk_bytes)?;

    let secret = if let Some(s) = secret_override {
        Fr::from_le_bytes_mod_order(&s)
    } else {
        derive_polynomial_coefficient(P_COEF_DST, &vss_seed, derivation_context, 0)?
    };
    let mut coefs_p = Vec::with_capacity(threshold);
    coefs_p.push(secret);
    for i in 1..threshold {
        coefs_p.push(derive_polynomial_coefficient(
            P_COEF_DST,
            &vss_seed,
            derivation_context,
            i,
        )?);
    }

    let coefs_r = (0..threshold)
        .map(|i| derive_polynomial_coefficient(R_COEF_DST, &vss_seed, derivation_context, i))
        .collect::<Result<Vec<_>>>()?;
    Ok((coefs_p, coefs_r))
}

fn derive_vss_seed(pke_dk_bytes: &[u8]) -> Result<[u8; 32]> {
    let hk = Hkdf::<Sha256>::from_prk(pke_dk_bytes)
        .map_err(|_| anyhow!("pke_dk is too short for VSS seed HKDF-Expand"))?;
    let mut seed = [0u8; 32];
    hk.expand(VSS_SEED_INFO, &mut seed)
        .map_err(|_| anyhow!("VSS seed HKDF-Expand failed"))?;
    Ok(seed)
}

fn derive_polynomial_coefficient(
    dst: &[u8],
    vss_seed: &[u8; 32],
    derivation_context: &[u8],
    idx: usize,
) -> Result<Fr> {
    let hk = Hkdf::<Sha256>::from_prk(vss_seed)
        .map_err(|_| anyhow!("vss_seed is too short for coefficient HKDF-Expand"))?;
    let mut info = Vec::with_capacity(dst.len() + derivation_context.len() + 8);
    info.extend_from_slice(dst);
    info.extend_from_slice(derivation_context);
    info.extend_from_slice(&(idx as u64).to_le_bytes());
    let mut bytes = [0u8; 32];
    hk.expand(&info, &mut bytes)
        .map_err(|_| anyhow!("coefficient HKDF-Expand failed"))?;
    Ok(Fr::from_le_bytes_mod_order(&bytes))
}

fn polynomial_derivation_context(chain_id: u8, ace: &str, session_addr: &str) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + 32 + 32);
    out.push(chain_id);
    out.extend_from_slice(&addr_to_bytes(ace)?);
    out.extend_from_slice(&addr_to_bytes(session_addr)?);
    Ok(out)
}

fn validate_polynomial_lengths(coefs_p: &[Fr], coefs_r: &[Fr], threshold: usize) -> Result<()> {
    if threshold == 0 {
        return Err(anyhow!("VSS threshold must be positive"));
    }
    if coefs_p.len() != threshold || coefs_r.len() != threshold {
        return Err(anyhow!(
            "VSS dealer state polynomial length mismatch: p={}, r={}, threshold={}",
            coefs_p.len(),
            coefs_r.len(),
            threshold
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_polynomials_is_stable_for_the_same_context() {
        let context = polynomial_derivation_context(4, "0x0ace", "0x1234").unwrap();
        let dk = [42u8; 32];

        let first = derive_polynomials(3, &dk, &context, None).unwrap();
        let second = derive_polynomials(3, &dk, &context, None).unwrap();

        assert_eq!(first, second);
    }

    #[test]
    fn derive_polynomials_changes_across_session_contexts() {
        let context_1 = polynomial_derivation_context(4, "0x0ace", "0x1234").unwrap();
        let context_2 = polynomial_derivation_context(4, "0x0ace", "0x1235").unwrap();
        let dk = [42u8; 32];

        let first = derive_polynomials(3, &dk, &context_1, None).unwrap();
        let second = derive_polynomials(3, &dk, &context_2, None).unwrap();

        assert_ne!(first, second);
    }

    #[test]
    fn derive_polynomials_preserves_secret_override() {
        let secret = [7u8; 32];
        let context = polynomial_derivation_context(4, "0x0ace", "0x1234").unwrap();
        let dk = [42u8; 32];

        let (coefs_p, coefs_r) = derive_polynomials(3, &dk, &context, Some(secret)).unwrap();
        let (coefs_p_again, coefs_r_again) =
            derive_polynomials(3, &dk, &context, Some(secret)).unwrap();

        assert_eq!(coefs_p[0], Fr::from_le_bytes_mod_order(&secret));
        assert_eq!(coefs_p, coefs_p_again);
        assert_eq!(coefs_r, coefs_r_again);
    }

    #[test]
    fn dealing_data_rejects_wrong_polynomial_length_before_group_work() {
        let err = match build_dealing_data_from_polys(
            0,
            1,
            2,
            vec![Fr::from(1u64)],
            vec![Fr::from(2u64)],
            &[0u8; 48],
            &[0u8; 48],
            &[0u8; 48],
        ) {
            Ok(_) => panic!("expected polynomial length mismatch"),
            Err(e) => e.to_string(),
        };

        assert!(err.contains("polynomial length mismatch"));
    }
}

async fn prove_public_key_binding(
    rpc: &AptosRpc,
    ace: &str,
    session_addr: &str,
    scheme: u8,
    purpose: &[u8],
    eval_position: u64,
    public_base_bytes: &[u8],
    generator_g_bytes: &[u8],
    generator_h_bytes: &[u8],
    public_key_bytes: &[u8],
    commitment_point_bytes: &[u8],
    p_i: Fr,
    r_i: Fr,
) -> Result<BcsSigmaDlogLinearProof> {
    let chain_id = rpc
        .get_chain_id()
        .await
        .map_err(|e| anyhow!("failed to get chain_id: {}", e))?;
    let ace_addr = addr_to_bytes(ace)?;
    let session_addr = addr_to_bytes(session_addr)?;
    let identity = group_identity_compressed(scheme)?;

    let b_vals = vec![
        element_for_scheme(scheme, public_base_bytes)?,
        element_for_scheme(scheme, &identity)?,
        element_for_scheme(scheme, generator_g_bytes)?,
        element_for_scheme(scheme, generator_h_bytes)?,
    ];
    let p_vals = vec![
        element_for_scheme(scheme, public_key_bytes)?,
        element_for_scheme(scheme, commitment_point_bytes)?,
    ];
    sigma_dlog_linear::prove_vss(
        scheme,
        chain_id,
        &ace_addr,
        &session_addr,
        purpose,
        eval_position,
        &b_vals,
        &p_vals,
        &[p_i, r_i],
    )
}

fn element_for_scheme(scheme: u8, bytes: &[u8]) -> Result<BcsElement> {
    BcsElement::from_scheme_and_bytes(scheme, bytes.to_vec())
}

fn addr_to_bytes(addr: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(addr.trim_start_matches("0x"))
        .map_err(|e| anyhow!("address decode '{}': {}", addr, e))?;
    if raw.len() > 32 {
        return Err(anyhow!("address too long: {}", addr));
    }
    let mut out = [0u8; 32];
    out[32 - raw.len()..].copy_from_slice(&raw);
    Ok(out)
}
