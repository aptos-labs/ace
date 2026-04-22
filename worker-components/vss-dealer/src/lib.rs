// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Programmatic API for the on-chain VSS dealer client.
//! `main.rs` is a thin CLI wrapper over [`run`].

use anyhow::{anyhow, Result};
use ark_bls12_381::{Fr, G1Affine};
use ark_ec::CurveGroup;
use ark_ff::PrimeField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use rand::RngCore;
use sha2::{Digest, Sha512};
use serde_json::json;
use tokio::sync::oneshot;
use vss_common::aptos::json_move_vec_u8_hex;
use vss_common::crypto::{fr_from_dk_bytes, fr_to_le_bytes, g1_compressed_with_base, pke_encrypt, poly_eval};
use vss_common::session::{ACK_WINDOW_MICROS, BcsElement, STATE_DEALER_DEAL, STATE_FAILED, STATE_RECIPIENT_ACK, STATE_SUCCESS};
use vss_common::vss_types::{
    dc0_bytes, dc1_bytes, private_share_message_bytes, DealerState, PcsCommitment, SecretShare,
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

/// Sigma DLog equality proof: proves knowledge of `secret` s.t. `secret*b0 == p0` AND `secret*b1 == p1`.
/// Returns `(p1_bytes, t0_bytes, t1_bytes, s_proof_bytes)`.
/// Transcript matches the on-chain verifier in `ace::vss::on_dealer_contribution_0`.
fn sigma_dlog_eq_prove(
    chain_id: u8,
    ace_addr_bytes: &[u8; 32],
    b0_bytes: &[u8; 48],
    p0_bytes: &[u8; 48],
    b1_bytes: &[u8; 48],
    secret: Fr,
) -> Result<([u8; 48], [u8; 48], [u8; 48], [u8; 32])> {
    let b0 = G1Affine::deserialize_compressed(b0_bytes.as_slice())
        .map_err(|e| anyhow!("b0 deserialize: {}", e))?;
    let b1 = G1Affine::deserialize_compressed(b1_bytes.as_slice())
        .map_err(|e| anyhow!("b1 deserialize: {}", e))?;

    let p1_proj = b1 * secret;
    let mut p1_bytes = [0u8; 48];
    p1_proj.into_affine().serialize_compressed(&mut p1_bytes[..]).expect("G1 serialize");

    let mut r_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut r_bytes);
    let r = Fr::from_le_bytes_mod_order(&r_bytes);
    let t0_proj = b0 * r;
    let t1_proj = b1 * r;
    let mut t0_bytes = [0u8; 48];
    let mut t1_bytes = [0u8; 48];
    t0_proj.into_affine().serialize_compressed(&mut t0_bytes[..]).expect("G1 serialize");
    t1_proj.into_affine().serialize_compressed(&mut t1_bytes[..]).expect("G1 serialize");

    // Fiat-Shamir transcript = BCS(FiatShamirTag) || BCS(b0) || BCS(p0) || BCS(b1) || BCS(p1) || BCS(t0) || BCS(t1)
    // BCS(FiatShamirTag { chain_id: u8, module_addr: address, module_name: vector<u8> })
    //   = [chain_id][32B addr][ULEB128(3)=0x03][b'v'][b's'][b's']
    let mut trx: Vec<u8> = Vec::new();
    trx.push(chain_id);
    trx.extend_from_slice(ace_addr_bytes);
    trx.extend_from_slice(&[0x03, b'v', b's', b's']);
    // BCS(group::Element::Bls12381G1) = [0x00][0x30][48B]
    for pt in [b0_bytes, p0_bytes, b1_bytes, &p1_bytes, &t0_bytes, &t1_bytes] {
        trx.push(0x00);
        trx.push(0x30);
        trx.extend_from_slice(pt);
    }

    let hash = Sha512::digest(&trx);
    let c = Fr::from_le_bytes_mod_order(&hash.iter().rev().cloned().collect::<Vec<_>>());
    let s_proof = r + c * secret;
    let s_bytes = fr_to_le_bytes(s_proof);

    Ok((p1_bytes, t0_bytes, t1_bytes, s_bytes))
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
    let base_point_bytes = match &bcs_session.base_point {
        vss_common::session::BcsElement::Bls12381G1(p) => p.point.clone(),
    };

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
        .map(|i| {
            let x_fr = Fr::from((i + 1) as u64);
            let y_fr = poly_eval(&coefs, x_fr);
            let y_bytes = fr_to_le_bytes(y_fr);

            let share = SecretShare::Bls12381Fr { y: y_bytes };
            let plaintext = private_share_message_bytes(&share);
            pke_encrypt(&enc_keys[i], &plaintext)
        })
        .collect();

    // Encrypt dealer state with enc_keys[0] (dealer = share_holders[0]).
    let dealer_state = DealerState::Bls12381Fr {
        n: n as u64,
        coefs_poly_p: coefs.iter().map(|c| fr_to_le_bytes(*c)).collect(),
    };
    let dealer_state_ct = pke_encrypt(&enc_keys[0], &dealer_state.to_bytes());

    // Build Feldman PCS commitment: v_k = coefs[k] * base_point for k = 0..threshold.
    // Use the session's actual base_point (not necessarily G1::generator).
    let commitment = PcsCommitment::Bls12381Fr {
        v_values: coefs.iter()
            .map(|c| g1_compressed_with_base(*c, &base_point_bytes))
            .collect::<anyhow::Result<Vec<_>>>()?,
    };

    // Build optional resharing response if the session has a resharing challenge.
    let resharing_resp = if let Some(challenge) = &bcs_session.resharing_challenge {
        let chain_id = rpc.get_chain_id().await
            .map_err(|e| anyhow!("failed to get chain_id: {}", e))?;

        let ace_hex = ace.trim_start_matches("0x");
        let ace_raw = hex::decode(ace_hex)?;
        let mut ace_bytes = [0u8; 32];
        let start = 32usize.saturating_sub(ace_raw.len());
        ace_bytes[start..].copy_from_slice(&ace_raw);

        let b1_bytes: [u8; 48] = match &challenge.another_base_element {
            BcsElement::Bls12381G1(p) => p.point.as_slice().try_into()
                .map_err(|_| anyhow!("another_base_element is not 48 bytes"))?,
        };
        let p0_bytes: &[u8; 48] = base_point_bytes.as_slice().try_into()
            .map_err(|_| anyhow!("base_point_bytes is not 48 bytes"))?;
        let commitment_p0: [u8; 48] = match &commitment {
            PcsCommitment::Bls12381Fr { v_values } => v_values[0],
        };

        let (p1, t0, t1, s_proof) = sigma_dlog_eq_prove(
            chain_id, &ace_bytes, p0_bytes, &commitment_p0, &b1_bytes, coefs[0],
        )?;
        Some((p1, t0, t1, s_proof))
    } else {
        None
    };

    let payload = dc0_bytes(
        &commitment,
        &share_ciphertexts,
        &dealer_state_ct,
        resharing_resp.as_ref().map(|(p1, t0, t1, s)| (p1, t0, t1, s)),
    );
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::G1Affine;
    use ark_ec::{AffineRepr, CurveGroup};
    use ark_serialize::CanonicalSerialize;

    /// Verifies `sigma_dlog_eq_prove` produces a mathematically valid proof.
    /// Rebuilds the Fiat-Shamir challenge in the test and checks both equations:
    ///   s*b0 == t0 + c*p0   AND   s*b1 == t1 + c*p1
    #[test]
    fn sigma_dlog_eq_prove_self_consistent() {
        let chain_id = 4u8;
        let ace_bytes = {
            let mut b = [0u8; 32];
            b[30] = 0xca;
            b[31] = 0xfe;
            b
        };

        let secret = Fr::from_le_bytes_mod_order(&[
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
            0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
            0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
        ]);

        let b0 = G1Affine::generator();
        let b1: G1Affine = (b0 * Fr::from(7u64)).into_affine();
        let p0: G1Affine = (b0 * secret).into_affine();

        let mut b0_bytes = [0u8; 48];
        let mut b1_bytes = [0u8; 48];
        let mut p0_bytes = [0u8; 48];
        b0.serialize_compressed(&mut b0_bytes[..]).unwrap();
        b1.serialize_compressed(&mut b1_bytes[..]).unwrap();
        p0.serialize_compressed(&mut p0_bytes[..]).unwrap();

        let (p1_bytes, t0_bytes, t1_bytes, s_bytes) =
            sigma_dlog_eq_prove(chain_id, &ace_bytes, &b0_bytes, &p0_bytes, &b1_bytes, secret)
                .unwrap();

        let p1 = G1Affine::deserialize_compressed(p1_bytes.as_slice()).unwrap();
        let t0 = G1Affine::deserialize_compressed(t0_bytes.as_slice()).unwrap();
        let t1 = G1Affine::deserialize_compressed(t1_bytes.as_slice()).unwrap();
        let s_fr = Fr::from_le_bytes_mod_order(&s_bytes);

        // Rebuild challenge c exactly as sigma_dlog_eq_prove does.
        let mut trx: Vec<u8> = Vec::new();
        trx.push(chain_id);
        trx.extend_from_slice(&ace_bytes);
        trx.extend_from_slice(&[0x03, b'v', b's', b's']);
        for pt in [&b0_bytes, &p0_bytes, &b1_bytes, &p1_bytes, &t0_bytes, &t1_bytes] {
            trx.push(0x00);
            trx.push(0x30);
            trx.extend_from_slice(pt);
        }
        let hash = Sha512::digest(&trx);
        let c = Fr::from_le_bytes_mod_order(&hash.iter().rev().cloned().collect::<Vec<_>>());

        // Check: s*b0 == t0 + c*p0
        let lhs0: G1Affine = (b0 * s_fr).into_affine();
        let rhs0: G1Affine = (t0.into_group() + p0 * c).into_affine();
        assert_eq!(lhs0, rhs0, "s*b0 != t0 + c*p0");

        // Check: s*b1 == t1 + c*p1
        let lhs1: G1Affine = (b1 * s_fr).into_affine();
        let rhs1: G1Affine = (t1.into_group() + p1 * c).into_affine();
        assert_eq!(lhs1, rhs1, "s*b1 != t1 + c*p1");
    }

    /// Verifies that a wrong secret produces a proof that fails verification.
    #[test]
    fn sigma_dlog_eq_prove_wrong_secret_fails() {
        let chain_id = 1u8;
        let ace_bytes = [0u8; 32];

        let secret = Fr::from_le_bytes_mod_order(&[1u8; 32]);
        let wrong_secret = Fr::from_le_bytes_mod_order(&[2u8; 32]);

        let b0 = G1Affine::generator();
        let b1: G1Affine = (b0 * Fr::from(3u64)).into_affine();
        let p0: G1Affine = (b0 * secret).into_affine();

        let mut b0_bytes = [0u8; 48];
        let mut b1_bytes = [0u8; 48];
        let mut p0_bytes = [0u8; 48];
        b0.serialize_compressed(&mut b0_bytes[..]).unwrap();
        b1.serialize_compressed(&mut b1_bytes[..]).unwrap();
        p0.serialize_compressed(&mut p0_bytes[..]).unwrap();

        // Prove with wrong_secret (doesn't satisfy secret*b0 == p0)
        let (p1_bytes, t0_bytes, t1_bytes, s_bytes) =
            sigma_dlog_eq_prove(chain_id, &ace_bytes, &b0_bytes, &p0_bytes, &b1_bytes, wrong_secret)
                .unwrap();

        let t0 = G1Affine::deserialize_compressed(t0_bytes.as_slice()).unwrap();
        let s_fr = Fr::from_le_bytes_mod_order(&s_bytes);

        let mut trx: Vec<u8> = Vec::new();
        trx.push(chain_id);
        trx.extend_from_slice(&ace_bytes);
        trx.extend_from_slice(&[0x03, b'v', b's', b's']);
        for pt in [&b0_bytes, &p0_bytes, &b1_bytes, &p1_bytes, &t0_bytes, &t1_bytes] {
            trx.push(0x00); trx.push(0x30); trx.extend_from_slice(pt);
        }
        let hash = Sha512::digest(&trx);
        let c = Fr::from_le_bytes_mod_order(&hash.iter().rev().cloned().collect::<Vec<_>>());

        let lhs0: G1Affine = (b0 * s_fr).into_affine();
        let rhs0: G1Affine = (t0.into_group() + p0 * c).into_affine();
        // p0 = secret*b0 but proof was made with wrong_secret, so this should not hold
        assert_ne!(lhs0, rhs0, "proof with wrong secret should not verify");
    }
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

    let payload = dc1_bytes(&shares_to_reveal);
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
