// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Programmatic API for the on-chain VSS dealer client.
//! `main.rs` is a thin CLI wrapper over [`run`].

use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc, Mutex, OnceLock,
    },
    time::{Duration, Instant},
};

use anyhow::{anyhow, Result};
use ark_bls12_381::Fr;
use ark_ff::{PrimeField, UniformRand};
use async_trait::async_trait;
use node_msg_gateway::{
    ensure_node_msg_gateway, GatewayContext, GatewayHandle, NodeHandlerError,
    VerifiedVssShareRequest, VssShareRequestHandler,
};
use rand::rngs::OsRng;
use tokio::sync::oneshot;
use vss_common::crypto::{
    fr_from_le_bytes, fr_to_le_bytes, group_compressed_with_base, group_identity_compressed,
    pedersen_commit_compressed, poly_eval,
};
use vss_common::group::BcsElement;
use vss_common::offchain::encrypt_share_response_ciphertext;
use vss_common::pke;
use vss_common::session::{
    BcsPcsCommitment, BcsPcsOpening, BcsPcsPublicParams, BcsSigmaDlogLinearProof,
    ACK_WINDOW_MICROS, STATE_DEALER_DEAL, STATE_FAILED, STATE_RECIPIENT_ACK, STATE_SUCCESS,
    STATE_VERIFY_DEALER_OPENING,
};
use vss_common::sigma_dlog_linear;
use vss_common::vss_types::{
    dc0_bytes, dc1_bytes, opening_for_scheme, private_share_message_bytes,
};
use vss_common::{normalize_account_addr, parse_ed25519_signing_key_hex, AptosRpc, TxnArg};
use vss_store::{connect_vss_store, DealerStateRecord, VssStore};

pub const POLL_SECS: u64 = 1;

const DEALER_STATE_VERSION: u8 = 1;
const SERVING_ENTRY_TTL_SECS: u64 = 15;

static NEXT_SERVING_OWNER_ID: AtomicU64 = AtomicU64::new(1);
static VSS_SHARE_REGISTRY: OnceLock<Mutex<HashMap<String, Arc<RegisteredVssDealerSession>>>> =
    OnceLock::new();

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
    /// Optional old Pedersen blinding for reshare consistency proofs (32-byte Fr LE).
    pub previous_blinding_override: Option<[u8; 32]>,
    /// Ed25519 node-to-node messaging signing key hex. Accepted now for symmetry
    /// with holder clients; dealer share responses are verified against PCS commitments.
    pub sig_sk_hex: Option<String>,
    /// Persistent VSS store URL.
    pub vss_store_url: Option<String>,
    /// Address this process listens on for node-to-node VSS share requests.
    pub node_msg_listen: Option<String>,
}

struct DealingData {
    coefs_r: Vec<Fr>,
    coefs_p: Vec<Fr>,
    evals_p: Vec<Fr>,
    evals_r: Vec<Fr>,
    commitment_points: Vec<Vec<u8>>,
}

#[derive(Clone)]
struct RegisteredVssDealerSession {
    owner_id: u64,
    session_addr: String,
    dealer_addr: String,
    share_holders: Vec<String>,
    scheme: u8,
    pcs_context: BcsPcsPublicParams,
    pcs_commitment: BcsPcsCommitment,
    coefs_p: Vec<Fr>,
    coefs_r: Vec<Fr>,
    expires_at: Instant,
}

#[derive(Clone, Default)]
struct DealerVssShareRequestHandler;

struct Dc0Submission {
    tx_hash: String,
    state_bytes: Vec<u8>,
}

#[async_trait]
impl VssShareRequestHandler for DealerVssShareRequestHandler {
    async fn handle(
        &self,
        request: VerifiedVssShareRequest,
    ) -> std::result::Result<pke::Ciphertext, NodeHandlerError> {
        let share_request = request.payload.share_request();
        let expected_request_id = share_request.request_id().map_err(NodeHandlerError::from)?;
        if request.request_id != expected_request_id {
            return Err(NodeHandlerError::bad_request(format!(
                "share request ID does not match request body: expected {expected_request_id}"
            )));
        }
        let requested_session = normalize_account_addr(&share_request.session_addr);
        let entry = get_registered_vss_dealer_session(&requested_session)
            .map_err(NodeHandlerError::from)?;

        if entry.dealer_addr != request.payload.recipient {
            return Err(NodeHandlerError::bad_request(format!(
                "share request recipient {} does not match dealer {}",
                request.payload.recipient, entry.dealer_addr
            )));
        }
        let holder_index = share_request.holder_index as usize;
        let expected_sender = entry.share_holders.get(holder_index).ok_or_else(|| {
            NodeHandlerError::bad_request(format!(
                "holder index {} out of range",
                share_request.holder_index
            ))
        })?;
        if expected_sender != &request.payload.sender {
            return Err(NodeHandlerError::bad_request(format!(
                "share request sender {} does not match holder {} at index {}",
                request.payload.sender, expected_sender, share_request.holder_index
            )));
        }

        let eval_position = share_request.holder_index + 1;
        let x = Fr::from(eval_position);
        let y_bytes = fr_to_le_bytes(poly_eval(&entry.coefs_p, x));
        let r_bytes = fr_to_le_bytes(poly_eval(&entry.coefs_r, x));
        let plaintext =
            private_share_message_bytes(entry.scheme, eval_position, &y_bytes, &r_bytes)
                .map_err(NodeHandlerError::from)?;
        vss_common::vss_types::pedersen_verify_private_share(
            &plaintext,
            &entry.pcs_context,
            &entry.pcs_commitment,
            eval_position,
        )
        .map_err(NodeHandlerError::from)?;
        encrypt_share_response_ciphertext(
            &share_request,
            &request.payload.sender,
            &request.payload.recipient,
            &request.request_id,
            &plaintext,
        )
        .map_err(NodeHandlerError::from)
    }
}

fn vss_share_registry() -> &'static Mutex<HashMap<String, Arc<RegisteredVssDealerSession>>> {
    VSS_SHARE_REGISTRY.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_serving_owner_id() -> u64 {
    NEXT_SERVING_OWNER_ID.fetch_add(1, Ordering::Relaxed)
}

fn upsert_vss_share_serving(
    owner_id: u64,
    session_addr: &str,
    dealer_addr: &str,
    session: &vss_common::Session,
    bcs_session: &vss_common::session::BcsSession,
    state_bytes: &[u8],
) -> Result<()> {
    let dc0 = bcs_session
        .dealer_contribution_0
        .as_ref()
        .ok_or_else(|| anyhow!("dealer contribution 0 missing"))?;
    let (coefs_p, coefs_r) = decode_dealer_state(state_bytes)?;
    let entry = RegisteredVssDealerSession {
        owner_id,
        session_addr: normalize_account_addr(session_addr),
        dealer_addr: normalize_account_addr(dealer_addr),
        share_holders: session
            .share_holders
            .iter()
            .map(|addr| normalize_account_addr(addr))
            .collect(),
        scheme: bcs_session.scheme,
        pcs_context: bcs_session.pcs_context.clone(),
        pcs_commitment: dc0.pcs_commitment.clone(),
        coefs_p,
        coefs_r,
        expires_at: Instant::now() + Duration::from_secs(SERVING_ENTRY_TTL_SECS),
    };
    let mut registry = vss_share_registry()
        .lock()
        .map_err(|_| anyhow!("VSS share registry is poisoned"))?;
    prune_expired_vss_share_entries(&mut registry);
    registry.insert(entry.session_addr.clone(), Arc::new(entry));
    Ok(())
}

fn unregister_vss_share_serving(session_addr: &str, owner_id: u64) {
    let session_addr = normalize_account_addr(session_addr);
    let Ok(mut registry) = vss_share_registry().lock() else {
        return;
    };
    let should_remove = registry
        .get(&session_addr)
        .is_some_and(|entry| entry.owner_id == owner_id);
    if should_remove {
        registry.remove(&session_addr);
    }
}

struct VssShareServingGuard {
    session_addr: String,
    owner_id: u64,
    registered: bool,
}

impl VssShareServingGuard {
    fn new(session_addr: &str) -> Self {
        Self {
            session_addr: normalize_account_addr(session_addr),
            owner_id: next_serving_owner_id(),
            registered: false,
        }
    }

    fn owner_id(&self) -> u64 {
        self.owner_id
    }

    fn mark_registered(&mut self) {
        self.registered = true;
    }

    fn unregister_now(&mut self) {
        if self.registered {
            unregister_vss_share_serving(&self.session_addr, self.owner_id);
            self.registered = false;
        }
    }
}

impl Drop for VssShareServingGuard {
    fn drop(&mut self) {
        self.unregister_now();
    }
}

fn get_registered_vss_dealer_session(
    session_addr: &str,
) -> Result<Arc<RegisteredVssDealerSession>> {
    let session_addr = normalize_account_addr(session_addr);
    let mut registry = vss_share_registry()
        .lock()
        .map_err(|_| anyhow!("VSS share registry is poisoned"))?;
    prune_expired_vss_share_entries(&mut registry);
    registry
        .get(&session_addr)
        .cloned()
        .ok_or_else(|| anyhow!("VSS session {session_addr} is not being served"))
}

fn prune_expired_vss_share_entries(
    registry: &mut HashMap<String, Arc<RegisteredVssDealerSession>>,
) {
    let now = Instant::now();
    registry.retain(|_, entry| entry.expires_at > now);
}

pub async fn ensure_vss_share_gateway(
    rpc: &AptosRpc,
    ace: &str,
    account_addr: &str,
    node_msg_listen: &str,
) -> Result<GatewayHandle> {
    let chain_id = rpc
        .get_chain_id()
        .await
        .map_err(|e| anyhow!("get chain_id for node-msg gateway: {}", e))?;
    let gateway = ensure_node_msg_gateway(
        node_msg_listen,
        GatewayContext::new(chain_id, ace, account_addr),
    )
    .await?;
    gateway
        .register_vss_share_handler(Arc::new(DealerVssShareRequestHandler))
        .await;
    Ok(gateway)
}

async fn preload_share_holder_sig_keys(
    gateway: &GatewayHandle,
    rpc: &AptosRpc,
    ace: &str,
    share_holders: &[String],
) -> Result<()> {
    let mut loads = tokio::task::JoinSet::new();
    for holder in share_holders {
        let holder = normalize_account_addr(holder);
        let holder_for_load = holder.clone();
        let gateway = gateway.clone();
        let rpc = rpc.clone();
        let ace = ace.to_string();
        loads.spawn(async move {
            gateway
                .preload_sig_verification_key(&holder, move || async move {
                    rpc.get_sig_verification_key(&ace, &holder_for_load).await
                })
                .await
                .map_err(|e| anyhow!("preload signature verification key for {holder}: {e:#}"))
        });
    }

    while let Some(result) = loads.join_next().await {
        result.map_err(|e| anyhow!("holder signature key preload task failed: {e}"))??;
    }
    Ok(())
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
    let store = match config.vss_store_url.as_ref() {
        Some(url) => Some(connect_vss_store(url)?),
        None => None,
    };
    let mut serving_guard = VssShareServingGuard::new(&session_addr);
    let mut dealer_state_bytes: Option<Vec<u8>> = None;
    let mut holder_sig_keys_ready = false;

    println!(
        "vss-dealer: starting (account={} session={} ace={})",
        account_addr, session_addr, ace
    );

    let gateway = if let Some(listen) = config.node_msg_listen.as_ref() {
        if store.is_none() {
            return Err(anyhow!("--node-msg-listen requires --vss-store-url"));
        }
        Some(ensure_vss_share_gateway(&rpc, &ace, &account_addr, listen).await?)
    } else {
        None
    };

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

        if !holder_sig_keys_ready {
            if let Some(gateway) = gateway.as_ref() {
                match preload_share_holder_sig_keys(gateway, &rpc, &ace, &session.share_holders)
                    .await
                {
                    Ok(()) => holder_sig_keys_ready = true,
                    Err(e) => {
                        eprintln!("vss-dealer: holder signature key preload failed: {e:#}")
                    }
                }
            }
        }

        let should_serve_shares = session.state_code == STATE_RECIPIENT_ACK
            && !session.dealer_contribution_0.is_empty()
            && session.dealer_contribution_1.is_empty();
        if should_serve_shares {
            if gateway.is_some() && holder_sig_keys_ready {
                let store = store
                    .as_deref()
                    .ok_or_else(|| anyhow!("vss-dealer requires --vss-store-url"))?;
                let state_bytes = match dealer_state_bytes.as_ref() {
                    Some(bytes) => bytes.clone(),
                    None => {
                        let state = store.get_dealer_state(&session_addr)?.ok_or_else(|| {
                            anyhow!("dealer state missing from VSS store for {session_addr}")
                        })?;
                        let bytes = state.state_bytes;
                        dealer_state_bytes = Some(bytes.clone());
                        bytes
                    }
                };
                let bcs_session = rpc
                    .get_session_bcs_decoded(&ace, &session_addr)
                    .await
                    .map_err(|e| anyhow!("failed to fetch BCS session: {}", e))?;
                upsert_vss_share_serving(
                    serving_guard.owner_id(),
                    &session_addr,
                    &account_addr,
                    &session,
                    &bcs_session,
                    &state_bytes,
                )?;
                serving_guard.mark_registered();
            }
        } else {
            serving_guard.unregister_now();
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
                        config.secret_override,
                        config.previous_blinding_override,
                        store.as_deref(),
                    )
                    .await
                    {
                        Ok(submission) => {
                            dealer_state_bytes = Some(submission.state_bytes);
                            println!(
                                "vss-dealer: on_dealer_contribution_0 confirmed: {}",
                                submission.tx_hash
                            );
                        }
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
                            config.secret_override,
                            store.as_deref(),
                        )
                        .await
                        {
                            Ok(h) => {
                                println!("vss-dealer: on_dealer_open confirmed: {}", h);
                                serving_guard.unregister_now();
                            }
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
                    eprintln!("vss-dealer: touch public-key verification error: {:#}", e);
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
    secret_override: Option<[u8; 32]>,
    previous_blinding_override: Option<[u8; 32]>,
    store: Option<&dyn VssStore>,
) -> Result<Dc0Submission> {
    let n = session.share_holders.len();
    let threshold = session.threshold as usize;

    let bcs_session = rpc
        .get_session_bcs_decoded(ace, session_addr)
        .await
        .map_err(|e| anyhow!("failed to fetch BCS session: {}", e))?;
    let scheme = bcs_session.scheme;
    let generator_g_bytes = bcs_session.pcs_context.generator_g.point_bytes().to_vec();
    let generator_h_bytes = bcs_session.pcs_context.generator_h.point_bytes().to_vec();

    let store = store.ok_or_else(|| anyhow!("vss-dealer requires --vss-store-url"))?;
    let (dealing, state_bytes) = load_or_create_dealing_data(
        store,
        session_addr,
        scheme,
        n,
        threshold,
        secret_override,
        previous_blinding_override,
        &generator_g_bytes,
        &generator_h_bytes,
    )?;

    let consistency_proof = match bcs_session.previous_commitment.as_ref() {
        Some(previous) => {
            let old_r = previous_blinding_override.ok_or_else(|| {
                anyhow!("previous commitment VSS requires previous_blinding_override")
            })?;
            Some(
                prove_same_secret(
                    rpc,
                    ace,
                    session_addr,
                    scheme,
                    previous,
                    &bcs_session.pcs_context.generator_g,
                    &bcs_session.pcs_context.generator_h,
                    &dealing.commitment_points[0],
                    dealing.evals_p[0],
                    Fr::from_le_bytes_mod_order(&old_r),
                    dealing.evals_r[0],
                )
                .await?,
            )
        }
        None => None,
    };

    let payload = dc0_bytes(scheme, &dealing.commitment_points, consistency_proof)?;
    println!(
        "vss-dealer: dc0 payload {} bytes, {} shares, threshold {} (scheme={})",
        payload.len(),
        n,
        threshold,
        scheme
    );

    let args = [TxnArg::Address(session_addr), TxnArg::Bytes(&payload)];
    let tx_hash = rpc
        .submit_txn(
            sk,
            vk,
            account_addr,
            &format!("{}::vss::on_dealer_contribution_0", ace),
            &[],
            &args,
        )
        .await?;
    Ok(Dc0Submission {
        tx_hash,
        state_bytes,
    })
}

async fn build_and_submit_dc1(
    rpc: &AptosRpc,
    sk: &ed25519_dalek::SigningKey,
    vk: &ed25519_dalek::VerifyingKey,
    account_addr: &str,
    session_addr: &str,
    ace: &str,
    session: &vss_common::Session,
    secret_override: Option<[u8; 32]>,
    store: Option<&dyn VssStore>,
) -> Result<String> {
    let n = session.share_holders.len();
    let threshold = session.threshold as usize;

    let bcs_session = rpc
        .get_session_bcs_decoded(ace, session_addr)
        .await
        .map_err(|e| anyhow!("failed to fetch BCS session: {}", e))?;
    let scheme = bcs_session.scheme;
    let generator_g_bytes = bcs_session.pcs_context.generator_g.point_bytes().to_vec();
    let generator_h_bytes = bcs_session.pcs_context.generator_h.point_bytes().to_vec();

    let store = store.ok_or_else(|| anyhow!("vss-dealer requires --vss-store-url"))?;
    let state = store
        .get_dealer_state(session_addr)?
        .ok_or_else(|| anyhow!("dealer state missing from VSS store for {session_addr}"))?;
    let (coefs_p, coefs_r) = decode_dealer_state(&state.state_bytes)?;
    validate_polynomial_overrides(&coefs_p, &coefs_r, secret_override, None)?;
    let dealing = build_dealing_data_from_polys(
        scheme,
        n,
        threshold,
        coefs_p,
        coefs_r,
        &generator_g_bytes,
        &generator_h_bytes,
    )?;

    let mut shares_to_reveal: Vec<Option<BcsPcsOpening>> = Vec::with_capacity(n + 1);
    let mut public_keys = Vec::with_capacity(n + 1);
    let mut public_key_proofs = Vec::with_capacity(n + 1);
    let chain_id = rpc
        .get_chain_id()
        .await
        .map_err(|e| anyhow!("failed to get chain_id: {}", e))?;
    let ace_addr = addr_to_bytes(ace)?;
    let session_addr_bytes = addr_to_bytes(session_addr)?;

    for eval_position in 0..=n {
        let public_key_bytes =
            group_compressed_with_base(scheme, dealing.evals_p[eval_position], &generator_g_bytes)?;
        let public_key = BcsElement::from_scheme_and_bytes(scheme, public_key_bytes)?;
        let opening_is_private = eval_position == 0
            || session
                .share_holder_acks
                .get(eval_position.saturating_sub(1))
                .copied()
                .unwrap_or(false);

        if opening_is_private {
            shares_to_reveal.push(None);
        } else {
            let y_bytes = fr_to_le_bytes(dealing.evals_p[eval_position]);
            let r_bytes = fr_to_le_bytes(dealing.evals_r[eval_position]);
            shares_to_reveal.push(Some(opening_for_scheme(
                scheme,
                eval_position as u64,
                &y_bytes,
                &r_bytes,
            )?));
        }

        let proof = if opening_is_private {
            Some(prove_public_key(
                chain_id,
                &ace_addr,
                &session_addr_bytes,
                scheme,
                eval_position as u64,
                &bcs_session.pcs_context,
                &public_key,
                &dealing.commitment_points[eval_position],
                dealing.evals_p[eval_position],
                dealing.evals_r[eval_position],
            )?)
        } else {
            None
        };
        public_keys.push(public_key);
        public_key_proofs.push(proof);
    }

    let payload = dc1_bytes(&shares_to_reveal, &public_keys, &public_key_proofs)?;
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

fn prove_public_key(
    chain_id: u8,
    ace_addr: &[u8; 32],
    session_addr: &[u8; 32],
    scheme: u8,
    eval_position: u64,
    pcs_context: &BcsPcsPublicParams,
    public_key: &BcsElement,
    commitment_point_bytes: &[u8],
    secret: Fr,
    blinding: Fr,
) -> Result<BcsSigmaDlogLinearProof> {
    let identity = BcsElement::from_scheme_and_bytes(scheme, group_identity_compressed(scheme)?)?;
    let commitment = BcsElement::from_scheme_and_bytes(scheme, commitment_point_bytes.to_vec())?;
    let b_vals = vec![
        pcs_context.generator_g.clone(),
        identity,
        pcs_context.generator_g.clone(),
        pcs_context.generator_h.clone(),
    ];
    let p_vals = vec![public_key.clone(), commitment];
    sigma_dlog_linear::prove_vss(
        scheme,
        chain_id,
        ace_addr,
        session_addr,
        b"vss::dc1-public-key",
        eval_position,
        &b_vals,
        &p_vals,
        &[secret, blinding],
    )
}

async fn prove_same_secret(
    rpc: &AptosRpc,
    ace: &str,
    session_addr: &str,
    scheme: u8,
    previous: &vss_common::session::BcsPreviousCommitment,
    new_g: &BcsElement,
    new_h: &BcsElement,
    new_commitment_point_bytes: &[u8],
    secret: Fr,
    old_r: Fr,
    new_r: Fr,
) -> Result<BcsSigmaDlogLinearProof> {
    let chain_id = rpc
        .get_chain_id()
        .await
        .map_err(|e| anyhow!("failed to get chain_id: {}", e))?;
    let ace_addr = addr_to_bytes(ace)?;
    let session_addr = addr_to_bytes(session_addr)?;
    let identity = BcsElement::from_scheme_and_bytes(scheme, group_identity_compressed(scheme)?)?;
    let new_commitment_point =
        BcsElement::from_scheme_and_bytes(scheme, new_commitment_point_bytes.to_vec())?;

    let b_vals = vec![
        previous.old_g.clone(),
        previous.old_h.clone(),
        identity.clone(),
        new_g.clone(),
        identity,
        new_h.clone(),
    ];
    let p_vals = vec![previous.old_c.clone(), new_commitment_point];
    sigma_dlog_linear::prove_vss(
        scheme,
        chain_id,
        &ace_addr,
        &session_addr,
        b"vss::dc0-same-secret",
        0,
        &b_vals,
        &p_vals,
        &[secret, old_r, new_r],
    )
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

fn load_or_create_dealing_data(
    store: &dyn VssStore,
    session_addr: &str,
    scheme: u8,
    n: usize,
    threshold: usize,
    secret_override: Option<[u8; 32]>,
    blinding_override: Option<[u8; 32]>,
    generator_g_bytes: &[u8],
    generator_h_bytes: &[u8],
) -> Result<(DealingData, Vec<u8>)> {
    if let Some(state) = store.get_dealer_state(session_addr)? {
        let (coefs_p, coefs_r) = decode_dealer_state(&state.state_bytes)?;
        validate_polynomial_overrides(&coefs_p, &coefs_r, secret_override, blinding_override)?;
        let dealing = build_dealing_data_from_polys(
            scheme,
            n,
            threshold,
            coefs_p,
            coefs_r,
            generator_g_bytes,
            generator_h_bytes,
        )?;
        return Ok((dealing, state.state_bytes));
    }

    let (coefs_p, coefs_r) = sample_polynomials(threshold, secret_override, blinding_override)?;
    let dealing = build_dealing_data_from_polys(
        scheme,
        n,
        threshold,
        coefs_p,
        coefs_r,
        generator_g_bytes,
        generator_h_bytes,
    )?;
    let state_bytes = encode_dealer_state(&dealing.coefs_p, &dealing.coefs_r);
    store.put_dealer_state(DealerStateRecord {
        epoch: 0,
        session_addr: session_addr.to_string(),
        state_bytes: state_bytes.clone(),
    })?;
    Ok((dealing, state_bytes))
}

fn build_dealing_data_from_polys(
    scheme: u8,
    n: usize,
    threshold: usize,
    coefs_p: Vec<Fr>,
    coefs_r: Vec<Fr>,
    generator_g_bytes: &[u8],
    generator_h_bytes: &[u8],
) -> Result<DealingData> {
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

    let mut evals_p = Vec::with_capacity(n + 1);
    let mut evals_r = Vec::with_capacity(n + 1);
    let mut commitment_points = Vec::with_capacity(n + 1);

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
    }

    Ok(DealingData {
        coefs_r,
        coefs_p,
        evals_p,
        evals_r,
        commitment_points,
    })
}

fn encode_dealer_state(coefs_p: &[Fr], coefs_r: &[Fr]) -> Vec<u8> {
    bcs::to_bytes(&(
        DEALER_STATE_VERSION,
        raw_poly_bytes(coefs_p),
        raw_poly_bytes(coefs_r),
    ))
    .expect("bcs serialization failed for VSS dealer state")
}

fn decode_dealer_state(bytes: &[u8]) -> Result<(Vec<Fr>, Vec<Fr>)> {
    let (version, coefs_p, coefs_r): (u8, Vec<Vec<u8>>, Vec<Vec<u8>>) =
        bcs::from_bytes(bytes).map_err(|e| anyhow!("decode VSS dealer state: {}", e))?;
    if version != DEALER_STATE_VERSION {
        return Err(anyhow!(
            "unsupported VSS dealer state version {version}; expected {DEALER_STATE_VERSION}"
        ));
    }
    Ok((decode_raw_poly(coefs_p)?, decode_raw_poly(coefs_r)?))
}

fn raw_poly_bytes(coefs: &[Fr]) -> Vec<Vec<u8>> {
    coefs
        .iter()
        .map(|coef| fr_to_le_bytes(*coef).to_vec())
        .collect()
}

fn decode_raw_poly(raw: Vec<Vec<u8>>) -> Result<Vec<Fr>> {
    raw.into_iter()
        .map(|coef| {
            let coef: [u8; 32] = coef.try_into().map_err(|v: Vec<u8>| {
                anyhow!(
                    "VSS polynomial coefficient must be 32 bytes, got {}",
                    v.len()
                )
            })?;
            Ok(fr_from_le_bytes(coef))
        })
        .collect()
}

fn sample_polynomials(
    threshold: usize,
    secret_override: Option<[u8; 32]>,
    blinding_override: Option<[u8; 32]>,
) -> Result<(Vec<Fr>, Vec<Fr>)> {
    if threshold == 0 {
        return Err(anyhow!("VSS threshold must be positive"));
    }
    let mut rng = OsRng;

    let secret = if let Some(s) = secret_override {
        Fr::from_le_bytes_mod_order(&s)
    } else {
        Fr::rand(&mut rng)
    };
    let mut coefs_p = Vec::with_capacity(threshold);
    coefs_p.push(secret);
    for _ in 1..threshold {
        coefs_p.push(Fr::rand(&mut rng));
    }

    let blinding = if let Some(r) = blinding_override {
        Fr::from_le_bytes_mod_order(&r)
    } else {
        Fr::rand(&mut rng)
    };
    let mut coefs_r = Vec::with_capacity(threshold);
    coefs_r.push(blinding);
    for _ in 1..threshold {
        coefs_r.push(Fr::rand(&mut rng));
    }
    Ok((coefs_p, coefs_r))
}

fn validate_polynomial_overrides(
    coefs_p: &[Fr],
    coefs_r: &[Fr],
    secret_override: Option<[u8; 32]>,
    blinding_override: Option<[u8; 32]>,
) -> Result<()> {
    if let Some(secret) = secret_override {
        let expected = Fr::from_le_bytes_mod_order(&secret);
        if coefs_p.first().copied() != Some(expected) {
            return Err(anyhow!(
                "stored VSS dealer secret constant does not match override"
            ));
        }
    }
    if let Some(blinding) = blinding_override {
        let expected = Fr::from_le_bytes_mod_order(&blinding);
        if coefs_r.first().copied() != Some(expected) {
            return Err(anyhow!(
                "stored VSS dealer blinding constant does not match override"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sample_polynomials_preserves_overrides_but_randomizes_other_coefficients() {
        let secret = [7u8; 32];
        let blinding = [9u8; 32];

        let (p1, r1) = sample_polynomials(3, Some(secret), Some(blinding)).unwrap();
        let (p2, r2) = sample_polynomials(3, Some(secret), Some(blinding)).unwrap();

        assert_eq!(p1[0], Fr::from_le_bytes_mod_order(&secret));
        assert_eq!(r1[0], Fr::from_le_bytes_mod_order(&blinding));
        assert_eq!(p2[0], Fr::from_le_bytes_mod_order(&secret));
        assert_eq!(r2[0], Fr::from_le_bytes_mod_order(&blinding));
        assert_ne!(&p1[1..], &p2[1..]);
        assert_ne!(&r1[1..], &r2[1..]);
    }

    #[test]
    fn dealer_state_rejects_wrong_polynomial_length() {
        let g = vec![0u8; 48];
        let h = vec![0u8; 48];
        let err = match build_dealing_data_from_polys(
            0,
            1,
            2,
            vec![Fr::from(1u64)],
            vec![Fr::from(2u64)],
            &g,
            &h,
        ) {
            Ok(_) => panic!("expected polynomial length mismatch"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("polynomial length mismatch"));
    }
}
