// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! One independently running ACE epoch instance. An E5 HANDOFF worker and an
//! E6 INIT worker can run concurrently in one process; each follows its own
//! `epoch::Session`, while both children use the same `epoch_change::Session`.
//!
//! The caller owns the HTTP/share store. Before an INIT worker signs an on-chain
//! readiness claim, it reconstructs and verifies every result share and waits
//! for the caller to confirm that the complete batch is installed for serving.

use std::collections::HashSet;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use vss_common::group::{BcsElement, BcsScalar};
use vss_common::{normalize_account_addr, parse_ed25519_signing_key_hex, AptosRpc, TxnArg};

const POLL_INTERVAL: Duration = Duration::from_secs(2);
const CHILD_STOP_TIMEOUT: Duration = Duration::from_secs(10);
const INSTALL_TIMEOUT: Duration = Duration::from_secs(15);
const TRANSITION_DONE: u8 = 3;
const DKG_DONE: u8 = 3;
const DKR_DONE: u8 = 4;

/// A phase belongs to an epoch, not to the shared inbound/outbound transition.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    Init,
    Serving,
    Handoff,
    Grace,
    Finished,
}

impl TryFrom<u8> for Phase {
    type Error = anyhow::Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Init),
            1 => Ok(Self::Serving),
            2 => Ok(Self::Handoff),
            3 => Ok(Self::Grace),
            4 => Ok(Self::Finished),
            _ => bail!("unknown epoch phase {value}"),
        }
    }
}

/// Exact BCS mirror of `ace::epoch::Session`; keep field order in sync with Move.
#[derive(Clone, Deserialize, Serialize)]
pub struct EpochSession {
    pub controller: [u8; 32],
    pub epoch: u64,
    phase_code: u8,
    pub nodes: Vec<[u8; 32]>,
    pub threshold: u64,
    pub admin_multisig: [u8; 32],
    pub secrets: Vec<[u8; 32]>,
    pub features: u64,
    pub epoch_duration_micros: u64,
    pub serving_since_micros: u64,
    pub inbound_transition: Option<[u8; 32]>,
    pub outbound_transition: Option<[u8; 32]>,
    pub grace_until_micros: u64,
    pub ready_nodes: Vec<bool>,
}

impl EpochSession {
    pub fn phase(&self) -> Result<Phase> {
        Phase::try_from(self.phase_code)
    }

    fn validate(&self) -> Result<()> {
        let phase = self.phase()?;
        if self.ready_nodes.len() != self.nodes.len() {
            bail!(
                "epoch {} readiness bitmap length differs from committee",
                self.epoch
            );
        }
        match phase {
            Phase::Init if self.inbound_transition.is_none() => {
                bail!("epoch {} INIT has no inbound transition", self.epoch);
            }
            Phase::Handoff if self.outbound_transition.is_none() => {
                bail!("epoch {} HANDOFF has no outbound transition", self.epoch);
            }
            _ => {}
        }
        Ok(())
    }
}

/// All key material stays in process. This type deliberately has no Debug or
/// serialization implementation, so it cannot be accidentally logged or sent
/// to the standalone CLI output.
pub struct PreloadedShare {
    pub keypair_id: String,
    pub epoch: u64,
    pub secret_session: String,
    pub scalar_le32: [u8; 32],
    pub group_scheme: u8,
    pub expected_usage: u64,
    pub eval_point: u64,
    pub note: String,
}

/// An atomic batch of all shares for one epoch. The caller must install every
/// entry and make the handler ready before confirming the event.
pub struct ShareBatch {
    pub epoch: u64,
    pub epoch_session: String,
    pub features: u64,
    pub shares: Vec<PreloadedShare>,
}

pub enum ShareEvent {
    Install {
        batch: ShareBatch,
        installed: oneshot::Sender<()>,
    },
    Phase {
        epoch: u64,
        phase: Phase,
        grace_until_micros: u64,
    },
    Retire {
        epoch: u64,
    },
}

/// One invocation owns one on-chain epoch session. Cloning the config lets an
/// operator in both committees run two instances concurrently via `tokio::spawn`.
/// Secrets are never included in logs or sent to an external transport here.
#[derive(Clone)]
pub struct RunConfig {
    pub rpc_url: String,
    pub rpc_api_key: Option<String>,
    pub rpc_gas_key: Option<String>,
    pub ace_contract: String,
    pub epoch_session: String,
    pub expected_epoch: Option<u64>,
    pub account_addr: String,
    pub account_sk_hex: String,
    pub pke_dk_hex: String,
    pub share_sink: Option<mpsc::Sender<ShareEvent>>,
}

/// Fetch one complete on-chain epoch snapshot through the versioned BCS view.
pub async fn fetch_session(rpc: &AptosRpc, ace: &str, epoch_session: &str) -> Result<EpochSession> {
    let session: EpochSession = view_bcs(rpc, ace, "epoch", epoch_session).await?;
    session.validate()?;
    Ok(session)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Role {
    Inbound,
    Outbound,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ChildKey {
    role: Role,
    transition: [u8; 32],
}

fn desired_child(session: &EpochSession, account: &[u8; 32]) -> Result<Option<ChildKey>> {
    if !session.nodes.contains(account) {
        return Ok(None);
    }
    Ok(match session.phase()? {
        Phase::Init => session.inbound_transition.map(|transition| ChildKey {
            role: Role::Inbound,
            transition,
        }),
        Phase::Handoff => session.outbound_transition.map(|transition| ChildKey {
            role: Role::Outbound,
            transition,
        }),
        Phase::Serving | Phase::Grace | Phase::Finished => None,
    })
}

struct Child {
    key: ChildKey,
    stop: oneshot::Sender<()>,
    join: JoinHandle<Result<()>>,
}

fn start_child(config: &RunConfig, key: ChildKey) -> Child {
    let (stop, stopped) = oneshot::channel();
    let session = address_hex(&key.transition);
    let join = match key.role {
        Role::Inbound => {
            let cfg = epoch_change_nxt::RunConfig {
                rpc_url: config.rpc_url.clone(),
                rpc_api_key: config.rpc_api_key.clone(),
                rpc_gas_key: config.rpc_gas_key.clone(),
                ace_contract: config.ace_contract.clone(),
                epoch_change_session: session,
                account_addr: config.account_addr.clone(),
                account_sk_hex: config.account_sk_hex.clone(),
                pke_dk_hex: config.pke_dk_hex.clone(),
            };
            tokio::spawn(async move { epoch_change_nxt::run(cfg, stopped).await })
        }
        Role::Outbound => {
            let cfg = epoch_change_cur::RunConfig {
                rpc_url: config.rpc_url.clone(),
                rpc_api_key: config.rpc_api_key.clone(),
                rpc_gas_key: config.rpc_gas_key.clone(),
                ace_contract: config.ace_contract.clone(),
                epoch_change_session: session,
                account_addr: config.account_addr.clone(),
                account_sk_hex: config.account_sk_hex.clone(),
                pke_dk_hex: config.pke_dk_hex.clone(),
            };
            tokio::spawn(async move { epoch_change_cur::run(cfg, stopped).await })
        }
    };
    Child { key, stop, join }
}

async fn stop_child(child: Child) {
    let Child {
        key,
        stop,
        mut join,
    } = child;
    let _ = stop.send(());
    if tokio::time::timeout(CHILD_STOP_TIMEOUT, &mut join)
        .await
        .is_err()
    {
        join.abort();
        let _ = join.await;
    }
    eprintln!(
        "epoch-worker: stopped {:?} transition={}",
        key.role,
        address_hex(&key.transition)
    );
}

fn parse_address(input: &str) -> Result<[u8; 32]> {
    let raw = input.trim().strip_prefix("0x").unwrap_or(input.trim());
    let decoded = hex::decode(raw).with_context(|| format!("invalid account address {input}"))?;
    if decoded.len() > 32 {
        bail!("account address exceeds 32 bytes");
    }
    let mut out = [0u8; 32];
    out[32 - decoded.len()..].copy_from_slice(&decoded);
    Ok(out)
}

fn address_hex(address: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(address))
}

async fn view_bcs<T: DeserializeOwned>(
    rpc: &AptosRpc,
    ace: &str,
    module: &str,
    address: &str,
) -> Result<T> {
    let output = rpc
        .call_view(
            &format!("{ace}::{module}::get_session_bcs"),
            &[json!(address)],
        )
        .await?;
    let hex = output
        .first()
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{module} view returned no BCS bytes"))?;
    let bytes = hex::decode(hex.trim_start_matches("0x"))?;
    bcs::from_bytes(&bytes).with_context(|| format!("decode {module} Session BCS"))
}

#[derive(Deserialize)]
struct DkgSession {
    _caller: [u8; 32],
    workers: Vec<[u8; 32]>,
    _threshold: u64,
    public_base_element: BcsElement,
    expected_usage: u64,
    note: String,
    state: u8,
    _vss_sessions: Vec<[u8; 32]>,
    _done_flags: Vec<bool>,
    _secretly_scaled_element: Option<BcsElement>,
    share_pks: Vec<BcsElement>,
}

#[derive(Deserialize)]
struct DkrSession {
    _caller: [u8; 32],
    public_base_element: BcsElement,
    _secretly_scaled_element: BcsElement,
    _original_session: [u8; 32],
    _previous_session: [u8; 32],
    expected_usage: u64,
    note: String,
    _current_nodes: Vec<[u8; 32]>,
    _current_threshold: u64,
    new_nodes: Vec<[u8; 32]>,
    _new_threshold: u64,
    state_code: u8,
    _src_share_pks: Vec<BcsElement>,
    _vss_sessions: Vec<[u8; 32]>,
    _vss_contribution_flags: Vec<bool>,
    _lagrange_coeffs_at_zero: Vec<BcsScalar>,
    share_pks: Vec<BcsElement>,
}

struct SecretMetadata {
    expected_usage: u64,
    note: String,
    base: BcsElement,
    share_pk: BcsElement,
}

async fn fetch_secret_metadata(
    rpc: &AptosRpc,
    ace: &str,
    secret: &str,
    nodes: &[[u8; 32]],
    my_idx: usize,
) -> Result<SecretMetadata> {
    match view_bcs::<DkrSession>(rpc, ace, "dkr", secret).await {
        Ok(session) => {
            if session.state_code != DKR_DONE {
                bail!("DKR secret {secret} is not complete");
            }
            if session.new_nodes != nodes {
                bail!("DKR secret {secret} committee differs from epoch committee");
            }
            let share_pk = session.share_pks.get(my_idx).cloned().ok_or_else(|| {
                anyhow!("DKR secret {secret} has no share public key for node index {my_idx}")
            })?;
            Ok(SecretMetadata {
                expected_usage: session.expected_usage,
                note: session.note,
                base: session.public_base_element,
                share_pk,
            })
        }
        Err(dkr_error) => {
            let session: DkgSession =
                view_bcs(rpc, ace, "dkg", secret).await.with_context(|| {
                    format!("secret {secret} is neither DKR ({dkr_error:#}) nor DKG")
                })?;
            if session.state != DKG_DONE {
                bail!("DKG secret {secret} is not complete");
            }
            if session.workers != nodes {
                bail!("DKG secret {secret} committee differs from epoch committee");
            }
            let share_pk = session.share_pks.get(my_idx).cloned().ok_or_else(|| {
                anyhow!("DKG secret {secret} has no share public key for node index {my_idx}")
            })?;
            Ok(SecretMetadata {
                expected_usage: session.expected_usage,
                note: session.note,
                base: session.public_base_element,
                share_pk,
            })
        }
    }
}

fn verify_reconstructed_share(
    scalar_le32: [u8; 32],
    scheme: u8,
    metadata: &SecretMetadata,
) -> Result<()> {
    if metadata.base.scheme() != scheme || metadata.share_pk.scheme() != scheme {
        bail!("reconstructed share group scheme differs from on-chain base/share public key");
    }
    let scalar = vss_common::crypto::fr_from_le_bytes(scalar_le32);
    let derived_pk = vss_common::crypto::group_compressed_with_base(
        scheme,
        scalar,
        metadata.base.point_bytes(),
    )?;
    if derived_pk != metadata.share_pk.point_bytes() {
        bail!("reconstructed share does not match its on-chain public key");
    }
    Ok(())
}

async fn preload_shares(
    rpc: &AptosRpc,
    config: &RunConfig,
    session: &EpochSession,
    sessions: &[[u8; 32]],
    my_idx: usize,
    pke_dk: &[u8],
) -> Result<Vec<PreloadedShare>> {
    let ace = normalize_account_addr(&config.ace_contract);
    let my_addr = normalize_account_addr(&config.account_addr);
    let eval_point = (my_idx + 1) as u64;
    let mut keypairs = HashSet::new();
    let mut shares = Vec::with_capacity(sessions.len());

    for secret in sessions {
        let secret_session = address_hex(secret);
        let (scalar_le32, keypair_id, group_scheme) =
            vss_common::reconstruct_share(rpc, &ace, &secret_session, &my_addr, pke_dk)
                .await
                .with_context(|| format!("reconstruct secret {secret_session}"))?;
        let metadata =
            fetch_secret_metadata(rpc, &ace, &secret_session, &session.nodes, my_idx).await?;
        verify_reconstructed_share(scalar_le32, group_scheme, &metadata)
            .with_context(|| format!("verify secret {secret_session}"))?;
        let keypair_id = normalize_account_addr(&keypair_id);
        if !keypairs.insert(keypair_id.clone()) {
            bail!(
                "epoch {} contains duplicate keypair ID {keypair_id}",
                session.epoch
            );
        }
        shares.push(PreloadedShare {
            keypair_id,
            epoch: session.epoch,
            secret_session,
            scalar_le32,
            group_scheme,
            expected_usage: metadata.expected_usage,
            eval_point,
            note: metadata.note,
        });
    }
    Ok(shares)
}

fn parse_u64(value: &Value, field: &str) -> Result<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
        .ok_or_else(|| anyhow!("invalid {field} in epoch-change resource"))
}

fn parse_address_list(value: &Value, field: &str) -> Result<Vec<[u8; 32]>> {
    value
        .as_array()
        .ok_or_else(|| anyhow!("missing {field} in epoch-change resource"))?
        .iter()
        .map(|address| {
            let address = address
                .as_str()
                .ok_or_else(|| anyhow!("invalid {field} address"))?;
            parse_address(address)
        })
        .collect()
}

/// `None` means the shared DKR/DKG transition is still running. The result
/// addresses are immutable after `STATE__DONE`.
async fn inbound_result_sessions(
    rpc: &AptosRpc,
    ace: &str,
    session: &EpochSession,
) -> Result<Option<Vec<[u8; 32]>>> {
    let transition = session
        .inbound_transition
        .ok_or_else(|| anyhow!("INIT has no inbound transition"))?;
    let transition_addr = address_hex(&transition);
    let data = rpc
        .get_resource_data(&transition_addr, &format!("{ace}::epoch_change::Session"))
        .await?;
    let state_code = parse_u64(&data["state_code"], "state_code")?;
    if state_code != TRANSITION_DONE as u64 {
        return Ok(None);
    }
    if parse_address_list(&data["nxt_nodes"], "nxt_nodes")? != session.nodes
        || parse_u64(&data["nxt_threshold"], "nxt_threshold")? != session.threshold
    {
        bail!(
            "inbound transition {transition_addr} does not target epoch {} committee",
            session.epoch
        );
    }
    let mut secrets = parse_address_list(&data["dkrs"], "dkrs")?;
    secrets.extend(parse_address_list(&data["dkgs"], "dkgs")?);
    Ok(Some(secrets))
}

async fn install_batch(
    sink: &mpsc::Sender<ShareEvent>,
    epoch_session: &str,
    session: &EpochSession,
    shares: Vec<PreloadedShare>,
) -> Result<()> {
    let (installed, confirmed) = oneshot::channel();
    sink.send(ShareEvent::Install {
        batch: ShareBatch {
            epoch: session.epoch,
            epoch_session: epoch_session.to_owned(),
            features: session.features,
            shares,
        },
        installed,
    })
    .await
    .map_err(|_| anyhow!("share sink disconnected before installation"))?;
    tokio::time::timeout(INSTALL_TIMEOUT, confirmed)
        .await
        .context("share sink did not confirm installation")?
        .map_err(|_| anyhow!("share sink dropped installation confirmation"))?;
    Ok(())
}

/// Follow one epoch protocol instance until it retires or the caller stops it.
/// The network supervisor may run this function for adjacent epochs at once.
pub async fn run(config: RunConfig, mut shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
    let rpc = AptosRpc::new_with_gas_key(
        config.rpc_url.clone(),
        config.rpc_api_key.clone(),
        config.rpc_gas_key.clone(),
    );
    let sk = parse_ed25519_signing_key_hex(&config.account_sk_hex)?;
    let vk = sk.verifying_key();
    let account = parse_address(&config.account_addr)?;
    let account_addr = address_hex(&account);
    let ace = normalize_account_addr(&config.ace_contract);
    let epoch_session = normalize_account_addr(&config.epoch_session);
    let pke_dk = hex::decode(config.pke_dk_hex.trim_start_matches("0x"))
        .context("decode PKE decryption key")?;

    let mut interval = tokio::time::interval(POLL_INTERVAL);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut child: Option<Child> = None;
    let mut completed_child: Option<ChildKey> = None;
    let mut installed = false;
    let mut warned_missing_sink = false;
    let mut last_phase: Option<Phase> = None;

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                if let Some(child) = child.take() {
                    stop_child(child).await;
                }
                return Ok(());
            },
            _ = interval.tick() => {},
        }

        let session = match fetch_session(&rpc, &ace, &epoch_session).await {
            Ok(session) => session,
            Err(error) => {
                eprintln!("epoch-worker: fetch epoch session={epoch_session}: {error:#}");
                continue;
            }
        };
        if config
            .expected_epoch
            .is_some_and(|expected| expected != session.epoch)
        {
            bail!(
                "epoch session={epoch_session} has epoch {}, expected {:?}",
                session.epoch,
                config.expected_epoch
            );
        }
        let my_idx = session.nodes.iter().position(|node| node == &account);
        if my_idx.is_none() {
            bail!(
                "account {account_addr} is not a member of epoch {}",
                session.epoch
            );
        }
        let phase = session.phase()?;

        if child
            .as_ref()
            .is_some_and(|running| running.join.is_finished())
        {
            let finished = child.take().expect("checked child presence");
            let key = finished.key;
            match finished.join.await {
                Ok(Ok(())) => completed_child = Some(key),
                Ok(Err(error)) => {
                    eprintln!(
                        "epoch-worker: {:?} transition={} failed: {error:#}",
                        key.role,
                        address_hex(&key.transition)
                    );
                    completed_child = None;
                }
                Err(error) => {
                    eprintln!(
                        "epoch-worker: {:?} transition={} task exited: {error:#}",
                        key.role,
                        address_hex(&key.transition)
                    );
                    completed_child = None;
                }
            }
        }
        let desired = desired_child(&session, &account)?;
        if child.as_ref().map(|running| running.key) != desired {
            if let Some(running) = child.take() {
                stop_child(running).await;
            }
        }
        if let Some(key) = desired {
            if child.is_none() && completed_child != Some(key) {
                child = Some(start_child(&config, key));
            }
        }

        if !installed {
            let sessions = match phase {
                Phase::Init => match inbound_result_sessions(&rpc, &ace, &session).await {
                    Ok(Some(sessions)) => Some(sessions),
                    Ok(None) => None,
                    Err(error) => {
                        eprintln!(
                            "epoch-worker: inbound epoch={} not ready: {error:#}",
                            session.epoch
                        );
                        None
                    }
                },
                Phase::Serving | Phase::Handoff | Phase::Grace => Some(session.secrets.clone()),
                Phase::Finished => None,
            };
            if let Some(sessions) = sessions {
                if config.share_sink.is_none() && !sessions.is_empty() {
                    if !warned_missing_sink {
                        eprintln!("epoch-worker: no in-process share sink; transition roles run, but epoch {} readiness will not be claimed", session.epoch);
                        warned_missing_sink = true;
                    }
                    continue;
                }
                let shares = match preload_shares(
                    &rpc,
                    &config,
                    &session,
                    &sessions,
                    my_idx.expect("checked membership"),
                    &pke_dk,
                )
                .await
                {
                    Ok(shares) => shares,
                    Err(error) => {
                        eprintln!(
                            "epoch-worker: preload epoch={} failed: {error:#}",
                            session.epoch
                        );
                        continue;
                    }
                };
                if let Some(sink) = &config.share_sink {
                    if let Err(error) = install_batch(sink, &epoch_session, &session, shares).await
                    {
                        eprintln!(
                            "epoch-worker: install epoch={} failed: {error:#}",
                            session.epoch
                        );
                        continue;
                    }
                    installed = true;
                } else if sessions.is_empty() {
                    installed = true;
                }
            }
        }

        if phase == Phase::Init && installed {
            let idx = my_idx.expect("checked membership");
            if !session.ready_nodes[idx] {
                if let Err(error) = rpc
                    .submit_txn(
                        &sk,
                        &vk,
                        &account_addr,
                        &format!("{ace}::epoch::acknowledge_ready"),
                        &[],
                        &[TxnArg::Address(&epoch_session)],
                    )
                    .await
                {
                    eprintln!(
                        "epoch-worker: acknowledge epoch={} failed: {error:#}",
                        session.epoch
                    );
                }
            }
        }

        if last_phase != Some(phase) {
            if let Some(sink) = &config.share_sink {
                sink.send(ShareEvent::Phase {
                    epoch: session.epoch,
                    phase,
                    grace_until_micros: session.grace_until_micros,
                })
                .await
                .map_err(|_| anyhow!("share sink disconnected during epoch phase update"))?;
            }
            last_phase = Some(phase);
        }
        if phase == Phase::Finished {
            if let Some(running) = child.take() {
                stop_child(running).await;
            }
            if let Some(sink) = &config.share_sink {
                sink.send(ShareEvent::Retire {
                    epoch: session.epoch,
                })
                .await
                .map_err(|_| anyhow!("share sink disconnected during retirement"))?;
            }
            return Ok(());
        }
    }
}
