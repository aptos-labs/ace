// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, Result};
use node_msg_gateway::{ensure_node_msg_gateway, GatewayContext};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{oneshot, Semaphore};
use vss_common::{
    normalize_account_addr, parse_ed25519_signing_key_hex, should_submit_rotating_touch, AptosRpc,
};
use vss_store::{connect_vss_store, VssStore};

use crate::config::{resolve_max_concurrent, ChainRpcConfig, RunConfig, RuntimeMode};
use crate::http_server;
use crate::onchain::{addr_bytes_to_string, fetch_state_view_v1, BcsSecretInfo, BcsStateView};
use crate::reconstruction::reconstruct_share_from_store;
use crate::secrets::{LocalSecrets, SecretsProvider, ShareEntry, ShareMap};
use crate::wlog;

// ── Task lifecycle helpers ───────────────────────────────────────────────────

fn stop_tasks(tasks: &mut HashMap<String, oneshot::Sender<()>>) {
    for (_, tx) in tasks.drain() {
        let _ = tx.send(());
    }
}

// ── Dispatch ─────────────────────────────────────────────────────────────────

pub async fn run(config: RunConfig, shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
    run_with_config(config, shutdown_rx).await
}

// ── Runtime supervisor ────────────────────────────────────────────────────────

const PREVIOUS_EPOCH_GRACE_MICROS: u64 = 30_000_000;

#[derive(Clone, Copy)]
struct RuntimeCapabilities {
    can_serve: bool,
    can_drive_protocol: bool,
    can_touch: bool,
}

#[derive(Clone)]
struct ProtocolRuntimeConfig {
    rpc_url: String,
    rpc_api_key: Option<String>,
    rpc_gas_key: Option<String>,
    account_sk_hex: String,
    pke_dk_hex: String,
    sig_sk_hex: String,
    vss_store_url: String,
    node_msg_listen: String,
}

struct UserServerConfig {
    port: u16,
    chain_rpc: ChainRpcConfig,
    max_concurrent: Option<usize>,
    pke_dk_bytes: Arc<Vec<u8>>,
}

struct NetworkSupervisorConfig {
    mode_label: &'static str,
    rpc: AptosRpc,
    ace: String,
    account_addr: String,
    node_listen: String,
    store: Arc<dyn VssStore>,
    capabilities: RuntimeCapabilities,
    protocol: Option<ProtocolRuntimeConfig>,
    user_server: Option<UserServerConfig>,
}

#[derive(Default)]
struct RuntimeTasks {
    epoch_change_cur: HashMap<String, oneshot::Sender<()>>,
    epoch_change_nxt: HashMap<String, oneshot::Sender<()>>,
}

impl RuntimeTasks {
    fn stop_all(&mut self) {
        stop_tasks(&mut self.epoch_change_cur);
        stop_tasks(&mut self.epoch_change_nxt);
    }
}

struct ServingEpoch {
    epoch: u64,
    eval_point: u64,
    secrets: Vec<BcsSecretInfo>,
}

async fn initialize_vss_store_management(
    config: &NetworkSupervisorConfig,
    shutdown_rx: &mut oneshot::Receiver<()>,
) -> Result<Option<(BcsStateView, bool)>> {
    loop {
        let state = match fetch_state_view_v1(&config.rpc, &config.ace).await {
            Ok(s) => s,
            Err(e) => {
                wlog!("network-node: fetch initial state view error: {:#}", e);
                if !sleep_or_shutdown(shutdown_rx, Duration::from_secs(5)).await {
                    return Ok(None);
                }
                continue;
            }
        };
        let reachability_vss_management_enabled = state
            .feature_configs
            .reachability_based_vss_store_management_enabled();
        match configure_vss_store_schema(config, reachability_vss_management_enabled) {
            Ok(()) => return Ok(Some((state, reachability_vss_management_enabled))),
            Err(e) => {
                wlog!("network-node: VSS store schema init error: {:#}", e);
                if !sleep_or_shutdown(shutdown_rx, Duration::from_secs(5)).await {
                    return Ok(None);
                }
            }
        }
    }
}

async fn sleep_or_shutdown(shutdown_rx: &mut oneshot::Receiver<()>, delay: Duration) -> bool {
    let sleep = tokio::time::sleep(delay);
    tokio::pin!(sleep);
    tokio::select! {
        _ = shutdown_rx => false,
        _ = &mut sleep => true,
    }
}

async fn run_supervisor(
    mut config: NetworkSupervisorConfig,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> Result<()> {
    wlog!(
        "network-node: starting {} (account={} ace={})",
        config.mode_label,
        config.account_addr,
        config.ace
    );

    let touch_keys = if config.capabilities.can_touch {
        let protocol = config
            .protocol
            .as_ref()
            .ok_or_else(|| anyhow!("can_touch requires protocol runtime config"))?;
        let sk = parse_ed25519_signing_key_hex(&protocol.account_sk_hex)?;
        let vk = sk.verifying_key();
        Some((sk, vk))
    } else {
        None
    };

    let local = if config.capabilities.can_serve {
        Some(LocalSecrets::empty())
    } else {
        None
    };

    let Some((startup_state, reachability_vss_management_enabled)) =
        initialize_vss_store_management(&config, &mut shutdown_rx).await?
    else {
        wlog!("network-node: shutdown signal received.");
        return Ok(());
    };
    wlog!(
        "network-node: VSS store management mode: {}",
        if reachability_vss_management_enabled {
            "reachability-based"
        } else {
            "legacy epoch-column"
        }
    );

    let chain_id = config
        .rpc
        .get_chain_id()
        .await
        .map_err(|e| anyhow!("get chain_id for node gateway: {e:#}"))?;
    let gateway = ensure_node_msg_gateway(
        &config.node_listen,
        GatewayContext::new(chain_id, &config.ace, &config.account_addr),
    )
    .await?;

    if let Some(user_server) = config.user_server.take() {
        let local = local
            .as_ref()
            .ok_or_else(|| anyhow!("worker handler requires serving capability"))?;
        let state = http_server::AppState {
            provider: Arc::new(SecretsProvider::Local(local.clone())),
            chain_rpc: Arc::new(user_server.chain_rpc),
            concurrency: Arc::new(Semaphore::new(resolve_max_concurrent(
                user_server.max_concurrent,
            ))),
            pke_dk_bytes: user_server.pke_dk_bytes,
        };
        gateway.register_worker_handler(Arc::new(state)).await;
        wlog!(
            "network-node: registered worker request handler on {}",
            user_server.port
        );
    }

    let mut tasks = RuntimeTasks::default();
    let mut next_delay = Duration::from_secs(0);
    let mut last_pruned_stable_epoch: Option<u64> = None;
    let mut next_state = Some(startup_state);

    loop {
        let sleep = tokio::time::sleep(next_delay);
        tokio::pin!(sleep);
        tokio::select! {
            _ = &mut shutdown_rx => {
                wlog!("network-node: shutdown signal received.");
                tasks.stop_all();
                return Ok(());
            }
            _ = &mut sleep => {}
        }

        let state = if let Some(state) = next_state.take() {
            state
        } else {
            match fetch_state_view_v1(&config.rpc, &config.ace).await {
                Ok(s) => s,
                Err(e) => {
                    wlog!("network-node: fetch state view error: {:#}", e);
                    next_delay = Duration::from_secs(5);
                    continue;
                }
            }
        };

        let now_micros = unix_time_micros();
        let cur_node_idx = committee_index(&state.cur_nodes, &config.account_addr);
        let network_needs_progress = network_needs_progress(&state, now_micros);

        if config.capabilities.can_touch
            && cur_node_idx
                .map(|idx| should_submit_rotating_touch(idx, state.cur_nodes.len()))
                .unwrap_or(false)
            && network_needs_progress
        {
            if let Some((sk, vk)) = &touch_keys {
                if let Err(e) = config
                    .rpc
                    .submit_txn(
                        sk,
                        vk,
                        &config.account_addr,
                        &format!("{}::network::touch", config.ace),
                        &[],
                        &[],
                    )
                    .await
                {
                    wlog!("network-node: network::touch error: {:#}", e);
                }
            }
        }

        reconcile_epoch_change_clients(
            &mut tasks,
            config.capabilities,
            config.protocol.as_ref(),
            &state,
            &config,
        );

        if let Some(local) = local.as_ref() {
            let desired_epochs = desired_serving_epochs(&state, &config.account_addr, now_micros);
            if let Err(e) = reconcile_serving_cache(&config, local, desired_epochs).await {
                wlog!("network-node: serving cache sync error: {:#}", e);
            }
        }

        if reachability_vss_management_enabled
            && state.epoch_change_info.is_none()
            && last_pruned_stable_epoch != Some(state.epoch)
        {
            match prune_vss_store_to_live_sessions(&config, &state.live_vss_sessions) {
                Ok(deleted) => {
                    last_pruned_stable_epoch = Some(state.epoch);
                    if deleted > 0 {
                        wlog!(
                            "network-node: pruned {} stale VSS store row(s) at stable epoch {}",
                            deleted,
                            state.epoch
                        );
                    }
                }
                Err(e) => wlog!("network-node: VSS store prune error: {:#}", e),
            }
        }

        next_delay = if network_needs_progress {
            Duration::from_secs(1)
        } else {
            Duration::from_secs(5)
        };
    }
}

fn configure_vss_store_schema(
    config: &NetworkSupervisorConfig,
    reachability_vss_management_enabled: bool,
) -> Result<()> {
    if reachability_vss_management_enabled {
        config.store.use_reachability_based_schema()
    } else {
        config.store.use_legacy_epoch_schema()
    }
}

fn unix_time_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

fn network_needs_progress(state: &BcsStateView, now_micros: u64) -> bool {
    let epoch_timed_out = now_micros
        >= state
            .epoch_start_time_micros
            .saturating_add(state.epoch_duration_micros);
    let has_approved_proposal = state
        .proposals
        .iter()
        .any(|p| p.as_ref().is_some_and(|pv| pv.voting_passed));
    state.epoch_change_info.is_some() || epoch_timed_out || has_approved_proposal
}

fn committee_index(nodes: &[[u8; 32]], account_addr: &str) -> Option<usize> {
    nodes
        .iter()
        .position(|node| addr_bytes_to_string(node) == account_addr)
}

fn desired_serving_epochs(
    state: &BcsStateView,
    account_addr: &str,
    now_micros: u64,
) -> Vec<ServingEpoch> {
    let mut epochs = Vec::new();

    if let Some(idx) = committee_index(&state.cur_nodes, account_addr) {
        epochs.push(ServingEpoch {
            epoch: state.epoch,
            eval_point: (idx + 1) as u64,
            secrets: state.secrets.clone(),
        });
    }

    if let Some(previous) = &state.previous_epoch_info {
        let in_grace = now_micros
            < state
                .epoch_start_time_micros
                .saturating_add(PREVIOUS_EPOCH_GRACE_MICROS);
        if in_grace && state.epoch > 0 {
            if let Some(idx) = committee_index(&previous.nodes, account_addr) {
                epochs.push(ServingEpoch {
                    epoch: state.epoch - 1,
                    eval_point: (idx + 1) as u64,
                    secrets: previous.secrets.clone(),
                });
            }
        }
    }

    epochs
}

async fn reconcile_serving_cache(
    config: &NetworkSupervisorConfig,
    local: &LocalSecrets,
    desired_epochs: Vec<ServingEpoch>,
) -> Result<()> {
    let mut refreshed = ShareMap::new();
    for epoch in desired_epochs {
        for secret in epoch.secrets {
            let session_addr = addr_bytes_to_string(&secret.current_session);
            let reconstructed = reconstruct_share_from_store(
                &config.rpc,
                &config.ace,
                &session_addr,
                &config.account_addr,
                config.store.as_ref(),
            )
            .await?;
            let keypair_id = reconstructed.keypair_id.clone();
            refreshed.insert(
                (keypair_id, epoch.epoch),
                ShareEntry {
                    scalar_le32: reconstructed.scalar_le32,
                    blinding_le32: reconstructed.blinding_le32,
                    group_scheme: reconstructed.group_scheme,
                    pcs_context: reconstructed.pcs_context,
                    share_commitment: reconstructed.share_commitment,
                    expected_usage: secret.expected_usage,
                    eval_point: epoch.eval_point,
                    note: secret.note,
                },
            );
        }
    }

    local.replace_all(refreshed).await;
    Ok(())
}

fn prune_vss_store_to_live_sessions(
    config: &NetworkSupervisorConfig,
    live_vss_sessions: &[[u8; 32]],
) -> Result<usize> {
    let mut keep_sessions: Vec<String> =
        live_vss_sessions.iter().map(addr_bytes_to_string).collect();
    keep_sessions.sort();
    config.store.prune_except_sessions(&keep_sessions)
}

fn reconcile_epoch_change_clients(
    tasks: &mut RuntimeTasks,
    capabilities: RuntimeCapabilities,
    protocol: Option<&ProtocolRuntimeConfig>,
    state: &BcsStateView,
    config: &NetworkSupervisorConfig,
) {
    if !capabilities.can_drive_protocol {
        tasks.stop_all();
        return;
    }
    let Some(protocol) = protocol else {
        tasks.stop_all();
        return;
    };

    match &state.epoch_change_info {
        Some(info) => {
            let session = addr_bytes_to_string(&info.session_addr);
            let in_cur_nodes = committee_index(&state.cur_nodes, &config.account_addr).is_some();
            if in_cur_nodes {
                ensure_epoch_change_cur(tasks, protocol, config, &session);
            } else {
                stop_tasks(&mut tasks.epoch_change_cur);
            }

            let in_nxt_nodes = committee_index(&info.nxt_nodes, &config.account_addr).is_some();
            if in_nxt_nodes {
                ensure_epoch_change_nxt(tasks, protocol, config, &session);
            } else {
                stop_tasks(&mut tasks.epoch_change_nxt);
            }
        }
        None => tasks.stop_all(),
    }
}

fn ensure_epoch_change_cur(
    tasks: &mut RuntimeTasks,
    protocol: &ProtocolRuntimeConfig,
    config: &NetworkSupervisorConfig,
    session: &str,
) {
    if tasks.epoch_change_cur.contains_key(session) {
        return;
    }
    let (tx, rx) = oneshot::channel::<()>();
    tasks.epoch_change_cur.insert(session.to_string(), tx);
    let cfg = epoch_change_cur::RunConfig {
        rpc_url: protocol.rpc_url.clone(),
        rpc_api_key: protocol.rpc_api_key.clone(),
        rpc_gas_key: protocol.rpc_gas_key.clone(),
        ace_contract: config.ace.clone(),
        epoch_change_session: session.to_string(),
        account_addr: config.account_addr.clone(),
        account_sk_hex: protocol.account_sk_hex.clone(),
        pke_dk_hex: protocol.pke_dk_hex.clone(),
        sig_sk_hex: protocol.sig_sk_hex.clone(),
        vss_store_url: protocol.vss_store_url.clone(),
        node_msg_listen: protocol.node_msg_listen.clone(),
    };
    tokio::spawn(async move {
        if let Err(e) = epoch_change_cur::run(cfg, rx).await {
            wlog!("network-node: epoch-change-cur error: {:#}", e);
        }
    });
    wlog!(
        "network-node: started epoch-change-cur for session={}",
        session
    );
}

fn ensure_epoch_change_nxt(
    tasks: &mut RuntimeTasks,
    protocol: &ProtocolRuntimeConfig,
    config: &NetworkSupervisorConfig,
    session: &str,
) {
    if tasks.epoch_change_nxt.contains_key(session) {
        return;
    }
    let (tx, rx) = oneshot::channel::<()>();
    tasks.epoch_change_nxt.insert(session.to_string(), tx);
    let cfg = epoch_change_nxt::RunConfig {
        rpc_url: protocol.rpc_url.clone(),
        rpc_api_key: protocol.rpc_api_key.clone(),
        rpc_gas_key: protocol.rpc_gas_key.clone(),
        ace_contract: config.ace.clone(),
        epoch_change_session: session.to_string(),
        account_addr: config.account_addr.clone(),
        account_sk_hex: protocol.account_sk_hex.clone(),
        pke_dk_hex: protocol.pke_dk_hex.clone(),
        sig_sk_hex: protocol.sig_sk_hex.clone(),
        vss_store_url: protocol.vss_store_url.clone(),
        node_msg_listen: protocol.node_msg_listen.clone(),
    };
    tokio::spawn(async move {
        if let Err(e) = epoch_change_nxt::run(cfg, rx).await {
            wlog!("network-node: epoch-change-nxt error: {:#}", e);
        }
    });
    wlog!(
        "network-node: started epoch-change-nxt for session={}",
        session
    );
}

async fn run_with_config(mut config: RunConfig, shutdown_rx: oneshot::Receiver<()>) -> Result<()> {
    require_config_field("ace_deployment_addr", &config.ace_deployment_addr)?;
    require_config_field("account_addr", &config.account_addr)?;
    require_config_field("pke_dk", &config.pke_dk)?;
    require_config_field("vss_store_url", &config.vss_store_url)?;
    let port = config
        .port
        .ok_or_else(|| anyhow!("network-node requires --port"))?;
    let node_listen = format!("0.0.0.0:{port}");

    let drive_protocol = matches!(config.mode, RuntimeMode::Monolith | RuntimeMode::Maintainer);
    let serve_requests = match config.mode {
        RuntimeMode::Monolith => true,
        RuntimeMode::Maintainer => false,
        RuntimeMode::Handler => true,
    };
    let capabilities = RuntimeCapabilities {
        can_serve: serve_requests,
        can_drive_protocol: drive_protocol,
        can_touch: drive_protocol,
    };

    if drive_protocol {
        require_config_field("account_sk_hex", &config.account_sk_hex)?;
        require_config_field("sig_sk_hex", &config.sig_sk_hex)?;
    }

    let user_server = if serve_requests {
        Some(UserServerConfig {
            port,
            chain_rpc: config
                .chain_rpc
                .take()
                .ok_or_else(|| anyhow!("serving mode requires chain_rpc"))?,
            max_concurrent: config.max_concurrent,
            pke_dk_bytes: decode_pke_dk(&config.pke_dk)?,
        })
    } else {
        None
    };

    let rpc = if drive_protocol {
        AptosRpc::new_with_gas_key(
            config.ace_deployment_api.clone(),
            config.ace_deployment_apikey.clone(),
            config.ace_deployment_gaskey.clone(),
        )
    } else {
        AptosRpc::new_with_key(
            config.ace_deployment_api.clone(),
            config.ace_deployment_apikey.clone(),
        )
    };
    let ace = normalize_account_addr(&config.ace_deployment_addr);
    let account_addr = normalize_account_addr(&config.account_addr);
    let store = connect_vss_store(&config.vss_store_url)?;
    let mode_label = match config.mode {
        RuntimeMode::Monolith => "monolith",
        RuntimeMode::Maintainer => "maintainer-only",
        RuntimeMode::Handler => "handler-only",
    };
    let protocol = if drive_protocol {
        Some(ProtocolRuntimeConfig {
            rpc_url: config.ace_deployment_api,
            rpc_api_key: config.ace_deployment_apikey,
            rpc_gas_key: config.ace_deployment_gaskey,
            account_sk_hex: config.account_sk_hex,
            pke_dk_hex: config.pke_dk,
            sig_sk_hex: config.sig_sk_hex,
            vss_store_url: config.vss_store_url,
            node_msg_listen: node_listen.clone(),
        })
    } else {
        None
    };

    run_supervisor(
        NetworkSupervisorConfig {
            mode_label,
            rpc,
            ace,
            account_addr,
            node_listen,
            store,
            capabilities,
            protocol,
            user_server,
        },
        shutdown_rx,
    )
    .await
}

fn require_config_field(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        Err(anyhow!(
            "missing required network-node config field {label}"
        ))
    } else {
        Ok(())
    }
}

fn decode_pke_dk(pke_dk: &str) -> Result<Arc<Vec<u8>>> {
    let raw = pke_dk.trim().trim_start_matches("0x");
    Ok(Arc::new(
        hex::decode(raw).map_err(|e| anyhow::anyhow!("pke_dk decode: {}", e))?,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::onchain::{BcsEpochSnapshot, BcsNetworkFeatureConfigs};

    fn addr(byte: u8) -> [u8; 32] {
        [byte; 32]
    }

    fn secret(session_byte: u8, keypair_byte: u8) -> BcsSecretInfo {
        BcsSecretInfo {
            current_session: addr(session_byte),
            keypair_id: addr(keypair_byte),
            scheme: 1,
            expected_usage: crate::secret_usage::USAGE_BLS12381_THRESHOLD_VRF,
            note: format!("secret-{session_byte}"),
        }
    }

    fn state_with_previous(
        current_nodes: Vec<[u8; 32]>,
        previous_nodes: Vec<[u8; 32]>,
    ) -> BcsStateView {
        BcsStateView {
            epoch: 7,
            epoch_start_time_micros: 1_000_000,
            epoch_duration_micros: 90_000_000,
            cur_nodes: current_nodes,
            cur_threshold: 2,
            secrets: vec![secret(0x10, 0x20)],
            previous_epoch_info: Some(BcsEpochSnapshot {
                nodes: previous_nodes,
                secrets: vec![secret(0x11, 0x21)],
            }),
            proposals: vec![],
            epoch_change_info: None,
            feature_configs: BcsNetworkFeatureConfigs::default(),
            live_vss_sessions: vec![],
        }
    }

    #[test]
    fn desired_serving_epochs_includes_current_committee_membership() {
        let me = addr(1);
        let state = state_with_previous(vec![addr(9), me], vec![addr(8)]);
        let desired = desired_serving_epochs(
            &state,
            &addr_bytes_to_string(&me),
            state.epoch_start_time_micros,
        );

        assert_eq!(desired.len(), 1);
        assert_eq!(desired[0].epoch, 7);
        assert_eq!(desired[0].eval_point, 2);
        assert_eq!(desired[0].secrets[0].current_session, addr(0x10));
    }

    #[test]
    fn desired_serving_epochs_keeps_previous_only_inside_grace_window() {
        let me = addr(1);
        let state = state_with_previous(vec![addr(9)], vec![addr(8), me]);
        let in_grace = desired_serving_epochs(
            &state,
            &addr_bytes_to_string(&me),
            state.epoch_start_time_micros + PREVIOUS_EPOCH_GRACE_MICROS - 1,
        );
        assert_eq!(in_grace.len(), 1);
        assert_eq!(in_grace[0].epoch, 6);
        assert_eq!(in_grace[0].eval_point, 2);
        assert_eq!(in_grace[0].secrets[0].current_session, addr(0x11));

        let after_grace = desired_serving_epochs(
            &state,
            &addr_bytes_to_string(&me),
            state.epoch_start_time_micros + PREVIOUS_EPOCH_GRACE_MICROS,
        );
        assert!(after_grace.is_empty());
    }
}
