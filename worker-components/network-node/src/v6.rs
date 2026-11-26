// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! V6 network supervisor. Each epoch protocol has its own CLI instance. During
//! a transition, the old HANDOFF and new INIT instances run concurrently and
//! invoke the two sides of the same lower-level epoch-change protocol.

use std::collections::{HashMap, HashSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use epoch_worker::{EpochSession, Phase, ShareEvent};
use serde::Deserialize;
use serde_json::Value;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use vss_common::{
    normalize_account_addr, parse_ed25519_signing_key_hex, should_submit_rotating_touch, AptosRpc,
};

use crate::secrets::{LocalSecrets, ShareEntry};
use crate::MaintainerConfig;

#[derive(Deserialize)]
pub(crate) struct StateViewV1 {
    active_epoch_addr: Option<[u8; 32]>,
    initializing_epoch_addr: Option<[u8; 32]>,
    grace_epoch_addr: Option<[u8; 32]>,
    transition_addr: Option<[u8; 32]>,
    active_epoch_bcs: Option<Vec<u8>>,
    initializing_epoch_bcs: Option<Vec<u8>>,
    grace_epoch_bcs: Option<Vec<u8>>,
}

fn address_hex(address: &[u8; 32]) -> String {
    format!("0x{}", hex::encode(address))
}

fn now_micros() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_micros() as u64
}

pub(crate) async fn fetch_state(rpc: &AptosRpc, ace: &str) -> Result<StateViewV1> {
    let result = rpc
        .call_view(&format!("{ace}::network::state_view_v1_bcs"), &[])
        .await?;
    let hex = result
        .first()
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("state_view_v1_bcs returned no BCS bytes"))?;
    bcs::from_bytes(&hex::decode(hex.trim_start_matches("0x"))?)
        .context("decode network::StateViewV1")
}

struct EpochView {
    address: String,
    session: EpochSession,
}

fn decode_epoch(
    address: Option<[u8; 32]>,
    bytes: Option<Vec<u8>>,
    expected: Phase,
) -> Result<Option<EpochView>> {
    match (address, bytes) {
        (None, None) => Ok(None),
        (Some(address), Some(bytes)) => {
            let session: EpochSession =
                bcs::from_bytes(&bytes).context("decode epoch::Session in StateViewV1")?;
            let phase = session.phase()?;
            let valid = match expected {
                Phase::Serving => phase == Phase::Serving || phase == Phase::Handoff,
                _ => phase == expected,
            };
            if !valid {
                bail!(
                    "epoch {} has phase {:?}, expected {:?}",
                    session.epoch,
                    phase,
                    expected
                );
            }
            Ok(Some(EpochView {
                address: address_hex(&address),
                session,
            }))
        }
        _ => bail!("StateViewV1 epoch address and BCS blob disagree"),
    }
}

struct Epochs {
    active: Option<EpochView>,
    initializing: Option<EpochView>,
    grace: Option<EpochView>,
}

impl StateViewV1 {
    fn decode(self) -> Result<Epochs> {
        let transition = self.transition_addr;
        let active = decode_epoch(
            self.active_epoch_addr,
            self.active_epoch_bcs,
            Phase::Serving,
        )?;
        let initializing = decode_epoch(
            self.initializing_epoch_addr,
            self.initializing_epoch_bcs,
            Phase::Init,
        )?;
        let grace = decode_epoch(self.grace_epoch_addr, self.grace_epoch_bcs, Phase::Grace)?;
        if initializing.is_some() && grace.is_some() {
            bail!("StateViewV1 contains both INIT and GRACE successors");
        }
        if grace.is_some() && active.is_none() {
            bail!("StateViewV1 has GRACE without a serving epoch");
        }
        let addresses: Vec<&str> = [&active, &initializing, &grace]
            .into_iter()
            .filter_map(|view| view.as_ref().map(|e| e.address.as_str()))
            .collect();
        if addresses.iter().copied().collect::<HashSet<_>>().len() != addresses.len() {
            bail!("StateViewV1 repeats an epoch session address");
        }
        match (&active, &initializing, &grace) {
            (None, Some(next), None)
                if next.session.epoch == 0 && next.session.inbound_transition == transition => {}
            (Some(old), Some(next), None)
                if old.session.phase()? == Phase::Handoff
                    && old.session.epoch.checked_add(1) == Some(next.session.epoch)
                    && old.session.outbound_transition == transition
                    && next.session.inbound_transition == transition => {}
            (Some(next), None, Some(old))
                if next.session.phase()? == Phase::Serving
                    && old.session.epoch.checked_add(1) == Some(next.session.epoch)
                    && old.session.outbound_transition == next.session.inbound_transition
                    && transition.is_none() => {}
            (Some(current), None, None)
                if current.session.phase()? == Phase::Serving && transition.is_none() => {}
            _ => bail!("StateViewV1 contains inconsistent epoch/transition pointers"),
        }
        Ok(Epochs {
            active,
            initializing,
            grace,
        })
    }
}

struct RunningEpoch {
    epoch: u64,
    stop: oneshot::Sender<()>,
    task: JoinHandle<Result<()>>,
}

async fn receive_shares(mut rx: mpsc::Receiver<ShareEvent>, local: LocalSecrets) {
    while let Some(event) = rx.recv().await {
        match event {
            ShareEvent::Install { batch, installed } => {
                if batch.shares.iter().any(|share| share.epoch != batch.epoch) {
                    crate::wlog!(
                        "network-node: rejected inconsistent share batch for epoch={}",
                        batch.epoch
                    );
                    continue;
                }
                let mut entries = local.shares.write().await;
                entries.retain(|(_, epoch), _| *epoch != batch.epoch);
                let count = batch.shares.len();
                for share in batch.shares {
                    entries.insert(
                        (share.keypair_id, share.epoch),
                        ShareEntry {
                            scalar_le32: share.scalar_le32,
                            group_scheme: share.group_scheme,
                            expected_usage: share.expected_usage,
                            eval_point: share.eval_point,
                            note: share.note,
                        },
                    );
                }
                drop(entries);
                crate::wlog!(
                    "network-node: installed {} shares for epoch={} session={} features={:#x}",
                    count,
                    batch.epoch,
                    batch.epoch_session,
                    batch.features
                );
                let _ = installed.send(());
            }
            ShareEvent::Phase {
                epoch,
                phase,
                grace_until_micros,
            } => {
                let mut visibility = local.visible_epochs.write().await;
                let visible = visibility.get_or_insert_with(HashMap::new);
                match phase {
                    Phase::Init | Phase::Finished => {
                        visible.remove(&epoch);
                    }
                    Phase::Serving | Phase::Handoff => {
                        visible.insert(epoch, None);
                    }
                    Phase::Grace => {
                        visible.insert(epoch, Some(grace_until_micros));
                    }
                }
                crate::wlog!(
                    "network-node: epoch={} phase={:?} grace_until={}",
                    epoch,
                    phase,
                    grace_until_micros
                );
            }
            ShareEvent::Retire { epoch } => {
                if let Some(visibility) = local.visible_epochs.write().await.as_mut() {
                    visibility.remove(&epoch);
                }
                local
                    .shares
                    .write()
                    .await
                    .retain(|(_, entry_epoch), _| *entry_epoch != epoch);
                crate::wlog!("network-node: retired epoch={}", epoch);
            }
        }
    }
}

fn should_touch(epochs: &Epochs, account: &[u8; 32]) -> bool {
    let now = now_micros();
    let (needed, committee): (bool, &[[u8; 32]]) = if let Some(next) = &epochs.initializing {
        let ready = next
            .session
            .ready_nodes
            .iter()
            .filter(|ready| **ready)
            .count() as u64;
        (ready >= next.session.threshold, &next.session.nodes)
    } else if let Some(old) = &epochs.grace {
        (
            now >= old.session.grace_until_micros,
            &epochs
                .active
                .as_ref()
                .expect("grace has active epoch")
                .session
                .nodes,
        )
    } else if let Some(active) = &epochs.active {
        (
            now >= active
                .session
                .serving_since_micros
                .saturating_add(active.session.epoch_duration_micros),
            &active.session.nodes,
        )
    } else {
        (false, &[][..])
    };
    needed
        && committee
            .iter()
            .position(|node| node == account)
            .is_some_and(|index| should_submit_rotating_touch(index, committee.len()))
}

pub(crate) async fn run(
    config: MaintainerConfig,
    local: LocalSecrets,
    initial: StateViewV1,
    mut shutdown_rx: oneshot::Receiver<()>,
) -> Result<()> {
    let rpc = AptosRpc::new_with_gas_key(
        config.ace_deployment_api.clone(),
        config.ace_deployment_apikey.clone(),
        config.ace_deployment_gaskey.clone(),
    );
    let sk = parse_ed25519_signing_key_hex(&config.account_sk_hex)?;
    let vk = sk.verifying_key();
    let account_addr = normalize_account_addr(&config.account_addr);
    let account: [u8; 32] = hex::decode(account_addr.trim_start_matches("0x"))?
        .try_into()
        .map_err(|_| anyhow!("worker account address is not 32 bytes"))?;
    let ace = normalize_account_addr(&config.ace_deployment_addr);

    *local.visible_epochs.write().await = Some(HashMap::new());
    local.shares.write().await.clear();
    let (share_tx, share_rx) = mpsc::channel(32);
    tokio::spawn(receive_shares(share_rx, local.clone()));
    let mut running: HashMap<String, RunningEpoch> = HashMap::new();
    let mut interval = tokio::time::interval(Duration::from_secs(1));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut first = Some(initial);

    loop {
        tokio::select! {
            _ = &mut shutdown_rx => {
                for (_, task) in running.drain() { let _ = task.stop.send(()); }
                return Ok(());
            },
            _ = interval.tick() => {},
        }
        let state = match first.take() {
            Some(state) => state,
            None => match fetch_state(&rpc, &ace).await {
                Ok(state) => state,
                Err(error) => {
                    crate::wlog!("network-node: v6 state fetch error: {error:#}");
                    continue;
                }
            },
        };
        let epochs = match state.decode() {
            Ok(epochs) => epochs,
            Err(error) => {
                crate::wlog!("network-node: invalid v6 epoch state: {error:#}");
                continue;
            }
        };
        if should_touch(&epochs, &account) {
            if let Err(error) = rpc
                .submit_txn(
                    &sk,
                    &vk,
                    &account_addr,
                    &format!("{ace}::network::touch"),
                    &[],
                    &[],
                )
                .await
            {
                crate::wlog!("network-node: v6 network::touch failed: {error:#}");
            }
        }

        let desired: HashMap<String, u64> = [&epochs.active, &epochs.initializing, &epochs.grace]
            .into_iter()
            .filter_map(|view| view.as_ref())
            .filter(|view| view.session.nodes.contains(&account))
            .map(|view| (view.address.clone(), view.session.epoch))
            .collect();

        let stale: Vec<String> = running
            .keys()
            .filter(|address| !desired.contains_key(*address))
            .cloned()
            .collect();
        for address in stale {
            if let Some(mut task) = running.remove(&address) {
                let _ = task.stop.send(());
                if tokio::time::timeout(Duration::from_secs(12), &mut task.task)
                    .await
                    .is_err()
                {
                    task.task.abort();
                    let _ = task.task.await;
                }
                let _ = share_tx
                    .send(ShareEvent::Retire { epoch: task.epoch })
                    .await;
            }
        }
        for (address, epoch) in desired {
            if let Some(task) = running.get(&address) {
                if !task.task.is_finished() {
                    continue;
                }
            }
            if let Some(done) = running.remove(&address) {
                match done.task.await {
                    Ok(Ok(())) => crate::wlog!("network-node: epoch worker {} exited", address),
                    Ok(Err(error)) => {
                        crate::wlog!("network-node: epoch worker {} failed: {error:#}", address)
                    }
                    Err(error) => crate::wlog!(
                        "network-node: epoch worker {} task ended: {error:#}",
                        address
                    ),
                }
            }
            let (stop, stopped) = oneshot::channel();
            let worker_config = epoch_worker::RunConfig {
                rpc_url: config.ace_deployment_api.clone(),
                rpc_api_key: config.ace_deployment_apikey.clone(),
                rpc_gas_key: config.ace_deployment_gaskey.clone(),
                ace_contract: ace.clone(),
                epoch_session: address.clone(),
                expected_epoch: Some(epoch),
                account_addr: account_addr.clone(),
                account_sk_hex: config.account_sk_hex.clone(),
                pke_dk_hex: config.pke_dk.clone(),
                share_sink: Some(share_tx.clone()),
            };
            let task = tokio::spawn(epoch_worker::run(worker_config, stopped));
            crate::wlog!(
                "network-node: started epoch worker epoch={} session={}",
                epoch,
                address
            );
            running.insert(address, RunningEpoch { epoch, stop, task });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn init_share_is_hidden_until_serving_and_grace_expires() {
        let local = LocalSecrets {
            shares: Arc::new(RwLock::new(HashMap::new())),
            visible_epochs: Arc::new(RwLock::new(Some(HashMap::new()))),
        };
        let (tx, rx) = mpsc::channel(8);
        let receiver = tokio::spawn(receive_shares(rx, local.clone()));
        let (installed, confirmed) = oneshot::channel();
        tx.send(ShareEvent::Install {
            batch: epoch_worker::ShareBatch {
                epoch: 6,
                epoch_session: "0x6".into(),
                features: 0,
                shares: vec![epoch_worker::PreloadedShare {
                    keypair_id: "0xabc".into(),
                    epoch: 6,
                    secret_session: "0xdef".into(),
                    scalar_le32: [7; 32],
                    group_scheme: 1,
                    expected_usage: 1,
                    eval_point: 2,
                    note: String::new(),
                }],
            },
            installed,
        })
        .await
        .unwrap();
        confirmed.await.unwrap();
        assert!(local.snapshot().await.entries.is_empty());
        assert!(
            matches!(local.snapshot_wire().await, crate::secrets::SecretsSnapshotWire::V1 { shares } if shares.is_empty())
        );

        tx.send(ShareEvent::Phase {
            epoch: 6,
            phase: Phase::Serving,
            grace_until_micros: 0,
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if !local.snapshot().await.entries.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(local.snapshot().await.lookup("0xabc", 6).is_some());

        tx.send(ShareEvent::Phase {
            epoch: 6,
            phase: Phase::Grace,
            grace_until_micros: now_micros() - 1,
        })
        .await
        .unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if local.snapshot().await.entries.is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        assert!(
            matches!(local.snapshot_wire().await, crate::secrets::SecretsSnapshotWire::V1 { shares } if shares.is_empty())
        );
        drop(tx);
        receiver.await.unwrap();
    }
}
