// DKG and epoch change processing (Synchronous VSS)
//
// Protocol for a DKG round:
//   1. Every committee member acts as a dealer.
//   2. Each dealer generates a degree-(T-1) polynomial and sends the share f(j)
//      to each peer j via HTTP POST /deal_share.  Peers verify and accumulate.
//   3. After Δ = 5 s, each dealer posts its partial MPK contribution on-chain:
//      [0x02][G1_compressed_48_bytes] = 49 bytes.
//   4. The contract aggregates partial MPKs; once all n committee members have
//      contributed, it finalises the DKG and stores the SecretInfo.
//   5. Workers read their accumulated share (sum of received shares) from the
//      in-memory DkgShareAccum and persist it in the ShareStore.

use anyhow::Result;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::{
    aptos_rpc::AptosRpc,
    store::{KeyShare, ShareStore},
    vss::{self, DealMsg, Polynomial, ReshareMsg, G1_GENERATOR_BYTES},
    DkgShareAccum, ReshareAccum,
};

// ── Registration ──────────────────────────────────────────────────────────────

/// Register node endpoint on-chain (idempotent: catches errors silently)
pub async fn ensure_registered(
    rpc: &AptosRpc,
    signing_key: &ed25519_dalek::SigningKey,
    verifying_key: &ed25519_dalek::VerifyingKey,
    contract_addr: &str,
    endpoint: &str,
) -> Result<()> {
    let my_addr = format!("0x{}", hex::encode(crate::compute_address(verifying_key)));

    let already = rpc
        .view(
            &format!("{}::ace_network::get_node_endpoint", contract_addr),
            &[],
            &[json!(contract_addr), json!(my_addr)],
        )
        .await;
    if already.is_ok() {
        info!("Node already registered.");
        return Ok(());
    }

    info!("Registering node with endpoint={}", endpoint);
    rpc.submit_txn(
        signing_key,
        verifying_key,
        &my_addr,
        &format!("{}::ace_network::register_node", contract_addr),
        &[],
        &[json!(endpoint)],
    )
    .await?;
    info!("Node registered.");
    Ok(())
}

// ── Main poll ─────────────────────────────────────────────────────────────────

pub async fn poll(
    rpc: &AptosRpc,
    signing_key: &ed25519_dalek::SigningKey,
    verifying_key: &ed25519_dalek::VerifyingKey,
    contract_addr: &str,
    my_address: &[u8; 32],
    store_path: &str,
    store: Arc<Mutex<ShareStore>>,
    accum: Arc<Mutex<DkgShareAccum>>,
    reshare_accum: Arc<Mutex<ReshareAccum>>,
) -> Result<()> {
    let my_addr_str = format!("0x{}", hex::encode(my_address));

    let epoch_result = rpc
        .view(
            &format!("{}::ace_network::get_current_epoch", contract_addr),
            &[],
            &[json!(contract_addr)],
        )
        .await;
    let (epoch_num, node_list, threshold) = match epoch_result {
        Err(e) => {
            warn!("[poller] get_current_epoch failed: {}", e);
            return Ok(());
        }
        Ok(vals) => {
            let epoch_num = vals
                .get(0)
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            let node_list: Vec<String> = vals
                .get(1)
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                        .collect()
                })
                .unwrap_or_default();
            let threshold = vals
                .get(2)
                .and_then(|v| v.as_str())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            (epoch_num, node_list, threshold)
        }
    };

    let my_addr_lower = my_addr_str.to_lowercase();
    // 1-based index in the OLD (current) committee; None if not a member.
    let my_old_index: Option<u64> = node_list
        .iter()
        .position(|n| n == &my_addr_lower)
        .map(|i| (i + 1) as u64);

    // DKG: only current committee members participate.
    if let Some(my_index) = my_old_index {
        if let Err(e) = process_dkg(
            rpc,
            signing_key,
            verifying_key,
            contract_addr,
            &my_addr_str,
            epoch_num,
            &node_list,
            threshold,
            my_index,
            store_path,
            Arc::clone(&store),
            Arc::clone(&accum),
        )
        .await
        {
            error!("[poller] DKG error: {}", e);
        }
    }

    // Epoch change: ALL workers call this.
    // Old members deal sub-shares; new-only members just accumulate and compute.
    if let Err(e) = process_epoch_change(
        rpc,
        signing_key,
        verifying_key,
        contract_addr,
        &my_addr_str,
        epoch_num,
        &node_list,
        threshold,
        my_old_index,
        Arc::clone(&store),
        Arc::clone(&reshare_accum),
    )
    .await
    {
        error!("[poller] epoch change error: {}", e);
    }

    Ok(())
}

// ── DKG ───────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn process_dkg(
    rpc: &AptosRpc,
    signing_key: &ed25519_dalek::SigningKey,
    verifying_key: &ed25519_dalek::VerifyingKey,
    contract_addr: &str,
    my_addr: &str,
    epoch_num: u64,
    nodes: &[String],
    threshold: u64,
    my_index: u64,
    store_path: &str,
    store: Arc<Mutex<ShareStore>>,
    accum: Arc<Mutex<DkgShareAccum>>,
) -> Result<()> {
    let pending = rpc
        .view(
            &format!("{}::ace_network::get_pending_dkg", contract_addr),
            &[],
            &[json!(contract_addr)],
        )
        .await?;

    let has_pending = pending.get(0).and_then(|v| v.as_bool()).unwrap_or(false);
    if !has_pending {
        return Ok(());
    }
    let dkg_id = pending
        .get(1)
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    // Secret count before DKG finalises — used to derive secret_id.
    let secret_count_before = get_secret_count(rpc, contract_addr).await?;

    // Check whether we already have a share for the upcoming secret_id.
    {
        let locked = store.lock().await;
        if locked.get(secret_count_before).is_some() {
            return Ok(());
        }
    }

    // Idempotency: have we already dealt for this dkg_id?
    {
        let locked = accum.lock().await;
        if locked.posted_dkg_ids.contains(&dkg_id) {
            // Already dealt; just check if DKG finalised so we can commit the share.
            drop(locked);
            try_commit_share(
                rpc,
                contract_addr,
                dkg_id,
                secret_count_before,
                epoch_num,
                store,
                accum,
            )
            .await;
            return Ok(());
        }
    }

    info!(
        "[DKG] dkg_id={} starting sync-VSS dealing (my_index={})",
        dkg_id, my_index
    );

    // Fetch peer endpoints from chain.
    let endpoints = fetch_endpoints(rpc, contract_addr, nodes).await?;

    // Generate degree-(T-1) polynomial.
    // Drop rng before any await points to keep the future Send.
    let degree = (threshold as usize).saturating_sub(1);
    let (poly, partial_mpk_bytes, own_share) = {
        let mut rng = rand::thread_rng();
        let poly = Polynomial::random(degree, &mut rng);
        let partial_mpk_bytes = vss::g1_to_bytes48(poly.partial_mpk());
        let own_share = poly.eval(my_index);
        (poly, partial_mpk_bytes, own_share)
    };
    {
        let mut locked = accum.lock().await;
        let entry = locked.shares.entry(dkg_id).or_insert(ark_bls12_381::Fr::from(0u64));
        *entry += own_share;
    }

    // Send shares to every other committee member.
    let http_client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()?;

    for (idx, endpoint) in endpoints.iter().enumerate() {
        let recipient_index = (idx + 1) as u64;
        if recipient_index == my_index || endpoint.is_empty() {
            continue;
        }
        let msg = DealMsg::build(dkg_id, my_index, &poly, recipient_index);
        let url = format!("{}/deal_share", endpoint.trim_end_matches('/'));
        match http_client.post(&url).json(&msg).send().await {
            Ok(resp) if resp.status().is_success() => {
                info!(
                    "[DKG] sent share to worker {} ({})",
                    recipient_index, endpoint
                );
            }
            Ok(resp) => {
                warn!(
                    "[DKG] worker {} rejected share: {}",
                    recipient_index,
                    resp.status()
                );
            }
            Err(e) => {
                warn!(
                    "[DKG] failed to reach worker {} ({}): {}",
                    recipient_index, endpoint, e
                );
            }
        }
    }

    // Wait Δ before posting partial MPK.
    info!(
        "[DKG] dkg_id={} waiting Δ=5s before posting partial MPK",
        dkg_id
    );
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    // Post partial contribution: [0x02][mpk_i_48]
    let mut contribution = vec![0x02u8];
    contribution.extend_from_slice(&partial_mpk_bytes);
    info!("[DKG] dkg_id={} posting partial MPK on-chain", dkg_id);
    rpc.submit_txn(
        signing_key,
        verifying_key,
        my_addr,
        &format!("{}::ace_network::contribute_to_dkg", contract_addr),
        &[],
        &[
            json!(dkg_id.to_string()),
            json!(format!("0x{}", hex::encode(&contribution))),
        ],
    )
    .await?;

    // Mark as posted.
    {
        let mut locked = accum.lock().await;
        locked.posted_dkg_ids.insert(dkg_id);
    }

    // Wait for the DKG to finalise on-chain and commit the share.
    try_commit_share(
        rpc,
        contract_addr,
        dkg_id,
        secret_count_before,
        epoch_num,
        store,
        accum,
    )
    .await;

    let _ = store_path;
    Ok(())
}

/// Poll until DKG finalises, then commit the accumulated share to the store.
async fn try_commit_share(
    rpc: &AptosRpc,
    contract_addr: &str,
    dkg_id: u64,
    secret_count_before: u64,
    epoch_num: u64,
    store: Arc<Mutex<ShareStore>>,
    accum: Arc<Mutex<DkgShareAccum>>,
) {
    let secret_id = secret_count_before;

    {
        let locked = store.lock().await;
        if locked.get(secret_id).is_some() {
            return;
        }
    }

    let mut finalised = false;
    for _ in 0..30 {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        if let Ok(count) = get_secret_count(rpc, contract_addr).await {
            if count > secret_count_before {
                finalised = true;
                break;
            }
        }
    }

    if !finalised {
        warn!("[DKG] timeout waiting for DKG finalisation (dkg_id={})", dkg_id);
        return;
    }

    let share_fr = {
        let locked = accum.lock().await;
        locked.shares.get(&dkg_id).copied().unwrap_or(ark_bls12_381::Fr::from(0u64))
    };

    let scalar_hex = hex::encode(vss::fr_to_le32(share_fr));
    let base_hex = hex::encode(G1_GENERATOR_BYTES);

    {
        let mut locked = store.lock().await;
        if locked.get(secret_id).is_none() {
            locked.insert(
                secret_id,
                KeyShare {
                    scalar_share_hex: scalar_hex,
                    base_hex,
                    acquired_at_epoch: epoch_num,
                },
            );
            info!(
                "[DKG] share committed: secret_id={} epoch={}",
                secret_id, epoch_num
            );
        }
    }
}

// ── Epoch change (real DKR) ───────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn process_epoch_change(
    rpc: &AptosRpc,
    signing_key: &ed25519_dalek::SigningKey,
    verifying_key: &ed25519_dalek::VerifyingKey,
    contract_addr: &str,
    my_addr: &str,
    epoch_num: u64,
    old_nodes: &[String],   // current (old) committee node list
    old_threshold: u64,
    my_old_index: Option<u64>, // 1-based index in old committee, None if not a member
    store: Arc<Mutex<ShareStore>>,
    reshare_accum: Arc<Mutex<ReshareAccum>>,
) -> Result<()> {
    // 1. Check for a pending EpochChangeRecord (DKR in progress).
    let pending = rpc
        .view(
            &format!("{}::ace_network::get_pending_epoch_change", contract_addr),
            &[],
            &[json!(contract_addr)],
        )
        .await?;
    let has_pending = pending.get(0).and_then(|v| v.as_bool()).unwrap_or(false);
    if !has_pending {
        return Ok(());
    }
    let epoch_change_id = pending
        .get(1)
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);

    // 2. Fetch the list of secrets being reshared.
    let secret_ids: Vec<u64> = {
        let r = rpc
            .view(
                &format!("{}::ace_network::get_pending_resharing_secret_ids", contract_addr),
                &[],
                &[json!(contract_addr), json!(epoch_change_id.to_string())],
            )
            .await?;
        r.get(0)
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().and_then(|s| s.parse().ok())).collect())
            .unwrap_or_default()
    };

    // Save active resharing info for later new-member share computation.
    {
        let mut locked = reshare_accum.lock().await;
        if locked.active_resharing.as_ref().map(|(id, _)| *id) != Some(epoch_change_id) {
            locked.active_resharing = Some((epoch_change_id, secret_ids.clone()));
        }
    }

    // 3. Fetch new committee details.
    let (new_nodes, new_threshold) = {
        let r = rpc
            .view(
                &format!("{}::ace_network::get_epoch_change_details", contract_addr),
                &[],
                &[json!(contract_addr), json!(epoch_change_id.to_string())],
            )
            .await?;
        let nodes: Vec<String> = r
            .get(0)
            .and_then(|v| v.as_array())
            .map(|a| a.iter().filter_map(|v| v.as_str().map(|s| s.to_lowercase())).collect())
            .unwrap_or_default();
        let threshold = r
            .get(1)
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        (nodes, threshold)
    };

    let my_addr_lower = my_addr.to_lowercase();

    // 4. Old-member dealing: re-deal each secret to the new committee.
    if let Some(my_old_idx) = my_old_index {
        let already_posted = reshare_accum.lock().await.posted_epoch_change_ids.contains(&epoch_change_id);
        if !already_posted && !secret_ids.is_empty() {
            let new_endpoints = fetch_endpoints(rpc, contract_addr, &new_nodes).await?;
            let http_client = reqwest::Client::builder()
                .timeout(std::time::Duration::from_secs(5))
                .build()?;

            for &secret_id in &secret_ids {
                // Load our current share for this secret.
                let share_scalar = {
                    let locked = store.lock().await;
                    match locked.get(secret_id) {
                        Some(row) => match hex::decode(&row.scalar_share_hex) {
                            Ok(b) if b.len() == 32 => vss::fr_from_le32(&b),
                            _ => {
                                warn!("[EpochChange] invalid stored share for secret_id={}", secret_id);
                                continue;
                            }
                        },
                        None => {
                            warn!("[EpochChange] no share for secret_id={}, skipping", secret_id);
                            continue;
                        }
                    }
                };

                // Generate degree-(t_new-1) polynomial with constant term = our share.
                let degree = (new_threshold as usize).saturating_sub(1);
                let (poly, commitment_bytes) = {
                    let mut rng = rand::thread_rng();
                    let mut poly = Polynomial::random(degree, &mut rng);
                    poly.coeffs[0] = share_scalar; // constant term = our current share
                    let comm_bytes: Vec<[u8; 48]> = poly.commitments()
                        .iter()
                        .map(|c| vss::g1_to_bytes48(*c))
                        .collect();
                    (poly, comm_bytes)
                };

                // If we are also in the new committee, accumulate our own sub-share directly.
                if let Some(my_new_idx_0) = new_nodes.iter().position(|n| n == &my_addr_lower) {
                    let my_new_index = (my_new_idx_0 + 1) as u64;
                    let own_sub_share = poly.eval(my_new_index);
                    let mut locked = reshare_accum.lock().await;
                    let entry = locked.sub_shares.entry((epoch_change_id, secret_id)).or_default();
                    if !entry.iter().any(|(idx, _)| *idx == my_old_idx) {
                        entry.push((my_old_idx, own_sub_share));
                    }
                }

                // Send sub-shares to every other new committee member.
                for (j_idx, endpoint) in new_endpoints.iter().enumerate() {
                    let recipient_new_index = (j_idx + 1) as u64;
                    // Skip self (already accumulated above).
                    if new_nodes.get(j_idx).map(|n| n == &my_addr_lower).unwrap_or(false) {
                        continue;
                    }
                    if endpoint.is_empty() {
                        continue;
                    }
                    let msg = ReshareMsg::build(
                        epoch_change_id, secret_id, my_old_idx, &poly, recipient_new_index,
                    );
                    let url = format!("{}/reshare_share", endpoint.trim_end_matches('/'));
                    match http_client.post(&url).json(&msg).send().await {
                        Ok(resp) if resp.status().is_success() => {
                            info!("[EpochChange] sent sub-share to new worker {} for secret_id={}", recipient_new_index, secret_id);
                        }
                        Ok(resp) => {
                            warn!("[EpochChange] new worker {} rejected sub-share: {}", recipient_new_index, resp.status());
                        }
                        Err(e) => {
                            warn!("[EpochChange] failed to reach new worker {} ({}): {}", recipient_new_index, endpoint, e);
                        }
                    }
                }

                // Post VSS commitments on-chain: [0x02][C_0 48B]...[C_{t_new-1} 48B]
                let mut contribution = vec![0x02u8];
                for cb in &commitment_bytes {
                    contribution.extend_from_slice(cb);
                }
                info!("[EpochChange] posting commitments on-chain for secret_id={}", secret_id);
                let _ = rpc
                    .submit_txn(
                        signing_key,
                        verifying_key,
                        my_addr,
                        &format!("{}::ace_network::contribute_to_epoch_change", contract_addr),
                        &[],
                        &[
                            json!(epoch_change_id.to_string()),
                            json!(secret_id.to_string()),
                            json!(format!("0x{}", hex::encode(&contribution))),
                        ],
                    )
                    .await;
            }

            reshare_accum.lock().await.posted_epoch_change_ids.insert(epoch_change_id);
            info!("[EpochChange] dealing complete for epoch_change_id={}", epoch_change_id);
        }
    }

    // 5. Wait for the epoch to advance, then compute the new share if we are in the new committee.
    let _ = old_nodes; // silence unused warning
    let _ = old_threshold;
    for _ in 0..30 {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        let vals = match rpc
            .view(&format!("{}::ace_network::get_current_epoch", contract_addr), &[], &[json!(contract_addr)])
            .await
        {
            Ok(v) => v,
            Err(_) => continue,
        };
        let new_epoch_num = vals
            .get(0)
            .and_then(|v| v.as_str())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);
        if new_epoch_num <= epoch_num {
            continue;
        }

        info!("[EpochChange] epoch advanced to {}", new_epoch_num);

        // Am I in the new committee?
        let my_new_index = match new_nodes.iter().position(|n| n == &my_addr_lower) {
            Some(i) => (i + 1) as u64,
            None => break, // not in new committee, nothing to compute
        };

        // Read the secret_ids we saved (the list from before epoch advanced).
        let (saved_ec_id, saved_secret_ids) = {
            let locked = reshare_accum.lock().await;
            match &locked.active_resharing {
                Some((id, ids)) => (*id, ids.clone()),
                None => break,
            }
        };
        if reshare_accum.lock().await.committed_epoch_change_ids.contains(&saved_ec_id) {
            break; // already computed
        }

        for secret_id in &saved_secret_ids {
            // Read on-chain qualifying dealer set for this secret.
            let dealer_info = rpc
                .view(
                    &format!("{}::ace_network::get_resharing_dealer_info", contract_addr),
                    &[],
                    &[json!(contract_addr), json!(saved_ec_id.to_string()), json!(secret_id.to_string())],
                )
                .await
                .unwrap_or_default();
            let on_chain_indices: Vec<u64> = dealer_info
                .get(0)
                .and_then(|v| v.as_array())
                .map(|a| a.iter().filter_map(|v| v.as_str().and_then(|s| s.parse().ok())).collect())
                .unwrap_or_default();

            if on_chain_indices.is_empty() {
                warn!("[EpochChange] no on-chain dealers for secret_id={}, cannot compute share", secret_id);
                continue;
            }

            // Gather received sub-shares that match on-chain qualifying dealers.
            let received = {
                let locked = reshare_accum.lock().await;
                locked.sub_shares.get(&(saved_ec_id, *secret_id)).cloned().unwrap_or_default()
            };

            // Lagrange combination: new_share_j = Σ λ_i(0) · g_i(j)
            let mut new_share = ark_bls12_381::Fr::from(0u64);
            let mut used = 0usize;
            for &idx in &on_chain_indices {
                if let Some((_, sub_share)) = received.iter().find(|(i, _)| *i == idx) {
                    let lambda = vss::lagrange_at_zero(idx, &on_chain_indices);
                    new_share += lambda * sub_share;
                    used += 1;
                }
            }

            if used < on_chain_indices.len() {
                warn!(
                    "[EpochChange] only received {}/{} sub-shares for secret_id={}; share may be incomplete",
                    used, on_chain_indices.len(), secret_id
                );
            }

            let scalar_hex = hex::encode(vss::fr_to_le32(new_share));
            let base_hex = hex::encode(G1_GENERATOR_BYTES);
            {
                let mut locked = store.lock().await;
                if locked.get(*secret_id).map(|s| s.acquired_at_epoch < new_epoch_num).unwrap_or(true) {
                    locked.insert(
                        *secret_id,
                        KeyShare { scalar_share_hex: scalar_hex, base_hex, acquired_at_epoch: new_epoch_num },
                    );
                    info!("[EpochChange] new share stored: secret_id={} epoch={} new_index={}", secret_id, new_epoch_num, my_new_index);
                }
            }
        }

        reshare_accum.lock().await.committed_epoch_change_ids.insert(saved_ec_id);
        break;
    }

    Ok(())
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn get_secret_count(rpc: &AptosRpc, contract_addr: &str) -> Result<u64> {
    let vals = rpc
        .view(
            &format!("{}::ace_network::get_secret_count", contract_addr),
            &[],
            &[json!(contract_addr)],
        )
        .await?;
    Ok(vals
        .get(0)
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0))
}

async fn fetch_endpoints(
    rpc: &AptosRpc,
    contract_addr: &str,
    nodes: &[String],
) -> Result<Vec<String>> {
    let mut endpoints = Vec::new();
    for node_addr in nodes {
        let result = rpc
            .view(
                &format!("{}::ace_network::get_node_endpoint", contract_addr),
                &[],
                &[json!(contract_addr), json!(node_addr)],
            )
            .await;
        match result {
            Ok(vals) => {
                let ep = vals
                    .get(0)
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                endpoints.push(ep);
            }
            Err(e) => {
                warn!("[DKG] could not fetch endpoint for {}: {}", node_addr, e);
                endpoints.push(String::new());
            }
        }
    }
    Ok(endpoints)
}
