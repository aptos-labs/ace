// DKG / DKR against on-chain DkgSession / DkrSession objects (object-address keyed).
// Encrypted Shamir rows live on `admin::vss::VssSession`; partial MPK / commitments on-chain.

use anyhow::Result;
use ark_bls12_381::{Fr, G1Affine};
use ark_serialize::CanonicalDeserialize;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::{error, info, warn};

use crate::{
    aptos_rpc::AptosRpc,
    share_crypto,
    store::{KeyShare, ShareStore},
    vss::{self, Polynomial, G1_GENERATOR_BYTES},
    DkgShareAccum, ReshareAccum,
};

const STATUS_IN_PROGRESS: u8 = 0;
const STATUS_DONE: u8 = 1;

// ── Registration ──────────────────────────────────────────────────────────────

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
    let dk = share_crypto::derive_vss_dk(signing_key);
    let enc_pk = share_crypto::encryption_pk_compressed(&dk);
    rpc.submit_txn(
        signing_key,
        verifying_key,
        &my_addr,
        &format!("{}::ace_network::register_node", contract_addr),
        &[],
        &[
            json!(endpoint),
            crate::aptos_rpc::json_move_vec_u8(&enc_pk),
        ],
    )
    .await?;
    info!("Node registered.");
    Ok(())
}

// ── Main poll (summary-driven) ───────────────────────────────────────────────

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
    let my_lower = my_addr_str.to_lowercase();

    let summary = match rpc.get_network_state_summary(contract_addr).await {
        Ok(s) => s,
        Err(e) => {
            warn!("[poller] get_network_state_summary failed: {}", e);
            return Ok(());
        }
    };

    let in_current = summary.workers.iter().any(|w| w == &my_lower);
    let in_next = summary.next_epoch_workers.iter().any(|w| w == &my_lower);

    if in_current {
        for dkg in &summary.dkg_sessions {
            if let Err(e) = process_dkg_session(
                rpc,
                signing_key,
                verifying_key,
                contract_addr,
                &my_lower,
                dkg,
                &summary.workers,
                summary.epoch,
                Arc::clone(&store),
                Arc::clone(&accum),
            )
            .await
            {
                error!("[poller] DKG session {} error: {}", dkg, e);
            }
        }
    }

    if in_current {
        for dkr in &summary.dkr_sessions {
            if let Err(e) = process_dkr_src(
                rpc,
                signing_key,
                verifying_key,
                contract_addr,
                &my_lower,
                dkr,
                &summary.workers,
                Arc::clone(&store),
                Arc::clone(&reshare_accum),
            )
            .await
            {
                error!("[poller] DKR-SRC {} error: {}", dkr, e);
            }
        }
    }

    if in_next || in_current {
        for dkr in &summary.dkr_sessions {
            if let Err(e) = process_dkr_dst(
                rpc,
                signing_key,
                contract_addr,
                &my_lower,
                dkr,
                &summary.next_epoch_workers,
                Arc::clone(&store),
                Arc::clone(&reshare_accum),
            )
            .await
            {
                error!("[poller] DKR-DST {} error: {}", dkr, e);
            }
        }
    }

    let _ = store_path;
    Ok(())
}

// ── DKG ───────────────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn process_dkg_session(
    rpc: &AptosRpc,
    signing_key: &ed25519_dalek::SigningKey,
    verifying_key: &ed25519_dalek::VerifyingKey,
    contract_addr: &str,
    my_lower: &str,
    dkg_addr: &str,
    workers: &[String],
    epoch: u64,
    store: Arc<Mutex<ShareStore>>,
    accum: Arc<Mutex<DkgShareAccum>>,
) -> Result<()> {
    let info = rpc.get_dkg_session(contract_addr, dkg_addr).await?;
    if info.status != STATUS_IN_PROGRESS {
        return Ok(());
    }

    let my_pos = match workers.iter().position(|w| w == my_lower) {
        Some(i) => i,
        None => return Ok(()),
    };
    let my_index = (my_pos + 1) as u64;
    let (epoch_num, _nodes, th_on_chain) = get_current_epoch_tuple(rpc, contract_addr).await?;
    if epoch_num != epoch {
        return Ok(());
    }
    let threshold = th_on_chain.max(2);

    let secret_count_before = get_secret_count(rpc, contract_addr).await?;
    let dkg_key = dkg_addr.to_lowercase();

    {
        let locked = store.lock().await;
        if locked.get(secret_count_before).is_some() {
            return Ok(());
        }
    }

    {
        let locked = accum.lock().await;
        if locked.posted_dkg_sessions.contains(&dkg_key) {
            drop(locked);
            try_commit_dkg_share(
                rpc,
                contract_addr,
                &dkg_key,
                secret_count_before,
                epoch_num,
                Arc::clone(&store),
                Arc::clone(&accum),
            )
            .await;
            return Ok(());
        }
    }

    let degree = (threshold as usize).saturating_sub(1);
    let (poly, partial_mpk_bytes) = {
        let mut rng = rand::thread_rng();
        let poly = Polynomial::random(degree, &mut rng);
        let partial = vss::g1_to_bytes48(poly.partial_mpk());
        (poly, partial)
    };

    let own_share = poly.eval(my_index);
    {
        let mut locked = accum.lock().await;
        let e = locked.shares.entry(dkg_key.clone()).or_insert(Fr::from(0u64));
        *e += own_share;
    }

    let my_vss = info
        .vss_sessions
        .get(my_pos)
        .cloned()
        .ok_or_else(|| anyhow::anyhow!("missing vss session"))?;

    let dk = share_crypto::derive_vss_dk(signing_key);
    for (j, recv) in workers.iter().enumerate() {
        let recipient_index = (j + 1) as u64;
        if recipient_index == my_index {
            continue;
        }
        let share_fr = poly.eval(recipient_index);
        let share_bytes = vss::fr_to_le32(share_fr);
        let pk = rpc.get_node_encryption_pk(contract_addr, recv).await.unwrap_or_default();
        if pk.len() != 48 {
            warn!("[DKG] skip recipient {}: bad encryption pk len {}", recv, pk.len());
            continue;
        }
        let mut pk_arr = [0u8; 48];
        pk_arr.copy_from_slice(&pk);
        let ct = match share_crypto::encrypt_share_80(&share_bytes, &pk_arr) {
            Ok(c) => c,
            Err(e) => {
                warn!("[DKG] encrypt for {}: {}", recv, e);
                continue;
            }
        };
        let _ = rpc
            .submit_txn(
                signing_key,
                verifying_key,
                my_lower,
                &format!("{}::vss::post_encrypted_share", contract_addr),
                &[],
                &[
                    json!(my_vss),
                    json!(recv),
                    crate::aptos_rpc::json_move_vec_u8(&ct),
                ],
            )
            .await;
    }

    for dealer_idx in 0..workers.len() {
        if dealer_idx == my_pos {
            continue;
        }
        let dealer_vss = match info.vss_sessions.get(dealer_idx) {
            Some(a) => a.clone(),
            None => continue,
        };
        let ct = rpc
            .get_encrypted_share(contract_addr, &dealer_vss, my_lower)
            .await
            .unwrap_or_default();
        if ct.len() != 80 {
            continue;
        }
        let sub = match share_crypto::decrypt_share_80(&ct, &dk) {
            Ok(b) => vss::fr_from_le32(&b),
            Err(e) => {
                warn!("[DKG] decrypt from dealer {}: {}", dealer_idx, e);
                continue;
            }
        };
        let comm = match rpc.get_vss_session(contract_addr, &dealer_vss).await {
            Ok(v) if v.contribution.len() > 1 => {
                let cbytes = &v.contribution[1..];
                let nc = cbytes.len() / 48;
                let mut out = Vec::new();
                for k in 0..nc {
                    let s = k * 48;
                    if s + 48 <= cbytes.len() {
                        if let Ok(p) = G1Affine::deserialize_compressed(&cbytes[s..s + 48]) {
                            out.push(p);
                        }
                    }
                }
                out
            }
            _ => Vec::new(),
        };
        // DKG on-chain contribution is 49-byte partial MPK only — no polynomial commitments to verify against.
        if comm.len() >= threshold as usize && !vss::verify_share(sub, my_index, &comm) {
            warn!("[DKG] verify failed for dealer {}", dealer_idx);
            continue;
        }
        let mut locked = accum.lock().await;
        let e = locked.shares.entry(dkg_key.clone()).or_insert(Fr::from(0u64));
        *e += sub;
    }

    info!("[DKG] {} wait 5s then post partial MPK", dkg_addr);
    tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;

    let mut contribution = vec![0x02u8];
    contribution.extend_from_slice(&partial_mpk_bytes);
    rpc.submit_txn(
        signing_key,
        verifying_key,
        my_lower,
        &format!("{}::ace_network::contribute_to_dkg", contract_addr),
        &[],
        &[json!(dkg_addr), crate::aptos_rpc::json_move_vec_u8(&contribution)],
    )
    .await?;

    {
        let mut locked = accum.lock().await;
        locked.posted_dkg_sessions.insert(dkg_key.clone());
    }

    try_commit_dkg_share(
        rpc,
        contract_addr,
        &dkg_key,
        secret_count_before,
        epoch_num,
        Arc::clone(&store),
        Arc::clone(&accum),
    )
    .await;

    Ok(())
}

async fn try_commit_dkg_share(
    rpc: &AptosRpc,
    contract_addr: &str,
    dkg_key: &str,
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
    for _ in 0..60 {
        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
        if let Ok(count) = get_secret_count(rpc, contract_addr).await {
            if count > secret_count_before {
                finalised = true;
                break;
            }
        }
    }
    if !finalised {
        warn!("[DKG] timeout waiting finalisation {}", dkg_key);
        return;
    }

    let share_fr = {
        let locked = accum.lock().await;
        locked
            .shares
            .get(dkg_key)
            .copied()
            .unwrap_or_else(|| Fr::from(0u64))
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
            info!("[DKG] share committed secret_id={} epoch={}", secret_id, epoch_num);
        }
    }
}

// ── DKR source (old committee) ───────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn process_dkr_src(
    rpc: &AptosRpc,
    signing_key: &ed25519_dalek::SigningKey,
    verifying_key: &ed25519_dalek::VerifyingKey,
    contract_addr: &str,
    my_lower: &str,
    dkr_addr: &str,
    old_workers: &[String],
    store: Arc<Mutex<ShareStore>>,
    reshare_accum: Arc<Mutex<ReshareAccum>>,
) -> Result<()> {
    let info = rpc.get_dkr_session(contract_addr, dkr_addr).await?;
    if info.status != STATUS_IN_PROGRESS {
        return Ok(());
    }

    let my_old_pos = match old_workers.iter().position(|w| w == my_lower) {
        Some(i) => i,
        None => return Ok(()),
    };
    let my_old_idx = (my_old_pos + 1) as u64;
    let n_secrets = info.n_secrets as usize;
    let n_old = old_workers.len();

    {
        let mut ra = reshare_accum.lock().await;
        if ra.active_dkr.as_deref() != Some(dkr_addr) {
            ra.active_dkr = Some(dkr_addr.to_string());
        }
    }

    let new_nodes = &info.new_nodes;
    let new_th = info.new_threshold.max(2) as usize;
    let degree = new_th.saturating_sub(1);

    for secret_idx in 0..n_secrets {
        let key = (dkr_addr.to_string(), secret_idx as u64);
        {
            let ra = reshare_accum.lock().await;
            if ra.posted_dkr_contribs.contains(&key) {
                continue;
            }
        }

        let secret_id = secret_idx as u64;
        let share_scalar = {
            let locked = store.lock().await;
            match locked.get(secret_id) {
                Some(row) => match hex::decode(&row.scalar_share_hex) {
                    Ok(b) if b.len() == 32 => {
                        let a: [u8; 32] = b.as_slice().try_into().unwrap_or([0u8; 32]);
                        vss::fr_from_le32(&a)
                    }
                    _ => {
                        warn!("[DKR] bad share secret_id={}", secret_id);
                        continue;
                    }
                },
                None => {
                    warn!("[DKR] no share secret_id={}", secret_id);
                    continue;
                }
            }
        };

        let vss_idx = my_old_pos * n_secrets + secret_idx;
        let my_vss = match info.vss_sessions.get(vss_idx) {
            Some(a) => a.clone(),
            None => continue,
        };

        let (poly, commitment_bytes) = {
            let mut rng = rand::thread_rng();
            let mut poly = Polynomial::random(degree, &mut rng);
            poly.coeffs[0] = share_scalar;
            let comm: Vec<[u8; 48]> = poly
                .commitments()
                .iter()
                .map(|c| vss::g1_to_bytes48(*c))
                .collect();
            (poly, comm)
        };

        for (j, recv) in new_nodes.iter().enumerate() {
            let recipient_new_index = (j + 1) as u64;
            if new_nodes.get(j).map(|n| n.to_lowercase()) == Some(my_lower.to_string()) {
                continue;
            }
            let sub = poly.eval(recipient_new_index);
            let share_bytes = vss::fr_to_le32(sub);
            let pk = rpc.get_node_encryption_pk(contract_addr, recv).await.unwrap_or_default();
            if pk.len() != 48 {
                continue;
            }
            let mut pk_arr = [0u8; 48];
            pk_arr.copy_from_slice(&pk);
            if let Ok(ct) = share_crypto::encrypt_share_80(&share_bytes, &pk_arr) {
                let _ = rpc
                    .submit_txn(
                        signing_key,
                        verifying_key,
                        my_lower,
                        &format!("{}::vss::post_encrypted_share", contract_addr),
                        &[],
                        &[
                            json!(my_vss),
                            json!(recv),
                            crate::aptos_rpc::json_move_vec_u8(&ct),
                        ],
                    )
                    .await;
            }
        }

        if let Some(my_new_j) = new_nodes.iter().position(|n| n.to_lowercase() == my_lower) {
            let my_new_index = (my_new_j + 1) as u64;
            let own_sub = poly.eval(my_new_index);
            let mut ra = reshare_accum.lock().await;
            let e = ra
                .sub_shares
                .entry((dkr_addr.to_string(), secret_idx as u64))
                .or_default();
            if !e.iter().any(|(i, _)| *i == my_old_idx) {
                e.push((my_old_idx, own_sub));
            }
        }

        let mut contribution = vec![0x02u8];
        for cb in &commitment_bytes {
            contribution.extend_from_slice(cb);
        }
        rpc.submit_txn(
            signing_key,
            verifying_key,
            my_lower,
            &format!("{}::ace_network::contribute_to_dkr", contract_addr),
            &[],
            &[
                json!(dkr_addr),
                json!(secret_idx),
                crate::aptos_rpc::json_move_vec_u8(&contribution),
            ],
        )
        .await?;

        reshare_accum
            .lock()
            .await
            .posted_dkr_contribs
            .insert((dkr_addr.to_string(), secret_idx as u64));
    }

    let _ = n_old;
    Ok(())
}

// ── DKR destination (new committee) ───────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
async fn process_dkr_dst(
    rpc: &AptosRpc,
    signing_key: &ed25519_dalek::SigningKey,
    contract_addr: &str,
    my_lower: &str,
    dkr_addr: &str,
    new_workers: &[String],
    store: Arc<Mutex<ShareStore>>,
    reshare_accum: Arc<Mutex<ReshareAccum>>,
) -> Result<()> {
    let info = rpc.get_dkr_session(contract_addr, dkr_addr).await?;
    if info.status != STATUS_IN_PROGRESS {
        return Ok(());
    }
    let my_new_pos = match new_workers.iter().position(|w| w == my_lower) {
        Some(i) => i,
        None => return Ok(()),
    };
    let my_new_index = (my_new_pos + 1) as u64;
    let n_secrets = info.n_secrets as usize;
    let n_old = info.vss_sessions.len() / n_secrets.max(1);
    let old_th = info.old_threshold;

    let dk = share_crypto::derive_vss_dk(signing_key);

    for secret_idx in 0..n_secrets {
        for d in 0..n_old {
            let vss_addr = match info.vss_sessions.get(d * n_secrets + secret_idx) {
                Some(a) => a.clone(),
                None => continue,
            };
            let ct = rpc
                .get_encrypted_share(contract_addr, &vss_addr, my_lower)
                .await
                .unwrap_or_default();
            if ct.len() != 80 {
                continue;
            }
            let sub = match share_crypto::decrypt_share_80(&ct, &dk) {
                Ok(b) => vss::fr_from_le32(&b),
                Err(_) => continue,
            };
            let vinfo = match rpc.get_vss_session(contract_addr, &vss_addr).await {
                Ok(v) => v,
                Err(_) => continue,
            };
            let comm = if vinfo.contribution.len() > 1 {
                let cbytes = &vinfo.contribution[1..];
                let nc = cbytes.len() / 48;
                let mut out = Vec::new();
                for k in 0..nc {
                    let s = k * 48;
                    if s + 48 <= cbytes.len() {
                        if let Ok(p) = G1Affine::deserialize_compressed(&cbytes[s..s + 48]) {
                            out.push(p);
                        }
                    }
                }
                out
            } else {
                continue;
            };
            if !vss::verify_share(sub, my_new_index, &comm) {
                continue;
            }
            let dealer_idx = d as u64 + 1;
            let mut ra = reshare_accum.lock().await;
            let e = ra
                .sub_shares
                .entry((dkr_addr.to_string(), secret_idx as u64))
                .or_default();
            if !e.iter().any(|(i, _)| *i == dealer_idx) {
                e.push((dealer_idx, sub));
            }
        }
    }

    let (epoch_now, _, _) = get_current_epoch_tuple(rpc, contract_addr).await?;

    for secret_idx in 0..n_secrets {
        let secret_id = secret_idx as u64;
        let pair = (dkr_addr.to_string(), secret_id);
        {
            let ra = reshare_accum.lock().await;
            if ra.committed_dkr_secrets.contains(&pair) {
                continue;
            }
        }
        let done_cnt = *info.resharing_counts.get(secret_idx).unwrap_or(&0);
        if done_cnt < old_th {
            continue;
        }
        let mut done_dealers: Vec<u64> = Vec::new();
        for d in 0..n_old {
            let vaddr = match info.vss_sessions.get(d * n_secrets + secret_idx) {
                Some(a) => a.as_str(),
                None => continue,
            };
            if let Ok(vi) = rpc.get_vss_session(contract_addr, vaddr).await {
                if vi.status == STATUS_DONE {
                    done_dealers.push((d + 1) as u64);
                }
            }
        }
        if done_dealers.len() != old_th as usize {
            continue;
        }
        done_dealers.sort_unstable();
        let use_idx = done_dealers;
        let received = {
            let ra = reshare_accum.lock().await;
            ra.sub_shares.get(&pair).cloned().unwrap_or_default()
        };
        let mut new_share = Fr::from(0u64);
        for &idx in &use_idx {
            let sub_share = match received.iter().find(|(i, _)| *i == idx) {
                Some((_, s)) => *s,
                None => continue,
            };
            new_share += vss::lagrange_at_zero(idx, &use_idx) * sub_share;
        }
        let scalar_hex = hex::encode(vss::fr_to_le32(new_share));
        let base_hex = hex::encode(G1_GENERATOR_BYTES);
        {
            let mut st = store.lock().await;
            st.insert(
                secret_id,
                KeyShare {
                    scalar_share_hex: scalar_hex,
                    base_hex,
                    acquired_at_epoch: epoch_now,
                },
            );
        }
        reshare_accum.lock().await.committed_dkr_secrets.insert(pair);
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
        .and_then(|s| s.parse().ok())
        .unwrap_or(0))
}

async fn get_current_epoch_tuple(
    rpc: &AptosRpc,
    contract_addr: &str,
) -> Result<(u64, Vec<String>, u64)> {
    let vals = rpc
        .view(
            &format!("{}::ace_network::get_current_epoch", contract_addr),
            &[],
            &[json!(contract_addr)],
        )
        .await?;
    let epoch_num = vals
        .get(0)
        .and_then(|v| v.as_str())
        .and_then(|s| s.parse().ok())
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
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    Ok((epoch_num, node_list, threshold))
}
