// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    future::Future,
    hash::Hash,
    sync::{Arc, OnceLock},
    time::Instant,
};

use anyhow::Result;
use tokio::sync::Mutex as AsyncMutex;

use super::aptos_constants::KEYLESS_RESOURCE_CACHE_TTL;
use super::{aptos_federated_keyless as federated_keyless, aptos_keyless as keyless};

type RsaJwk = aptos_keyless_common::RsaJwk;
type Groth16VerificationKey = aptos_keyless_common::Groth16VerificationKey;
type KeylessConfiguration = aptos_keyless_common::types::Configuration;
type CacheEntry<T> = Arc<AsyncMutex<Option<Timed<T>>>>;
type CacheStore<K, T> = AsyncMutex<HashMap<K, CacheEntry<T>>>;

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct KeylessChainCacheKey {
    chain_id: u8,
    rpc_base_url: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct SystemJwkCacheKey {
    chain: KeylessChainCacheKey,
    iss: String,
    kid: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Hash)]
struct FederatedJwkCacheKey {
    chain: KeylessChainCacheKey,
    jwk_addr: [u8; 32],
    iss: String,
    kid: String,
}

#[derive(Clone)]
struct Timed<T> {
    value: T,
    fetched_at: Instant,
}

static SYSTEM_JWK_CACHE: OnceLock<CacheStore<SystemJwkCacheKey, RsaJwk>> = OnceLock::new();
static FEDERATED_JWK_CACHE: OnceLock<CacheStore<FederatedJwkCacheKey, RsaJwk>> = OnceLock::new();
static GROTH16_VK_CACHE: OnceLock<CacheStore<KeylessChainCacheKey, Groth16VerificationKey>> =
    OnceLock::new();
static KEYLESS_CONFIG_CACHE: OnceLock<CacheStore<KeylessChainCacheKey, KeylessConfiguration>> =
    OnceLock::new();

fn system_jwk_cache() -> &'static CacheStore<SystemJwkCacheKey, RsaJwk> {
    SYSTEM_JWK_CACHE.get_or_init(|| AsyncMutex::new(HashMap::new()))
}

fn federated_jwk_cache() -> &'static CacheStore<FederatedJwkCacheKey, RsaJwk> {
    FEDERATED_JWK_CACHE.get_or_init(|| AsyncMutex::new(HashMap::new()))
}

fn groth16_vk_cache() -> &'static CacheStore<KeylessChainCacheKey, Groth16VerificationKey> {
    GROTH16_VK_CACHE.get_or_init(|| AsyncMutex::new(HashMap::new()))
}

fn keyless_config_cache() -> &'static CacheStore<KeylessChainCacheKey, KeylessConfiguration> {
    KEYLESS_CONFIG_CACHE.get_or_init(|| AsyncMutex::new(HashMap::new()))
}

fn chain_cache_key(chain_id: u8, rpc: &vss_common::AptosRpc) -> KeylessChainCacheKey {
    KeylessChainCacheKey {
        chain_id,
        rpc_base_url: rpc.base_url.trim_end_matches('/').to_string(),
    }
}

async fn cached_fetch<K, T, Fut, Fetch>(
    store: &'static CacheStore<K, T>,
    key: K,
    fetch: Fetch,
) -> Result<T>
where
    K: Eq + Hash + Clone,
    T: Clone,
    Fetch: FnOnce() -> Fut,
    Fut: Future<Output = Result<T>>,
{
    // The entry mutex is the per-key singleflight: one task refreshes while
    // same-key callers wait, then consume the freshly cached value.
    let entry = {
        let mut map = store.lock().await;
        map.entry(key.clone())
            .or_insert_with(|| Arc::new(AsyncMutex::new(None)))
            .clone()
    };

    let mut guard = entry.lock().await;
    if let Some(cached) = guard.as_ref() {
        if cached.fetched_at.elapsed() <= KEYLESS_RESOURCE_CACHE_TTL {
            return Ok(cached.value.clone());
        }
    }

    let had_cached_value = guard.is_some();
    match fetch().await {
        Ok(fresh) => {
            *guard = Some(Timed {
                value: fresh.clone(),
                fetched_at: Instant::now(),
            });
            Ok(fresh)
        }
        Err(err) => {
            drop(guard);
            if !had_cached_value {
                let mut map = store.lock().await;
                if map
                    .get(&key)
                    .is_some_and(|current| Arc::ptr_eq(current, &entry))
                {
                    map.remove(&key);
                }
            }
            Err(err)
        }
    }
}

pub(super) async fn fetch_cached_system_rsa_jwk(
    chain_id: u8,
    rpc: &vss_common::AptosRpc,
    iss: &str,
    kid: &str,
) -> Result<RsaJwk> {
    let key = SystemJwkCacheKey {
        chain: chain_cache_key(chain_id, rpc),
        iss: iss.to_string(),
        kid: kid.to_string(),
    };
    cached_fetch(system_jwk_cache(), key, || {
        keyless::fetch_system_rsa_jwk(rpc, iss, kid)
    })
    .await
}

pub(super) async fn fetch_cached_federated_jwk_with_fallback(
    chain_id: u8,
    rpc: &vss_common::AptosRpc,
    fpk: &aptos_keyless_common::FederatedKeylessPublicKey,
    kid: &str,
) -> Result<RsaJwk> {
    let key = FederatedJwkCacheKey {
        chain: chain_cache_key(chain_id, rpc),
        jwk_addr: fpk.jwk_addr,
        iss: fpk.pk.iss_val.clone(),
        kid: kid.to_string(),
    };
    cached_fetch(federated_jwk_cache(), key, || {
        federated_keyless::fetch_jwk_with_federated_fallback(rpc, fpk, kid)
    })
    .await
}

pub(super) async fn fetch_cached_groth16_vk(
    chain_id: u8,
    rpc: &vss_common::AptosRpc,
) -> Result<Groth16VerificationKey> {
    cached_fetch(groth16_vk_cache(), chain_cache_key(chain_id, rpc), || {
        keyless::fetch_groth16_vk(rpc)
    })
    .await
}

pub(super) async fn fetch_cached_configuration(
    chain_id: u8,
    rpc: &vss_common::AptosRpc,
) -> Result<KeylessConfiguration> {
    cached_fetch(
        keyless_config_cache(),
        chain_cache_key(chain_id, rpc),
        || keyless::fetch_configuration(rpc),
    )
    .await
}
