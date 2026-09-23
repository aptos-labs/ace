// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

//! Fullnode REST access + the `ChainReader` abstraction (TS: `createAptos`, `FullnodeChainReader`,
//! `DiscoveryChainReader`, `getChainReader`). Requires the `aptos` feature.

use async_trait::async_trait;
use tokio::sync::OnceCell;

use super::deployment::AceDeployment;
use super::discovery::{DiscoveryViewV0, SessionPks};
use crate::address::AccountAddress;
use crate::error::{AceError, Result};
use crate::network::State as NetworkState;
use crate::pke;
use crate::wire::{decode_hex, Wire};
use crate::{dkg, dkr};

/// Thin Aptos fullnode REST client: `/v1` ledger info and `/v1/view`.
#[derive(Clone, Debug)]
pub struct FullnodeClient {
    http: reqwest::Client,
    api_endpoint: String,
    api_key: Option<String>,
}

impl FullnodeClient {
    pub fn new(api_endpoint: impl Into<String>, api_key: Option<String>) -> Self {
        let api_endpoint = api_endpoint.into().trim_end_matches('/').to_string();
        Self {
            http: reqwest::Client::new(),
            api_endpoint,
            api_key,
        }
    }
    pub fn for_deployment(dep: &AceDeployment) -> Self {
        Self::new(dep.api_endpoint.clone(), dep.api_key.clone())
    }
    pub fn api_endpoint(&self) -> &str {
        &self.api_endpoint
    }

    fn auth(&self, req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.api_key {
            Some(k) => req.bearer_auth(k),
            None => req,
        }
    }

    async fn send_json(&self, req: reqwest::RequestBuilder) -> Result<serde_json::Value> {
        let resp = self
            .auth(req)
            .send()
            .await
            .map_err(|e| AceError::Chain(format!("http: {e}")))?;
        let status = resp.status();
        let body = resp
            .text()
            .await
            .map_err(|e| AceError::Chain(format!("http body: {e}")))?;
        if !status.is_success() {
            return Err(AceError::Http {
                status: status.as_u16(),
                body,
            });
        }
        serde_json::from_str(&body).map_err(|e| AceError::Chain(format!("bad json: {e}")))
    }

    /// `GET /v1` → `chain_id`.
    pub async fn chain_id(&self) -> Result<u8> {
        let v = self.send_json(self.http.get(&self.api_endpoint)).await?;
        v.get("chain_id")
            .and_then(|c| c.as_u64())
            .and_then(|c| u8::try_from(c).ok())
            .ok_or_else(|| AceError::Chain("ledger info: missing chain_id".into()))
    }

    /// `POST /v1/view` with `function` = `0x..::module::fn`, string arguments as the REST API
    /// expects them. Returns the raw return-value array.
    pub async fn view(
        &self,
        function: &str,
        type_arguments: &[&str],
        arguments: &[serde_json::Value],
    ) -> Result<Vec<serde_json::Value>> {
        let payload = serde_json::json!({
            "function": function,
            "type_arguments": type_arguments,
            "arguments": arguments,
        });
        let v = self
            .send_json(
                self.http
                    .post(format!("{}/view", self.api_endpoint))
                    .json(&payload),
            )
            .await?;
        v.as_array()
            .cloned()
            .ok_or_else(|| AceError::Chain(format!("view {function}: expected array")))
    }

    /// A view whose single return value is a hex-encoded BCS blob.
    pub async fn view_bcs(
        &self,
        function: &str,
        arguments: &[serde_json::Value],
    ) -> Result<Vec<u8>> {
        let vals = self.view(function, &[], arguments).await?;
        let hex = vals
            .first()
            .and_then(|v| v.as_str())
            .ok_or_else(|| AceError::Chain(format!("view {function}: expected hex string")))?;
        decode_hex(hex)
    }
}

/// What the client flows need from the chain; served either by the fullnode or by a discovery
/// snapshot (TS `ChainReader`).
#[async_trait]
pub trait ChainReader: Send + Sync {
    async fn network_state(&self) -> Result<NetworkState>;
    /// `is_dkg` selects the session module on the fullnode path; discovery ignores it.
    async fn session(&self, addr: &AccountAddress, is_dkg: bool) -> Result<SessionPks>;
    async fn worker_endpoint(&self, addr: &AccountAddress) -> Result<String>;
    async fn worker_enc_key(&self, addr: &AccountAddress) -> Result<pke::EncryptionKey>;
}

pub struct FullnodeChainReader {
    client: FullnodeClient,
    contract: String,
}

impl FullnodeChainReader {
    pub fn new(dep: &AceDeployment) -> Self {
        Self {
            client: FullnodeClient::for_deployment(dep),
            contract: dep.contract_addr.to_string_long(),
        }
    }
    pub fn client(&self) -> &FullnodeClient {
        &self.client
    }
    fn f(&self, name: &str) -> String {
        format!("{}::{}", self.contract, name)
    }
    fn arg(addr: &AccountAddress) -> serde_json::Value {
        serde_json::Value::String(addr.to_string_long())
    }
}

#[async_trait]
impl ChainReader for FullnodeChainReader {
    async fn network_state(&self) -> Result<NetworkState> {
        let bytes = self
            .client
            .view_bcs(&self.f("network::state_view_v0_bcs"), &[])
            .await?;
        NetworkState::from_bytes(&bytes)
            .map_err(|e| AceError::Chain(format!("parse network state: {e}")))
    }
    async fn session(&self, addr: &AccountAddress, is_dkg: bool) -> Result<SessionPks> {
        let arg = Self::arg(addr);
        if is_dkg {
            let bytes = self
                .client
                .view_bcs(&self.f("dkg::get_session_bcs"), &[arg])
                .await?;
            let s = dkg::Session::from_bytes(&bytes)
                .map_err(|e| AceError::Chain(format!("parse DKG session: {e}")))?;
            Ok(SessionPks {
                base_point: s.base_point,
                share_pks: s.share_pks,
                result_pk: s.result_pk,
            })
        } else {
            let bytes = self
                .client
                .view_bcs(&self.f("dkr::get_session_bcs"), &[arg])
                .await?;
            let s = dkr::Session::from_bytes(&bytes)
                .map_err(|e| AceError::Chain(format!("parse DKR session: {e}")))?;
            Ok(SessionPks {
                base_point: s.public_base_element,
                share_pks: s.share_pks,
                result_pk: None,
            })
        }
    }
    async fn worker_endpoint(&self, addr: &AccountAddress) -> Result<String> {
        let vals = self
            .client
            .view(
                &self.f("worker_config::get_endpoint"),
                &[],
                &[Self::arg(addr)],
            )
            .await?;
        vals.first()
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| AceError::Chain(format!("worker endpoint for {addr}: expected string")))
    }
    async fn worker_enc_key(&self, addr: &AccountAddress) -> Result<pke::EncryptionKey> {
        let bytes = self
            .client
            .view_bcs(
                &self.f("worker_config::get_pke_enc_key_bcs"),
                &[Self::arg(addr)],
            )
            .await?;
        pke::EncryptionKey::from_bytes(&bytes)
            .map_err(|e| AceError::Chain(format!("parse pke enc key for {addr}: {e}")))
    }
}

/// Fetch `GET <discovery_url>/bcs` (hex, or JSON `{discoveryViewV0Bcs}`) and decode it.
pub async fn fetch_discovery_view(discovery_url: &str) -> Result<DiscoveryViewV0> {
    let url = format!("{}/bcs", discovery_url.trim_end_matches('/'));
    let resp = reqwest::get(&url)
        .await
        .map_err(|e| AceError::Chain(format!("discovery GET {url}: {e}")))?;
    let status = resp.status();
    let body = resp
        .text()
        .await
        .map_err(|e| AceError::Chain(format!("discovery body: {e}")))?;
    if !status.is_success() {
        return Err(AceError::Http {
            status: status.as_u16(),
            body,
        });
    }
    let mut hex = body.trim().to_string();
    if hex.starts_with('{') {
        let v: serde_json::Value = serde_json::from_str(&hex)
            .map_err(|e| AceError::Chain(format!("discovery json: {e}")))?;
        hex = v
            .get("discoveryViewV0Bcs")
            .and_then(|x| x.as_str())
            .ok_or_else(|| {
                AceError::Chain("discovery: response JSON missing 'discoveryViewV0Bcs'".into())
            })?
            .to_string();
    }
    DiscoveryViewV0::from_bytes(&decode_hex(&hex)?)
}

/// One discovery snapshot per reader, fetched lazily and reused for every query.
pub struct DiscoveryChainReader {
    discovery_url: String,
    snapshot: OnceCell<DiscoveryViewV0>,
}

impl DiscoveryChainReader {
    pub fn new(discovery_url: impl Into<String>) -> Self {
        Self {
            discovery_url: discovery_url.into(),
            snapshot: OnceCell::new(),
        }
    }
    async fn view0(&self) -> Result<&DiscoveryViewV0> {
        self.snapshot
            .get_or_try_init(|| fetch_discovery_view(&self.discovery_url))
            .await
    }
    fn missing(addr: &AccountAddress) -> AceError {
        AceError::Chain(format!("discovery: node {addr} not in snapshot"))
    }
}

#[async_trait]
impl ChainReader for DiscoveryChainReader {
    async fn network_state(&self) -> Result<NetworkState> {
        Ok(self.view0().await?.state.clone())
    }
    async fn session(&self, addr: &AccountAddress, _is_dkg: bool) -> Result<SessionPks> {
        self.view0()
            .await?
            .sessions
            .get(addr)
            .cloned()
            .ok_or_else(|| AceError::Chain(format!("discovery: session {addr} not in snapshot")))
    }
    async fn worker_endpoint(&self, addr: &AccountAddress) -> Result<String> {
        let n = self
            .view0()
            .await?
            .nodes
            .get(addr)
            .ok_or_else(|| Self::missing(addr))?;
        n.endpoint.clone().ok_or_else(|| {
            AceError::Chain(format!("discovery: node {addr} has no registered endpoint"))
        })
    }
    async fn worker_enc_key(&self, addr: &AccountAddress) -> Result<pke::EncryptionKey> {
        let n = self
            .view0()
            .await?
            .nodes
            .get(addr)
            .ok_or_else(|| Self::missing(addr))?;
        Ok(n.enc_key.clone())
    }
}

/// TS `getChainReader`: discovery when configured and no API key is set, else the fullnode.
pub fn chain_reader(dep: &AceDeployment) -> Box<dyn ChainReader> {
    match (&dep.api_key, &dep.discovery_url) {
        (None, Some(url)) => Box::new(DiscoveryChainReader::new(url.clone())),
        _ => Box::new(FullnodeChainReader::new(dep)),
    }
}

#[cfg(test)]
mod live_tests {
    use super::*;
    use crate::aptos::known_deployment;

    /// Hits the public shelbynet discovery service + fullnode. Run with `cargo test -- --ignored`.
    ///
    /// STALE as of the 2026-09-22 shelbynet reset (chain_id 118 -> 119): the
    /// "shelbynet-20260731" deployment key was removed pending redeploy (contract +
    /// DKG on the new chain). Update to the new dated key once it lands.
    #[tokio::test]
    #[ignore]
    async fn shelbynet_discovery_and_fullnode_agree() {
        let dep = known_deployment("shelbynet-20260731").unwrap();
        let disc = DiscoveryChainReader::new(dep.ace_deployment.discovery_url.clone().unwrap());
        let full = FullnodeChainReader::new(&dep.ace_deployment);
        let ds = disc.network_state().await.unwrap();
        let fs = full.network_state().await.unwrap();
        assert!(
            ds.epoch >= 900 && fs.epoch >= ds.epoch,
            "epochs {} {}",
            ds.epoch,
            fs.epoch
        );
        assert_eq!(ds.cur_nodes, fs.cur_nodes);
        assert_eq!(ds.cur_threshold, 2);
        let kp = dep.ibe_keypair_id;
        let secret = fs.secret(&kp).expect("keypair present");
        let is_dkg = secret.current_session == kp;
        let sess = full.session(&secret.current_session, is_dkg).await.unwrap();
        assert_eq!(sess.share_pks.len(), fs.cur_nodes.len());
        let dsess = disc.session(&secret.current_session, is_dkg).await.unwrap();
        assert_eq!(dsess.base_point, sess.base_point);
        for n in &fs.cur_nodes {
            let ep = disc.worker_endpoint(n).await.unwrap();
            assert!(ep.starts_with("https://"), "{ep}");
            let ek = full.worker_enc_key(n).await.unwrap();
            assert_eq!(disc.worker_enc_key(n).await.unwrap(), ek);
        }
        assert_eq!(full.client().chain_id().await.unwrap(), dep.chain_id);
    }
}
