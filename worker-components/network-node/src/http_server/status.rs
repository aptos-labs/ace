// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::time::{Duration, Instant};

use futures::future::join_all;
use serde::Serialize;
use serde_json::{json, Value};
use tokio::time::timeout;
use vss_common::AptosRpc;

use crate::{now_utc_iso, ChainRpcConfig};

const STATUS_SCHEMA: &str = "ace.node_status.v1";
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);

#[derive(Clone)]
pub struct NodeStatus {
    public_config: PublicNodeConfig,
    dependencies: Vec<DependencyTarget>,
}

#[derive(Clone, Serialize)]
pub struct PublicNodeConfig {
    pub mode: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub account_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ace_deployment_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_server: Option<PublicServerConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets_server: Option<PublicServerConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_concurrent_requests: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maintainer_url: Option<String>,
    pub dependencies: Vec<PublicDependencyConfig>,
}

#[derive(Clone, Serialize)]
pub struct PublicServerConfig {
    pub port: u16,
}

#[derive(Clone, Serialize)]
pub struct PublicDependencyConfig {
    pub name: String,
    pub kind: DependencyKind,
    pub url: String,
    pub auth_configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_station_configured: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_chain_id: Option<u8>,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DependencyKind {
    AptosFullnode,
    SolanaRpc,
    HttpJson,
}

#[derive(Clone)]
pub struct DependencyTarget {
    public: PublicDependencyConfig,
    raw_url: String,
    probe: DependencyProbe,
}

#[derive(Clone)]
enum DependencyProbe {
    Aptos { rpc: AptosRpc },
    Solana { client: reqwest::Client },
    HttpJson { client: reqwest::Client },
}

#[derive(Serialize)]
pub struct PublicStatusResponse {
    pub version: String,
}

#[derive(Serialize)]
pub struct DebugStatusResponse {
    pub schema: &'static str,
    pub generated_at: String,
    pub version: VersionInfo,
    pub public_config: PublicNodeConfig,
    pub dependencies: Vec<DependencyStatus>,
}

#[derive(Serialize)]
pub struct VersionInfo {
    pub crate_name: &'static str,
    pub crate_version: &'static str,
    pub build_profile: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ace_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_tag: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_sha: Option<String>,
}

#[derive(Serialize)]
pub struct DependencyStatus {
    pub name: String,
    pub kind: DependencyKind,
    pub url: String,
    pub auth_configured: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gas_station_configured: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_chain_id: Option<u8>,
    pub ok: bool,
    pub latency_ms: u128,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub observed_chain_id: Option<u8>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl NodeStatus {
    pub fn new(mut public_config: PublicNodeConfig, dependencies: Vec<DependencyTarget>) -> Self {
        public_config.dependencies = dependencies.iter().map(|d| d.public.clone()).collect();
        Self {
            public_config,
            dependencies,
        }
    }

    pub fn public_response(&self) -> PublicStatusResponse {
        PublicStatusResponse {
            version: VersionInfo::public_version(),
        }
    }

    pub async fn debug_response(&self) -> DebugStatusResponse {
        let dependencies = join_all(self.dependencies.iter().map(DependencyTarget::probe)).await;
        DebugStatusResponse {
            schema: STATUS_SCHEMA,
            generated_at: now_utc_iso(),
            version: VersionInfo::current(),
            public_config: self.public_config.clone(),
            dependencies,
        }
    }
}

impl VersionInfo {
    fn public_version() -> String {
        first_env(&["ACE_VERSION", "ACE_RELEASE_VERSION"])
        .filter(|v| v != "unknown")
        .unwrap_or_else(|| env!("CARGO_PKG_VERSION").to_string())
    }

    fn current() -> Self {
        Self {
            crate_name: env!("CARGO_PKG_NAME"),
            crate_version: env!("CARGO_PKG_VERSION"),
            build_profile: if cfg!(debug_assertions) { "debug" } else { "release" },
            ace_version: first_env(&["ACE_VERSION", "ACE_RELEASE_VERSION"]),
            image_tag: first_env(&["ACE_IMAGE_TAG", "ACE_DOCKER_TAG"]),
            git_sha: first_env(&["ACE_GIT_SHA", "GIT_SHA", "COMMIT_SHA"]),
        }
    }
}

fn first_env(names: &[&str]) -> Option<String> {
    names
        .iter()
        .find_map(|name| std::env::var(name).ok().filter(|v| !v.trim().is_empty()))
}

impl PublicNodeConfig {
    pub fn new(mode: &str) -> Self {
        Self {
            mode: mode.to_string(),
            account_addr: None,
            ace_deployment_addr: None,
            user_server: None,
            secrets_server: None,
            max_concurrent_requests: None,
            maintainer_url: None,
            dependencies: Vec::new(),
        }
    }
}

impl DependencyTarget {
    pub fn aptos(name: &str, rpc: AptosRpc, expected_chain_id: Option<u8>) -> Self {
        let raw_url = rpc.base_url.clone();
        Self {
            public: PublicDependencyConfig {
                name: name.to_string(),
                kind: DependencyKind::AptosFullnode,
                url: redact_url_for_status(&raw_url),
                auth_configured: rpc.api_key_configured(),
                gas_station_configured: Some(rpc.gas_station_configured()),
                expected_chain_id,
            },
            raw_url,
            probe: DependencyProbe::Aptos { rpc },
        }
    }

    pub fn solana(name: &str, url: String, client: reqwest::Client) -> Self {
        Self {
            public: PublicDependencyConfig {
                name: name.to_string(),
                kind: DependencyKind::SolanaRpc,
                url: redact_url_for_status(&url),
                auth_configured: false,
                gas_station_configured: None,
                expected_chain_id: None,
            },
            raw_url: url,
            probe: DependencyProbe::Solana { client },
        }
    }

    pub fn http_json(name: &str, url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(PROBE_TIMEOUT)
            .build()
            .expect("build status HTTP client");
        Self {
            public: PublicDependencyConfig {
                name: name.to_string(),
                kind: DependencyKind::HttpJson,
                url: redact_url_for_status(&url),
                auth_configured: false,
                gas_station_configured: None,
                expected_chain_id: None,
            },
            raw_url: url,
            probe: DependencyProbe::HttpJson { client },
        }
    }

    async fn probe(&self) -> DependencyStatus {
        let started = Instant::now();
        let mut status = DependencyStatus {
            name: self.public.name.clone(),
            kind: self.public.kind,
            url: self.public.url.clone(),
            auth_configured: self.public.auth_configured,
            gas_station_configured: self.public.gas_station_configured,
            expected_chain_id: self.public.expected_chain_id,
            ok: false,
            latency_ms: 0,
            http_status: None,
            observed_chain_id: None,
            detail: None,
        };

        match &self.probe {
            DependencyProbe::Aptos { rpc } => {
                match timeout(PROBE_TIMEOUT, rpc.get_chain_id()).await {
                    Ok(Ok(chain_id)) => {
                        status.observed_chain_id = Some(chain_id);
                        status.ok = self
                            .public
                            .expected_chain_id
                            .map(|expected| expected == chain_id)
                            .unwrap_or(true);
                        if !status.ok {
                            status.detail = Some(format!(
                                "chain_id mismatch: expected {}, observed {}",
                                self.public.expected_chain_id.unwrap_or_default(),
                                chain_id
                            ));
                        }
                    }
                    Ok(Err(e)) => {
                        status.detail = Some(redact_detail(&format!("{:#}", e), &self.raw_url))
                    }
                    Err(_) => status.detail = Some(format!("timed out after {:?}", PROBE_TIMEOUT)),
                }
            }
            DependencyProbe::Solana { client } => {
                let result = timeout(PROBE_TIMEOUT, probe_solana(client, &self.raw_url)).await;
                match result {
                    Ok(Ok((http_status, detail))) => {
                        status.http_status = Some(http_status);
                        status.ok = true;
                        status.detail = detail;
                    }
                    Ok(Err((http_status, detail))) => {
                        status.http_status = http_status;
                        status.detail = Some(detail);
                    }
                    Err(_) => status.detail = Some(format!("timed out after {:?}", PROBE_TIMEOUT)),
                }
            }
            DependencyProbe::HttpJson { client } => {
                let result = timeout(PROBE_TIMEOUT, probe_http_json(client, &self.raw_url)).await;
                match result {
                    Ok(Ok(http_status)) => {
                        status.http_status = Some(http_status);
                        status.ok = true;
                    }
                    Ok(Err((http_status, detail))) => {
                        status.http_status = http_status;
                        status.detail = Some(detail);
                    }
                    Err(_) => status.detail = Some(format!("timed out after {:?}", PROBE_TIMEOUT)),
                }
            }
        }

        status.latency_ms = started.elapsed().as_millis();
        status
    }
}

fn redact_url_for_status(raw: &str) -> String {
    let Ok(mut url) = reqwest::Url::parse(raw) else {
        return raw
            .split(['?', '#'])
            .next()
            .unwrap_or(raw)
            .to_string();
    };
    let _ = url.set_username("");
    let _ = url.set_password(None);
    url.set_query(None);
    url.set_fragment(None);

    if let Some(segments) = url.path_segments() {
        let redacted: Vec<String> = segments
            .map(|segment| {
                if looks_secretish(segment) {
                    "redacted".to_string()
                } else {
                    segment.to_string()
                }
            })
            .collect();
        if let Ok(mut path) = url.path_segments_mut() {
            path.clear();
            for segment in redacted {
                path.push(&segment);
            }
        }
    }

    url.to_string()
}

fn looks_secretish(segment: &str) -> bool {
    segment.len() >= 24
        && segment
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn redact_detail(detail: &str, raw_url: &str) -> String {
    detail.replace(raw_url, &redact_url_for_status(raw_url))
}

async fn probe_solana(
    client: &reqwest::Client,
    url: &str,
) -> Result<(u16, Option<String>), (Option<u16>, String)> {
    let body = json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "getHealth",
    });
    let resp = client
        .post(url)
        .json(&body)
        .send()
        .await
        .map_err(|e| (None, brief_reqwest_error(&e)))?;
    let http_status = resp.status().as_u16();
    if !resp.status().is_success() {
        return Err((Some(http_status), format!("HTTP {}", http_status)));
    }
    let v: Value = resp
        .json()
        .await
        .map_err(|e| (Some(http_status), format!("decode JSON: {}", e)))?;
    if let Some(error) = v.get("error") {
        return Err((Some(http_status), format!("JSON-RPC error: {}", error)));
    }
    let detail = v
        .get("result")
        .and_then(Value::as_str)
        .map(|result| format!("getHealth={}", result));
    Ok((http_status, detail))
}

async fn probe_http_json(
    client: &reqwest::Client,
    url: &str,
) -> Result<u16, (Option<u16>, String)> {
    let resp = client
        .get(url)
        .send()
        .await
        .map_err(|e| (None, brief_reqwest_error(&e)))?;
    let http_status = resp.status().as_u16();
    if !resp.status().is_success() {
        return Err((Some(http_status), format!("HTTP {}", http_status)));
    }
    Ok(http_status)
}

fn brief_reqwest_error(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "HTTP request timed out".to_string()
    } else if e.is_connect() {
        "HTTP connect failed".to_string()
    } else if e.is_decode() {
        "HTTP response decode failed".to_string()
    } else if e.is_request() {
        "HTTP request failed".to_string()
    } else {
        "HTTP error".to_string()
    }
}

pub fn chain_rpc_dependency_targets(chain_rpc: &ChainRpcConfig) -> Vec<DependencyTarget> {
    let mut deps = vec![
        DependencyTarget::aptos("aptos_mainnet_api", chain_rpc.aptos_mainnet.clone(), Some(1)),
        DependencyTarget::aptos("aptos_testnet_api", chain_rpc.aptos_testnet.clone(), Some(2)),
        DependencyTarget::aptos("aptos_localnet_api", chain_rpc.aptos_localnet.clone(), Some(4)),
    ];
    if let Some(rpc) = &chain_rpc.aptos_shelby_private_beta {
        deps.push(DependencyTarget::aptos(
            "aptos_shelby_private_beta_api",
            rpc.clone(),
            Some(125),
        ));
    }
    deps.extend([
        DependencyTarget::solana(
            "solana_mainnet_beta_rpc",
            chain_rpc.solana_mainnet_beta.clone(),
            chain_rpc.solana_client.clone(),
        ),
        DependencyTarget::solana(
            "solana_testnet_rpc",
            chain_rpc.solana_testnet.clone(),
            chain_rpc.solana_client.clone(),
        ),
        DependencyTarget::solana(
            "solana_devnet_rpc",
            chain_rpc.solana_devnet.clone(),
            chain_rpc.solana_client.clone(),
        ),
    ]);
    deps
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_dependency_config_excludes_secret_material() {
        let rpc = AptosRpc::new_with_key(
            "https://aptos.example/v1".to_string(),
            Some("aptoslabs_secret".to_string()),
        );
        let dep = DependencyTarget::aptos("aptos_testnet_api", rpc, Some(2));
        let json = serde_json::to_string(&dep.public).unwrap();
        assert!(json.contains("\"auth_configured\":true"));
        assert!(!json.contains("aptoslabs_secret"));
    }

    #[test]
    fn public_url_redacts_query_userinfo_and_secretish_path_segments() {
        let raw = "https://user:pass@solana.example/v2/abcdefghijklmnopqrstuvwxyz012345?api-key=secret";
        let redacted = redact_url_for_status(raw);
        assert_eq!(redacted, "https://solana.example/v2/redacted");
        assert!(!redacted.contains("secret"));
        assert!(!redacted.contains("user"));
        assert!(!redacted.contains("pass"));
        assert!(!redacted.contains("abcdefghijklmnopqrstuvwxyz012345"));
    }

    #[test]
    fn node_status_copies_dependencies_into_public_config() {
        let dep = DependencyTarget::http_json(
            "maintainer_secrets_api",
            "http://maintainer/secrets".to_string(),
        );
        let status = NodeStatus::new(PublicNodeConfig::new("handler"), vec![dep]);
        assert_eq!(status.public_config.dependencies.len(), 1);
        assert_eq!(
            status.public_config.dependencies[0].name,
            "maintainer_secrets_api"
        );
    }

    #[test]
    fn public_status_exposes_only_version() {
        let status = NodeStatus::new(PublicNodeConfig::new("handler"), Vec::new());
        let json = serde_json::to_value(status.public_response()).unwrap();
        assert_eq!(
            json.as_object().unwrap().keys().collect::<Vec<_>>(),
            vec!["version"]
        );
        assert!(!json.get("dependencies").is_some());
        assert!(!json.get("public_config").is_some());
    }
}
