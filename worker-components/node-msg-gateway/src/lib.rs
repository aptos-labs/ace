// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, OnceLock},
};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, RwLock};

use vss_common::{
    normalize_account_addr,
    sig::{self, sign_ed25519},
    AptosRpc,
};

const NODE_MSG_DOMAIN: &[u8] = b"ace::node-msg-gateway::v1";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GatewayContext {
    pub chain_id: u8,
    pub ace_addr: String,
    pub recipient_addr: String,
}

impl GatewayContext {
    pub fn new(chain_id: u8, ace_addr: impl AsRef<str>, recipient_addr: impl AsRef<str>) -> Self {
        Self {
            chain_id,
            ace_addr: normalize_account_addr(ace_addr.as_ref()),
            recipient_addr: normalize_account_addr(recipient_addr.as_ref()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NodeMsgRoute {
    pub protocol: String,
    pub route: String,
}

impl NodeMsgRoute {
    pub fn new(protocol: impl Into<String>, route: impl Into<String>) -> Self {
        Self {
            protocol: protocol.into(),
            route: route.into(),
        }
    }
}

pub type HandlerMap = HashMap<NodeMsgRoute, Arc<dyn NodeMessageHandler>>;
type SharedHandlerMap = Arc<RwLock<HandlerMap>>;

#[derive(Clone)]
pub struct GatewayHandle {
    listen: String,
    local_addr: SocketAddr,
    context: GatewayContext,
    handlers: SharedHandlerMap,
}

impl GatewayHandle {
    pub fn listen(&self) -> &str {
        &self.listen
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn context(&self) -> &GatewayContext {
        &self.context
    }

    pub async fn register_handler(
        &self,
        route: NodeMsgRoute,
        handler: Arc<dyn NodeMessageHandler>,
    ) {
        self.handlers.write().await.insert(route, handler);
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedNodeMessage {
    pub sender: String,
    pub recipient: String,
    pub protocol: String,
    pub route: String,
    pub request_id: String,
    pub body_bcs_hex: String,
    pub signature_bcs_hex: String,
}

#[derive(Clone, Debug)]
pub struct VerifiedNodeMessage {
    pub sender: String,
    pub recipient: String,
    pub protocol: String,
    pub route: String,
    pub request_id: String,
    pub body_bcs: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeMessageResponse {
    pub body_bcs_hex: String,
}

#[async_trait]
pub trait SigKeyResolver: Send + Sync {
    async fn resolve_sig_verification_key(&self, worker_addr: &str) -> Result<sig::PublicKey>;
}

#[derive(Clone, Debug)]
pub struct StaticSigKeyResolver {
    keys: Arc<HashMap<String, sig::PublicKey>>,
}

impl StaticSigKeyResolver {
    pub fn new(keys: HashMap<String, sig::PublicKey>) -> Self {
        let keys = keys
            .into_iter()
            .map(|(addr, pk)| (normalize_account_addr(&addr), pk))
            .collect();
        Self {
            keys: Arc::new(keys),
        }
    }
}

#[async_trait]
impl SigKeyResolver for StaticSigKeyResolver {
    async fn resolve_sig_verification_key(&self, worker_addr: &str) -> Result<sig::PublicKey> {
        let addr = normalize_account_addr(worker_addr);
        self.keys
            .get(&addr)
            .cloned()
            .ok_or_else(|| anyhow!("missing static signature verification key for {addr}"))
    }
}

#[derive(Clone)]
pub struct AptosSigKeyResolver {
    rpc: AptosRpc,
    ace_addr: String,
}

impl AptosSigKeyResolver {
    pub fn new(rpc: AptosRpc, ace_addr: impl AsRef<str>) -> Self {
        Self {
            rpc,
            ace_addr: normalize_account_addr(ace_addr.as_ref()),
        }
    }
}

#[async_trait]
impl SigKeyResolver for AptosSigKeyResolver {
    async fn resolve_sig_verification_key(&self, worker_addr: &str) -> Result<sig::PublicKey> {
        self.rpc
            .get_sig_verification_key_bcs(&self.ace_addr, &normalize_account_addr(worker_addr))
            .await
    }
}

#[async_trait]
pub trait NodeMessageHandler: Send + Sync {
    async fn handle(&self, message: VerifiedNodeMessage) -> Result<Vec<u8>>;
}

#[derive(Clone, Default)]
pub struct EchoHandler;

#[async_trait]
impl NodeMessageHandler for EchoHandler {
    async fn handle(&self, message: VerifiedNodeMessage) -> Result<Vec<u8>> {
        Ok(message.body_bcs)
    }
}

#[derive(Clone)]
struct GatewayState {
    context: GatewayContext,
    sig_keys: Arc<dyn SigKeyResolver>,
    handlers: SharedHandlerMap,
}

pub fn build_node_msg_router(
    context: GatewayContext,
    sig_keys: Arc<dyn SigKeyResolver>,
    handlers: HandlerMap,
) -> Router {
    build_node_msg_router_with_handlers(context, sig_keys, Arc::new(RwLock::new(handlers)))
}

fn build_node_msg_router_with_handlers(
    context: GatewayContext,
    sig_keys: Arc<dyn SigKeyResolver>,
    handlers: SharedHandlerMap,
) -> Router {
    let state = GatewayState {
        context,
        sig_keys,
        handlers,
    };
    Router::new()
        .route("/node-msg", post(handle_node_msg))
        .with_state(state)
}

static NODE_MSG_GATEWAYS: OnceLock<Mutex<HashMap<String, GatewayHandle>>> = OnceLock::new();

pub async fn ensure_node_msg_gateway(
    listen: impl AsRef<str>,
    context: GatewayContext,
    sig_keys: Arc<dyn SigKeyResolver>,
) -> Result<GatewayHandle> {
    let listen = listen.as_ref().to_string();
    let gateways = NODE_MSG_GATEWAYS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut gateways = gateways.lock().await;

    if let Some(existing) = gateways.get(&listen) {
        if existing.context != context {
            return Err(anyhow!(
                "node-msg gateway {} already exists for context {:?}, requested {:?}",
                listen,
                existing.context,
                context
            ));
        }
        return Ok(existing.clone());
    }

    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .map_err(|e| anyhow!("bind node-msg listener {listen}: {e}"))?;
    let local_addr = listener
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    let handlers = Arc::new(RwLock::new(HashMap::new()));
    let handle = GatewayHandle {
        listen: listen.clone(),
        local_addr,
        context: context.clone(),
        handlers: handlers.clone(),
    };
    tokio::spawn(async move {
        if let Err(e) = serve_node_msg_gateway_with_handlers(
            listener,
            context,
            sig_keys,
            handlers,
            std::future::pending::<()>(),
        )
        .await
        {
            eprintln!("node-msg gateway task error: {e:#}");
        }
    });

    gateways.insert(listen, handle.clone());
    Ok(handle)
}

pub async fn serve_node_msg_gateway(
    listener: tokio::net::TcpListener,
    context: GatewayContext,
    sig_keys: Arc<dyn SigKeyResolver>,
    handlers: HandlerMap,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    serve_node_msg_gateway_with_handlers(
        listener,
        context,
        sig_keys,
        Arc::new(RwLock::new(handlers)),
        shutdown,
    )
    .await
}

async fn serve_node_msg_gateway_with_handlers(
    listener: tokio::net::TcpListener,
    context: GatewayContext,
    sig_keys: Arc<dyn SigKeyResolver>,
    handlers: SharedHandlerMap,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let local = listener
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    println!("node-msg gateway: listening on http://{local}");
    axum::serve(
        listener,
        build_node_msg_router_with_handlers(context, sig_keys, handlers),
    )
    .with_graceful_shutdown(shutdown)
    .await
    .map_err(|e| anyhow!("serve node-msg gateway: {}", e))
}

async fn handle_node_msg(
    State(state): State<GatewayState>,
    Json(message): Json<SignedNodeMessage>,
) -> Response {
    match verify_signed_node_message(&state.context, state.sig_keys.as_ref(), message).await {
        Ok(verified) => {
            let route = NodeMsgRoute::new(verified.protocol.clone(), verified.route.clone());
            let handler = { state.handlers.read().await.get(&route).cloned() };
            match handler {
                Some(handler) => match handler.handle(verified).await {
                    Ok(body) => Json(NodeMessageResponse {
                        body_bcs_hex: encode_hex(&body),
                    })
                    .into_response(),
                    Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")).into_response(),
                },
                None => (StatusCode::NOT_FOUND, "node-msg route not registered").into_response(),
            }
        }
        Err(e) => (StatusCode::UNAUTHORIZED, format!("{e:#}")).into_response(),
    }
}

pub fn sign_node_message(
    context: &GatewayContext,
    signing_key: &SigningKey,
    sender_addr: impl AsRef<str>,
    protocol: impl Into<String>,
    route: impl Into<String>,
    request_id: impl Into<String>,
    body_bcs: Vec<u8>,
) -> Result<SignedNodeMessage> {
    let sender = normalize_account_addr(sender_addr.as_ref());
    let message = UnsignedNodeMessage {
        sender,
        recipient: context.recipient_addr.clone(),
        protocol: protocol.into(),
        route: route.into(),
        request_id: request_id.into(),
        body_bcs,
    };
    let signing_bytes = node_msg_signing_bytes(context, &message)?;
    let signature = sign_ed25519(signing_key, &signing_bytes);
    Ok(SignedNodeMessage {
        sender: message.sender,
        recipient: message.recipient,
        protocol: message.protocol,
        route: message.route,
        request_id: message.request_id,
        body_bcs_hex: encode_hex(&message.body_bcs),
        signature_bcs_hex: encode_hex(&signature.to_bytes()),
    })
}

pub async fn send_signed_node_message(
    endpoint: impl AsRef<str>,
    message: &SignedNodeMessage,
) -> Result<Vec<u8>> {
    let url = format!("{}/node-msg", endpoint.as_ref().trim_end_matches('/'));
    let response = reqwest::Client::new()
        .post(url)
        .json(message)
        .send()
        .await?;
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        return Err(anyhow!("node-msg request failed with {status}: {body}"));
    }
    let body: NodeMessageResponse = response.json().await?;
    decode_hex(&body.body_bcs_hex, "response body_bcs_hex")
}

async fn verify_signed_node_message(
    context: &GatewayContext,
    resolver: &dyn SigKeyResolver,
    message: SignedNodeMessage,
) -> Result<VerifiedNodeMessage> {
    let unsigned = UnsignedNodeMessage {
        sender: normalize_account_addr(&message.sender),
        recipient: normalize_account_addr(&message.recipient),
        protocol: message.protocol,
        route: message.route,
        request_id: message.request_id,
        body_bcs: decode_hex(&message.body_bcs_hex, "body_bcs_hex")?,
    };

    if unsigned.recipient != context.recipient_addr {
        return Err(anyhow!(
            "node-msg recipient {} does not match this node {}",
            unsigned.recipient,
            context.recipient_addr
        ));
    }

    let signature = sig::Signature::from_bytes(&decode_hex(
        &message.signature_bcs_hex,
        "signature_bcs_hex",
    )?)?;
    let signing_bytes = node_msg_signing_bytes(context, &unsigned)?;
    let public_key = resolver
        .resolve_sig_verification_key(&unsigned.sender)
        .await?;
    if !public_key.verify(&signing_bytes, &signature)? {
        return Err(anyhow!(
            "invalid node-msg signature from {}",
            unsigned.sender
        ));
    }

    Ok(VerifiedNodeMessage {
        sender: unsigned.sender,
        recipient: unsigned.recipient,
        protocol: unsigned.protocol,
        route: unsigned.route,
        request_id: unsigned.request_id,
        body_bcs: unsigned.body_bcs,
    })
}

#[derive(Clone, Debug)]
struct UnsignedNodeMessage {
    sender: String,
    recipient: String,
    protocol: String,
    route: String,
    request_id: String,
    body_bcs: Vec<u8>,
}

#[derive(Serialize)]
struct NodeMessageToSign {
    domain: Vec<u8>,
    chain_id: u8,
    ace_addr: Vec<u8>,
    sender: Vec<u8>,
    recipient: Vec<u8>,
    protocol: String,
    route: String,
    request_id: String,
    body_bcs: Vec<u8>,
}

fn node_msg_signing_bytes(
    context: &GatewayContext,
    message: &UnsignedNodeMessage,
) -> Result<Vec<u8>> {
    let to_sign = NodeMessageToSign {
        domain: NODE_MSG_DOMAIN.to_vec(),
        chain_id: context.chain_id,
        ace_addr: address_bytes(&context.ace_addr)?.to_vec(),
        sender: address_bytes(&message.sender)?.to_vec(),
        recipient: address_bytes(&message.recipient)?.to_vec(),
        protocol: message.protocol.clone(),
        route: message.route.clone(),
        request_id: message.request_id.clone(),
        body_bcs: message.body_bcs.clone(),
    };
    bcs::to_bytes(&to_sign).map_err(|e| anyhow!("BCS encode node-msg signing payload: {}", e))
}

fn address_bytes(addr: &str) -> Result<[u8; 32]> {
    let normalized = normalize_account_addr(addr);
    let raw = hex::decode(normalized.trim_start_matches("0x"))?;
    raw.try_into()
        .map_err(|v: Vec<u8>| anyhow!("address must be 32 bytes, got {}", v.len()))
}

fn encode_hex(bytes: &[u8]) -> String {
    format!("0x{}", hex::encode(bytes))
}

fn decode_hex(input: &str, label: &str) -> Result<Vec<u8>> {
    hex::decode(input.trim_start_matches("0x")).map_err(|e| anyhow!("decode {label}: {}", e))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn context() -> GatewayContext {
        GatewayContext::new(4, "0xace", "0x2222")
    }

    #[tokio::test]
    async fn signed_message_round_trips_through_gateway() {
        let sk = SigningKey::from_bytes(&[9u8; 32]);
        let sender = normalize_account_addr("0x1111");
        let mut keys = HashMap::new();
        keys.insert(
            sender.clone(),
            sig::PublicKey::from_ed25519_verifying_key(&sk.verifying_key()),
        );

        let mut handlers: HandlerMap = HashMap::new();
        handlers.insert(NodeMsgRoute::new("system", "ping"), Arc::new(EchoHandler));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve_node_msg_gateway(
            listener,
            context(),
            Arc::new(StaticSigKeyResolver::new(keys)),
            handlers,
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        let msg = sign_node_message(
            &context(),
            &sk,
            sender,
            "system",
            "ping",
            "req-1",
            b"hello".to_vec(),
        )
        .unwrap();
        let response = send_signed_node_message(endpoint, &msg).await.unwrap();
        assert_eq!(response, b"hello");

        let _ = shutdown_tx.send(());
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn ensure_gateway_reuses_existing_listener() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = probe.local_addr().unwrap().to_string();
        drop(probe);

        let sk = SigningKey::from_bytes(&[10u8; 32]);
        let sender = normalize_account_addr("0x1111");
        let mut keys = HashMap::new();
        keys.insert(
            sender.clone(),
            sig::PublicKey::from_ed25519_verifying_key(&sk.verifying_key()),
        );

        let first = ensure_node_msg_gateway(
            &listen,
            context(),
            Arc::new(StaticSigKeyResolver::new(keys.clone())),
        )
        .await
        .unwrap();
        let second = ensure_node_msg_gateway(
            &listen,
            context(),
            Arc::new(StaticSigKeyResolver::new(keys)),
        )
        .await
        .unwrap();
        assert_eq!(first.local_addr(), second.local_addr());
    }

    #[tokio::test]
    async fn rejects_wrong_signature() {
        let good_sk = SigningKey::from_bytes(&[7u8; 32]);
        let bad_sk = SigningKey::from_bytes(&[8u8; 32]);
        let sender = normalize_account_addr("0x1111");
        let mut keys = HashMap::new();
        keys.insert(
            sender.clone(),
            sig::PublicKey::from_ed25519_verifying_key(&good_sk.verifying_key()),
        );
        let msg = sign_node_message(
            &context(),
            &bad_sk,
            sender,
            "system",
            "ping",
            "req-1",
            b"hello".to_vec(),
        )
        .unwrap();

        let err = verify_signed_node_message(&context(), &StaticSigKeyResolver::new(keys), msg)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("invalid node-msg signature"));
    }
}
