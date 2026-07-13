// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    sync::{Arc, OnceLock},
};

use anyhow::{anyhow, Result};
use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Router,
};
use ed25519_dalek::SigningKey;
use tokio::sync::{Mutex, RwLock};
use tower_http::cors::CorsLayer;

use vss_common::{
    node_wire::{
        sign_vss_share_request as sign_vss_share_request_wire, verify_vss_share_request,
        NodeRequest, NodeResponse, VssShareRequest, VssShareRequestPayload,
    },
    normalize_account_addr,
    offchain::ShareRequest,
    pke, sig,
};

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

#[derive(Clone, Default)]
pub struct SigKeyRegistry {
    keys: Arc<RwLock<HashMap<String, sig::PublicKey>>>,
    load_locks: Arc<Mutex<HashMap<String, Arc<Mutex<()>>>>>,
}

impl SigKeyRegistry {
    pub async fn register(
        &self,
        worker_addr: impl AsRef<str>,
        public_key: sig::PublicKey,
    ) -> Result<()> {
        public_key.validate()?;
        let worker_addr = normalize_account_addr(worker_addr.as_ref());
        let mut keys = self.keys.write().await;
        if let Some(existing) = keys.get(&worker_addr) {
            if existing != &public_key {
                return Err(anyhow!(
                    "signature verification key for {worker_addr} is already registered differently"
                ));
            }
            return Ok(());
        }
        keys.insert(worker_addr, public_key);
        Ok(())
    }

    pub async fn preload_with<F, Fut>(&self, worker_addr: impl AsRef<str>, load: F) -> Result<()>
    where
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = Result<sig::PublicKey>> + Send,
    {
        let worker_addr = normalize_account_addr(worker_addr.as_ref());
        if self.keys.read().await.contains_key(&worker_addr) {
            return Ok(());
        }

        let load_lock = {
            let mut load_locks = self.load_locks.lock().await;
            load_locks
                .entry(worker_addr.clone())
                .or_insert_with(|| Arc::new(Mutex::new(())))
                .clone()
        };
        let _load_guard = load_lock.lock().await;
        if self.keys.read().await.contains_key(&worker_addr) {
            return Ok(());
        }

        let public_key = load().await?;
        self.register(&worker_addr, public_key).await
    }

    async fn resolve(&self, worker_addr: &str) -> Result<sig::PublicKey> {
        let worker_addr = normalize_account_addr(worker_addr);
        self.keys
            .read()
            .await
            .get(&worker_addr)
            .cloned()
            .ok_or_else(|| anyhow!("signature verification key for {worker_addr} is not preloaded"))
    }

    #[cfg(test)]
    async fn len(&self) -> usize {
        self.keys.read().await.len()
    }
}

#[derive(Clone)]
pub struct GatewayHandle {
    listen: String,
    local_addr: SocketAddr,
    context: GatewayContext,
    sig_keys: SigKeyRegistry,
    vss_share_handler: SharedVssShareHandler,
    worker_handler: SharedWorkerHandler,
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

    pub async fn register_vss_share_handler(&self, handler: Arc<dyn VssShareRequestHandler>) {
        *self.vss_share_handler.write().await = Some(handler);
    }

    pub async fn unregister_vss_share_handler(&self) {
        *self.vss_share_handler.write().await = None;
    }

    pub async fn register_worker_handler(&self, handler: Arc<dyn WorkerRequestHandler>) {
        *self.worker_handler.write().await = Some(handler);
    }

    pub async fn unregister_worker_handler(&self) {
        *self.worker_handler.write().await = None;
    }

    pub async fn preload_sig_verification_key<F, Fut>(
        &self,
        worker_addr: impl AsRef<str>,
        load: F,
    ) -> Result<()>
    where
        F: FnOnce() -> Fut + Send,
        Fut: Future<Output = Result<sig::PublicKey>> + Send,
    {
        self.sig_keys.preload_with(worker_addr, load).await
    }
}

#[derive(Clone, Debug)]
pub struct VerifiedVssShareRequest {
    pub payload: VssShareRequestPayload,
    pub request_id: String,
}

#[derive(Clone, Debug)]
pub struct NodeHandlerError {
    pub status: StatusCode,
    pub detail: String,
}

impl NodeHandlerError {
    pub fn new(status: StatusCode, detail: impl Into<String>) -> Self {
        Self {
            status,
            detail: detail.into(),
        }
    }

    pub fn bad_request(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, detail)
    }

    pub fn internal(detail: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, detail)
    }
}

impl From<anyhow::Error> for NodeHandlerError {
    fn from(value: anyhow::Error) -> Self {
        Self::internal(format!("{value:#}"))
    }
}

#[async_trait]
pub trait VssShareRequestHandler: Send + Sync {
    async fn handle(
        &self,
        request: VerifiedVssShareRequest,
    ) -> std::result::Result<pke::Ciphertext, NodeHandlerError>;
}

#[async_trait]
pub trait WorkerRequestHandler: Send + Sync {
    async fn handle(
        &self,
        request: pke::Ciphertext,
    ) -> std::result::Result<pke::Ciphertext, NodeHandlerError>;
}

type SharedVssShareHandler = Arc<RwLock<Option<Arc<dyn VssShareRequestHandler>>>>;
type SharedWorkerHandler = Arc<RwLock<Option<Arc<dyn WorkerRequestHandler>>>>;

#[derive(Clone)]
struct GatewayState {
    context: GatewayContext,
    sig_keys: SigKeyRegistry,
    vss_share_handler: SharedVssShareHandler,
    worker_handler: SharedWorkerHandler,
}

pub fn build_node_msg_router(
    context: GatewayContext,
    sig_keys: SigKeyRegistry,
    vss_share_handler: Option<Arc<dyn VssShareRequestHandler>>,
    worker_handler: Option<Arc<dyn WorkerRequestHandler>>,
) -> Router {
    build_node_msg_router_with_handlers(
        context,
        sig_keys,
        Arc::new(RwLock::new(vss_share_handler)),
        Arc::new(RwLock::new(worker_handler)),
    )
}

fn build_node_msg_router_with_handlers(
    context: GatewayContext,
    sig_keys: SigKeyRegistry,
    vss_share_handler: SharedVssShareHandler,
    worker_handler: SharedWorkerHandler,
) -> Router {
    let state = GatewayState {
        context,
        sig_keys,
        vss_share_handler,
        worker_handler,
    };
    Router::new()
        .route("/", post(handle_node_request))
        .route("/healthz", get(handle_healthz))
        .with_state(state)
        .layer(CorsLayer::permissive())
}

static NODE_MSG_GATEWAYS: OnceLock<Mutex<HashMap<String, GatewayHandle>>> = OnceLock::new();

pub async fn ensure_node_msg_gateway(
    listen: impl AsRef<str>,
    context: GatewayContext,
) -> Result<GatewayHandle> {
    let listen = listen.as_ref().to_string();
    let gateways = NODE_MSG_GATEWAYS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut gateways = gateways.lock().await;

    if let Some(existing) = gateways.get(&listen) {
        if existing.context != context {
            return Err(anyhow!(
                "node gateway {} already exists for context {:?}, requested {:?}",
                listen,
                existing.context,
                context
            ));
        }
        return Ok(existing.clone());
    }

    let listener = tokio::net::TcpListener::bind(&listen)
        .await
        .map_err(|e| anyhow!("bind node listener {listen}: {e}"))?;
    let local_addr = listener
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    let sig_keys = SigKeyRegistry::default();
    let vss_share_handler = Arc::new(RwLock::new(None));
    let worker_handler = Arc::new(RwLock::new(None));
    let handle = GatewayHandle {
        listen: listen.clone(),
        local_addr,
        context: context.clone(),
        sig_keys: sig_keys.clone(),
        vss_share_handler: vss_share_handler.clone(),
        worker_handler: worker_handler.clone(),
    };
    tokio::spawn(async move {
        if let Err(e) = serve_node_msg_gateway_with_handlers(
            listener,
            context,
            sig_keys,
            vss_share_handler,
            worker_handler,
            std::future::pending::<()>(),
        )
        .await
        {
            eprintln!("node gateway task error: {e:#}");
        }
    });

    gateways.insert(listen, handle.clone());
    Ok(handle)
}

pub async fn serve_node_msg_gateway(
    listener: tokio::net::TcpListener,
    context: GatewayContext,
    sig_keys: SigKeyRegistry,
    vss_share_handler: Option<Arc<dyn VssShareRequestHandler>>,
    worker_handler: Option<Arc<dyn WorkerRequestHandler>>,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    serve_node_msg_gateway_with_handlers(
        listener,
        context,
        sig_keys,
        Arc::new(RwLock::new(vss_share_handler)),
        Arc::new(RwLock::new(worker_handler)),
        shutdown,
    )
    .await
}

async fn serve_node_msg_gateway_with_handlers(
    listener: tokio::net::TcpListener,
    context: GatewayContext,
    sig_keys: SigKeyRegistry,
    vss_share_handler: SharedVssShareHandler,
    worker_handler: SharedWorkerHandler,
    shutdown: impl std::future::Future<Output = ()> + Send + 'static,
) -> Result<()> {
    let local = listener
        .local_addr()
        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
    println!("node gateway: listening on http://{local}");
    axum::serve(
        listener,
        build_node_msg_router_with_handlers(context, sig_keys, vss_share_handler, worker_handler),
    )
    .with_graceful_shutdown(shutdown)
    .await
    .map_err(|e| anyhow!("serve node gateway: {}", e))
}

async fn handle_healthz() -> StatusCode {
    StatusCode::OK
}

async fn handle_node_request(State(state): State<GatewayState>, body: Bytes) -> Response {
    let request: NodeRequest = match bcs::from_bytes(&body) {
        Ok(request) => request,
        Err(e) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("BCS decode NodeRequest failed: {e}"),
            )
                .into_response()
        }
    };

    let response = match request {
        NodeRequest::VssShareRequest(request) => handle_vss_share_request(&state, request).await,
        NodeRequest::WorkerRequest(ciphertext) => handle_worker_request(&state, ciphertext).await,
    };

    match response {
        Ok(response) => match bcs::to_bytes(&response) {
            Ok(bytes) => (StatusCode::OK, bytes).into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("BCS encode NodeResponse failed: {e}"),
            )
                .into_response(),
        },
        Err(e) => (e.status, e.detail).into_response(),
    }
}

async fn handle_vss_share_request(
    state: &GatewayState,
    request: VssShareRequest,
) -> std::result::Result<NodeResponse, NodeHandlerError> {
    let handler = { state.vss_share_handler.read().await.clone() };
    let Some(handler) = handler else {
        return Err(NodeHandlerError::new(
            StatusCode::NOT_FOUND,
            "VSS share request handler is not registered",
        ));
    };

    let payload = request.payload.clone();
    if payload.recipient != state.context.recipient_addr {
        return Err(NodeHandlerError::new(
            StatusCode::UNAUTHORIZED,
            format!(
                "VSS share request recipient {} does not match this node {}",
                payload.recipient, state.context.recipient_addr
            ),
        ));
    }

    let public_key = state.sig_keys.resolve(&payload.sender).await.map_err(|e| {
        NodeHandlerError::new(
            StatusCode::UNAUTHORIZED,
            format!("resolve sender sig key: {e:#}"),
        )
    })?;
    let signature_ok = verify_vss_share_request(
        state.context.chain_id,
        &state.context.ace_addr,
        &public_key,
        &request,
    )
    .map_err(|e| NodeHandlerError::bad_request(format!("verify VSS share request: {e:#}")))?;
    if !signature_ok {
        return Err(NodeHandlerError::new(
            StatusCode::UNAUTHORIZED,
            format!(
                "invalid VSS share request signature from {}",
                payload.sender
            ),
        ));
    }

    let request_id = payload.request_id().map_err(|e| {
        NodeHandlerError::bad_request(format!("compute VSS share request ID: {e:#}"))
    })?;
    let ciphertext = handler
        .handle(VerifiedVssShareRequest {
            payload,
            request_id,
        })
        .await?;
    Ok(NodeResponse::VssShareResponse(ciphertext))
}

async fn handle_worker_request(
    state: &GatewayState,
    request: pke::Ciphertext,
) -> std::result::Result<NodeResponse, NodeHandlerError> {
    let handler = { state.worker_handler.read().await.clone() };
    let Some(handler) = handler else {
        return Err(NodeHandlerError::new(
            StatusCode::NOT_FOUND,
            "worker request handler is not registered",
        ));
    };
    let ciphertext = handler.handle(request).await?;
    Ok(NodeResponse::WorkerResponse(ciphertext))
}

pub fn sign_vss_share_request(
    context: &GatewayContext,
    signing_key: &SigningKey,
    sender_addr: impl AsRef<str>,
    share_request: ShareRequest,
) -> Result<VssShareRequest> {
    let payload = VssShareRequestPayload::new(
        sender_addr,
        &context.recipient_addr,
        share_request.session_addr,
        share_request.holder_index,
        share_request.response_enc_key,
    );
    sign_vss_share_request_wire(context.chain_id, &context.ace_addr, signing_key, payload)
}

pub async fn send_node_request(
    endpoint: impl AsRef<str>,
    request: &NodeRequest,
) -> Result<NodeResponse> {
    let url = endpoint.as_ref().trim_end_matches('/').to_string();
    let request_bytes =
        bcs::to_bytes(request).map_err(|e| anyhow!("BCS encode NodeRequest: {e}"))?;
    let response = reqwest::Client::new()
        .post(url)
        .body(request_bytes)
        .send()
        .await?;
    let status = response.status();
    let body = response.bytes().await?;
    if !status.is_success() {
        return Err(anyhow!(
            "node request failed with {status}: {}",
            String::from_utf8_lossy(&body)
        ));
    }
    bcs::from_bytes(&body).map_err(|e| anyhow!("BCS decode NodeResponse: {e}"))
}

pub async fn send_vss_share_request(
    endpoint: impl AsRef<str>,
    request: &VssShareRequest,
) -> Result<pke::Ciphertext> {
    match send_node_request(endpoint, &NodeRequest::VssShareRequest(request.clone())).await? {
        NodeResponse::VssShareResponse(ciphertext) => Ok(ciphertext),
        NodeResponse::WorkerResponse(_) => {
            Err(anyhow!("node returned WorkerResponse to VSS request"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::time::{sleep, Duration};

    #[derive(Clone, Default)]
    struct EchoWorkerHandler;

    #[async_trait]
    impl WorkerRequestHandler for EchoWorkerHandler {
        async fn handle(
            &self,
            request: pke::Ciphertext,
        ) -> std::result::Result<pke::Ciphertext, NodeHandlerError> {
            Ok(request)
        }
    }

    fn context() -> GatewayContext {
        GatewayContext::new(4, "0xace", "0x2222")
    }

    fn dummy_ciphertext() -> pke::Ciphertext {
        pke::Ciphertext::HpkeX25519ChaCha20Poly1305(
            vss_common::pke_hpke_x25519_chacha20poly1305::Ciphertext {
                enc: vec![1u8; 32],
                aead_ct: b"hello".to_vec(),
            },
        )
    }

    #[tokio::test]
    async fn worker_message_round_trips_through_gateway() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve_node_msg_gateway(
            listener,
            context(),
            SigKeyRegistry::default(),
            None,
            Some(Arc::new(EchoWorkerHandler)),
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        let ciphertext = dummy_ciphertext();
        let response = send_node_request(endpoint, &NodeRequest::WorkerRequest(ciphertext.clone()))
            .await
            .unwrap();
        match response {
            NodeResponse::WorkerResponse(returned) => {
                assert_eq!(
                    bcs::to_bytes(&returned).unwrap(),
                    bcs::to_bytes(&ciphertext).unwrap()
                );
            }
            NodeResponse::VssShareResponse(_) => panic!("unexpected VSS response"),
        }

        let _ = shutdown_tx.send(());
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn ensure_gateway_reuses_existing_listener() {
        let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let listen = probe.local_addr().unwrap().to_string();
        drop(probe);

        let first = ensure_node_msg_gateway(&listen, context()).await.unwrap();
        let second = ensure_node_msg_gateway(&listen, context()).await.unwrap();
        assert_eq!(first.local_addr(), second.local_addr());
    }

    #[tokio::test]
    async fn rejects_wrong_vss_signature() {
        #[derive(Clone, Default)]
        struct UnusedVssHandler;

        #[async_trait]
        impl VssShareRequestHandler for UnusedVssHandler {
            async fn handle(
                &self,
                _request: VerifiedVssShareRequest,
            ) -> std::result::Result<pke::Ciphertext, NodeHandlerError> {
                Ok(dummy_ciphertext())
            }
        }

        let good_sk = SigningKey::from_bytes(&[7u8; 32]);
        let bad_sk = SigningKey::from_bytes(&[8u8; 32]);
        let sender = normalize_account_addr("0x1111");
        let sig_keys = SigKeyRegistry::default();
        sig_keys
            .register(
                &sender,
                sig::PublicKey::from_ed25519_verifying_key(&good_sk.verifying_key()),
            )
            .await
            .unwrap();
        let share_request = ShareRequest {
            session_addr: normalize_account_addr("0x3333"),
            holder_index: 0,
            response_enc_key: vss_common::pke::EncryptionKey::HpkeX25519ChaCha20Poly1305(
                vss_common::pke_hpke_x25519_chacha20poly1305::keygen().0,
            ),
        };
        let request = sign_vss_share_request(&context(), &bad_sk, &sender, share_request).unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
        let server = tokio::spawn(serve_node_msg_gateway(
            listener,
            context(),
            sig_keys,
            Some(Arc::new(UnusedVssHandler)),
            None,
            async move {
                let _ = shutdown_rx.await;
            },
        ));

        let err = send_node_request(endpoint, &NodeRequest::VssShareRequest(request))
            .await
            .unwrap_err();
        assert!(err
            .to_string()
            .contains("invalid VSS share request signature"));

        let _ = shutdown_tx.send(());
        server.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn concurrent_preloads_fetch_each_key_once() {
        let sig_keys = SigKeyRegistry::default();
        let sender = normalize_account_addr("0x1111");
        let public_key = sig::PublicKey::from_ed25519_verifying_key(
            &SigningKey::from_bytes(&[11u8; 32]).verifying_key(),
        );
        let load_count = Arc::new(AtomicUsize::new(0));
        let mut tasks = Vec::new();

        for _ in 0..16 {
            let sig_keys = sig_keys.clone();
            let sender = sender.clone();
            let public_key = public_key.clone();
            let load_count = load_count.clone();
            tasks.push(tokio::spawn(async move {
                sig_keys
                    .preload_with(&sender, || async move {
                        load_count.fetch_add(1, Ordering::SeqCst);
                        sleep(Duration::from_millis(20)).await;
                        Ok(public_key)
                    })
                    .await
            }));
        }

        for task in tasks {
            task.await.unwrap().unwrap();
        }
        assert_eq!(load_count.load(Ordering::SeqCst), 1);
        assert_eq!(sig_keys.len().await, 1);
    }
}
