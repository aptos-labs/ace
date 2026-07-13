# Node Message Signatures (`sig::*`)

ACE uses Ed25519 signatures to authenticate node-to-node protocol messages.
This is separate from Aptos account signatures: a worker account key signs
on-chain transactions, while the node-message signing key signs off-chain
messages such as VSS share requests.

## 1. Keys and Registration

Each operator has one node-message signing key pair in addition to its worker
account key and PKE key.

- The private key is passed to clients as `--sig-sk` / `ACE_SIG_SK`.
- The public verification key is registered on chain through
  `worker_config::register_sig_verification_key`.
- The node-message HTTP endpoint is registered through
  `worker_config::register_node_msg_endpoint`.

The on-chain `sig` package stores the BCS enum `sig::PublicKey`; the current
variant is Ed25519 only. The public key payload is the raw 32-byte Ed25519
verification key.

## 2. Signed VSS Share Requests

The node HTTP server accepts BCS `NodeRequest` bytes at `POST /`. The VSS
variant is signed directly:

```rust
enum NodeRequest {
    VssShareRequest(VssShareRequest), // tag 0
    WorkerRequest(pke::Ciphertext),   // tag 1
}

struct VssShareRequest {
    payload: VssShareRequestPayload,
    sig: sig::Signature,
}

struct VssShareRequestPayload {
    sender: String,
    recipient: String,
    session_addr: String,
    holder_index: u64,
    response_enc_key: pke::EncryptionKey,
}
```

The signature covers the BCS encoding of:

```rust
struct VssShareRequestToSign {
    domain: Vec<u8>,       // b"ace::node-request::vss-share-request::v1"
    chain_id: u8,
    ace_addr: Vec<u8>,     // 32-byte ACE package address
    sender: Vec<u8>,       // 32-byte worker address
    recipient: Vec<u8>,    // 32-byte worker address
    session_addr: Vec<u8>, // 32-byte VSS session address
    holder_index: u64,
    response_enc_key: pke::EncryptionKey,
}
```

The recipient gateway:

1. Checks the `recipient` matches its own worker address.
2. Looks up the sender's `sig::PublicKey` in its in-memory registry.
3. Verifies the Ed25519 signature over the domain-separated signing bytes.
4. Dispatches to its registered VSS share handler.

Protocol clients populate the registry before enabling their request-serving
state. For VSS, concurrent dealer clients single-flight the initial
`worker_config` reads, then retain the immutable registered keys for the
gateway process lifetime. A request whose key has not been preloaded is rejected
immediately; request handling never fetches a key from chain or DB.

The signature does not make the transport private. VSS separately encrypts the
share-response body to a request-scoped HPKE key, but node-message metadata
remains visible. Deployments still need ordinary endpoint protections for
availability, rate limiting, and metadata exposure.

## 3. Implementation Map

- Move signature type: `contracts/sig/sources/sig.move`,
  `contracts/sig/sources/sig_ed25519.move`
- Worker config registration: `contracts/worker_config/sources/worker_config.move`
- Rust signature mirror: `worker-components/vss-common/src/sig.rs`
- Node-message gateway: `worker-components/node-msg-gateway/src/lib.rs`
- TypeScript signature mirror: `ts-sdk/src/sig/index.ts`
