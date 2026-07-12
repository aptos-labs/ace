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

## 2. Signed Node Messages

The node-message gateway accepts JSON at `POST /node-msg`:

```rust
struct SignedNodeMessage {
    sender: String,
    recipient: String,
    protocol: String,
    route: String,
    request_id: String,
    body_bcs_hex: String,
    signature_bcs_hex: String,
}
```

The signature covers the BCS encoding of:

```rust
struct NodeMessageToSign {
    domain: Vec<u8>,       // b"ace::node-msg-gateway::v1"
    chain_id: u8,
    ace_addr: Vec<u8>,     // 32-byte ACE package address
    sender: Vec<u8>,       // 32-byte worker address
    recipient: Vec<u8>,    // 32-byte worker address
    protocol: String,
    route: String,
    request_id: String,
    body_bcs: Vec<u8>,
}
```

The recipient gateway:

1. Checks the `recipient` matches its own worker address.
2. Fetches the sender's registered `sig::PublicKey` from `worker_config`.
3. Verifies the Ed25519 signature over the domain-separated signing bytes.
4. Dispatches to a registered `(protocol, route)` handler.

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
