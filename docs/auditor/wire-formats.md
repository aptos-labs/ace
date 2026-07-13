# ACE Wire Formats

ACE wire formats use Aptos BCS unless explicitly stated otherwise. Rust structs derive `Serialize` / `Deserialize`; TypeScript mirrors the same field order.

## BCS Primer

| Type | BCS encoding |
|------|--------------|
| `u8` | 1 raw byte |
| `u64` | 8 little-endian bytes |
| `[u8; N]` | N raw bytes |
| `Vec<u8>` | `ULEB128(len) || bytes` |
| `String` | `ULEB128(len) || UTF-8 bytes` |
| `Option<T>` | `00` for none, `01 || T` for some |
| `enum` | `ULEB128(variant_index) || fields` |
| `struct` | fields in declaration order |

## PKE

Defined in `worker-components/vss-common/src/pke.rs` and mirrored in `ts-sdk/src/pke`.

```rust
enum EncryptionKey {
    ElGamalOtpRistretto255(ElGamalOtpRistretto255EncKey), // tag 0
    HpkeX25519ChaCha20Poly1305(HpkeEncryptionKey),        // tag 1
}

enum Ciphertext {
    ElGamalOtpRistretto255(ElGamalOtpRistretto255Ciphertext), // tag 0
    HpkeX25519ChaCha20Poly1305(HpkeCiphertext),               // tag 1
}
```

HPKE encryption keys are `01 || 20 || 32B pk`. HPKE ciphertexts are `01 || 20 || 32B enc || ULEB(L) || L bytes aead_ct`.

## Node-Message Signatures

Defined in `contracts/sig`, `worker-components/vss-common/src/sig.rs`, and
`ts-sdk/src/sig`.

```rust
enum sig::PublicKey {
    Ed25519(Ed25519PublicKey), // tag 0
}

struct Ed25519PublicKey {
    bytes: Vec<u8>,            // exactly 32 bytes
}

enum sig::Signature {
    Ed25519(Ed25519Signature), // tag 0
}

struct Ed25519Signature {
    bytes: Vec<u8>,            // exactly 64 bytes
}
```

The current Ed25519 public key bytes are `00 || 20 || 32B pk`. The current
signature bytes are `00 || 40 || 64B sig`.

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

`signature_bcs_hex` is the BCS `sig::Signature` over the BCS
`NodeMessageToSign` described in [`cryptography/sig.md`](./cryptography/sig.md).
Before serving a VSS session, the dealer client loads its holders' keys from
the holders' `worker_config::SigVerificationKey` resources into the gateway.
The request path verifies the sender against that in-memory registry without a
chain read.

## Off-Chain VSS Share Request

The VSS recipient asks the dealer's node-message gateway for its share with:

```rust
struct ShareRequest {
    session_addr: String,
    holder_index: u64, // zero-based index in vss::Session.share_holders
    response_enc_key: pke::EncryptionKey, // fresh HPKE-X25519 key
}
```

The message route is `(protocol = "vss", route = "share-request")`. The gateway
checks that the signed sender equals `share_holders[holder_index]`; the dealer
then returns `BCS(pke::Ciphertext::HpkeX25519ChaCha20Poly1305)`. The encrypted
plaintext is the BCS bytes of a `pedersen_polynomial_commitment::Opening` for
evaluation position `holder_index + 1`.

The canonical request ID is `vss-share:` followed by the hex-encoded,
domain-separated SHA-256 hash of `BCS(ShareRequest)`. The dealer rejects an
envelope whose signed request ID does not match its request body.

The HPKE AAD is the BCS encoding of the domain
`ace::vss::share-response::v1` together with the signed message's sender,
recipient, request ID, and complete `ShareRequest`. This binds the encrypted
opening to the complete share request transcript.

The recipient decrypts with the request's ephemeral key, verifies the returned
opening against the on-chain PCS context and DC0 commitment, and only then
submits the on-chain ACK transaction.

## Worker Request

The HTTP request body is a hex string of `pke_encrypt(worker_enc_key, BCS(WorkerRequest))`.

```rust
enum WorkerRequest {
    DecryptionBasicFlow(DecryptionBasicFlowRequest),   // tag 0
    DecryptionCustomFlow(DecryptionCustomFlowRequest), // tag 1
    ThresholdVrf(ThresholdVrfRequest),                 // tag 2
}

struct DecryptionRequestPayload {
    keypair_id: [u8; 32],
    epoch: u64,
    contract_id: ContractId,
    domain: Vec<u8>,
    ephemeral_enc_key: EncryptionKey,
}

struct DecryptionBasicFlowRequest {
    payload: DecryptionRequestPayload,
    proof: ProofOfPermission,
    tibe_scheme: u8,
}

struct DecryptionCustomFlowRequest {
    keypair_id: [u8; 32],
    epoch: u64,
    contract_id: ContractId,
    label: Vec<u8>,
    enc_pk: EncryptionKey,
    proof: CustomFlowProof,
    tibe_scheme: u8,
}

struct ThresholdVrfRequestPayload {
    keypair_id: [u8; 32],
    epoch: u64,
    contract_id: ContractId,
    label: Vec<u8>,
    account_address: [u8; 32],
    response_enc_key: EncryptionKey,
}

struct ThresholdVrfRequest {
    payload: ThresholdVrfRequestPayload,
    auth_proof: AptosProofOfPermission,
}

enum ContractId {
    Aptos(AptosContractId), // tag 0
}

struct AptosContractId {
    chain_id: u8,
    module_addr: [u8; 32],
    module_name: String,
}
```

`AptosProofOfPermission` is the shared Aptos account proof format used by the worker verifier. It carries account address, public-key scheme, public key, signature scheme, signature, and full wallet message.

For Aptos-only IBE, `ProofOfPermission` and `CustomFlowProof` are single-variant
BCS enums (tag `0`). The IBE identity is raw `keypair_id` followed by
`BCS(contract_id)` and `BCS(domain_or_label)`.

## Worker Response

The HTTP response body is a hex string of `BCS(pke_encrypt(response_enc_key, BCS(ThresholdVrfShare)))`.

For IBE requests, the encrypted plaintext is `BCS(IdentityDecryptionKeyShare)`:

```rust
enum IdentityDecryptionKeyShare {
    BfibeBls12381ShortPkOtpHmac(ShortPkIdentityDecryptionKeyShare), // tag 0
    BfibeBls12381ShortSigAead(ShortSigIdentityDecryptionKeyShare),  // tag 1
}

struct ShortPkIdentityDecryptionKeyShare {
    eval_point: BcsFixedBytes<32>,
    idk_share: BcsFixedBytes<96>, // compressed G2 encoding
}

struct ShortSigIdentityDecryptionKeyShare {
    eval_point: BcsFixedBytes<32>,
    idk_share: BcsFixedBytes<48>, // compressed G1 encoding
}
```

The enum discriminants are the scheme tags consumed by the TypeScript SDK.
`BcsFixedBytes<N>` serializes as a BCS byte vector. Both Rust and TypeScript first
parse this wire representation with only exact-length checks; neither decoder
decompresses or validates a curve point. The SDK then checks the response scheme
and the holder's expected evaluation point before explicitly materializing the
curve point and performing pairing verification against the public share-PK.
There is no separate IBE share proof field; the SDK verifies each share against
its public share-PK by pairing. The complete outer encoding is 131 bytes for
scheme 0 and 83 bytes for scheme 1. Rust and TypeScript consume the shared golden vectors in
`test-vectors/identity-decryption-key-share.json`.

```rust
struct ThresholdVrfShare {
    eval_point: u64,
    share: group::Element,
    proof: ThresholdVrfShareProof,
}

struct ThresholdVrfShareProof {
    commitment_nonce: group::Element,
    vrf_nonce: group::Element,
    z_secret: group::Scalar,
    z_blinding: group::Scalar,
}
```

The SDK verifies each VRF proof against the current DKG/DKR PCS context and the
worker's aggregate share commitment before combining shares. The separate IBE
flow verifies identity-key shares against `sharePks` using pairings.

For a worker at SDK index `i`, expected `eval_point = i + 1`. The SDK fetches
the current session's `shareCommitments[i] = s_iG + r_iH` and verifies:

```text
z_secret G + z_blinding H == commitment_nonce + c * shareCommitment_i
z_secret H(input)         == vrf_nonce        + c * vrfShare_i
```

where `c = H(transcript)` binds the request fields, PCS context, share
commitment, VRF input point, share point, and proof nonces.

## DKG/DKR Session Public Data

Completed DKG and DKR sessions expose BCS session blobs with:

- `pcsContext`
- `commitmentPoints[0]`, the aggregate root commitment `F(0)G + R(0)H`
- `commitmentPoints[1..]`, aggregate holder commitments `F(i)G + R(i)H`
- `publicKeys[0]`, the master public key `F(0)G`
- `publicKeys[1..]`, per-holder public keys `F(i)G`

The commitment and public-key vectors are distinct. TypeScript accessors
`resultCommitment` / `shareCommitments` return the former, while `resultPk` /
`sharePks` return the latter.

## VSS Store

The VSS store is not consensus state. Its serialized `state_bytes` fields are implementation-private blobs owned by the Rust clients and may change with client versions. Protocol-visible state remains on-chain.
