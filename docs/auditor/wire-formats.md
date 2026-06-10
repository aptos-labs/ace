# ACE Wire Formats

Authoritative byte-level reference for every BCS-encoded wire format in the ACE codebase. After PR #55, every wire type below is `#[derive(Serialize, Deserialize)]` in Rust, and every field's BCS encoding is determined mechanically from its Rust type. This doc is a human-readable mirror of those derivations.

For the cryptographic operations that produce / consume these bytes, see [`cryptography/`](./cryptography/). For protocol context, see [`protocols.md`](./protocols.md). For protocol-level term definitions (`keypair_id`, `epoch`, `identity`, etc.), see [`glossary.md`](./glossary.md).

---

## 0. BCS primer (the rules we use)

Aptos's [BCS](https://github.com/aptos-labs/bcs) is a deterministic, length-prefixed serialization. Rules used in this doc:

| Type | BCS encoding |
|------|-------------|
| `bool` | 1 byte (`0x00` / `0x01`) |
| `u8` | 1 raw byte |
| `u64` | 8 little-endian bytes |
| `[u8; N]` (fixed array) | N raw bytes (no length prefix) |
| `Vec<u8>` | `ULEB128(len) || raw bytes` |
| `Vec<T>` | `ULEB128(len) || (T encoded len times)` |
| `String` | `ULEB128(len) || UTF-8 bytes` |
| `Option<T>` | `0x00` (None) or `0x01 || T encoded` |
| `enum E` (derived) | `ULEB128(variant_index) || variant fields encoded` |
| `struct S { a, b, c }` (derived) | `a encoded || b encoded || c encoded` (declaration order) |

ULEB128 of 0..127 is exactly one byte. All ACE enum tags fit in one byte today.

> **Audit hook.** Every byte-level claim below derives from the Rust serde derives. If a Rust struct field is reordered or its type changes, the wire format changes. CI must run cross-implementation round-trip tests (TS ↔ Rust ↔ Move) to catch drift.

---

## 1. PKE wire formats

Defined in `worker-components/vss-common/src/pke.rs`, mirrored in `ts-sdk/src/pke/index.ts` and `contracts/pke/sources/pke.move`.

### 1.1 `pke::EncryptionKey`

```rust
enum EncryptionKey {
    ElGamalOtpRistretto255(ElGamalOtpRistretto255EncKey),    // tag 0
    HpkeX25519ChaCha20Poly1305(HpkeEncryptionKey),           // tag 1
    HybridX25519MlKem768ChaCha20Poly1305(HybridEncryptionKey), // tag 2
}

struct ElGamalOtpRistretto255EncKey { enc_base: Vec<u8>, public_point: Vec<u8> }
struct HpkeEncryptionKey { pk: Vec<u8> }   // (pke_hpke_x25519_chacha20poly1305::EncryptionKey)
struct HybridEncryptionKey { hpke_x25519: HpkeEncryptionKey, mlkem768_ek: Vec<u8> }
```

| Variant | Wire bytes (total) |
|---------|---------------------|
| ElGamalOtpRistretto255 | `00 \| 20 \| 32B enc_base \| 20 \| 32B public_point` = **67 B** |
| HpkeX25519ChaCha20Poly1305 | `01 \| 20 \| 32B pk` = **34 B** |
| HybridX25519MlKem768ChaCha20Poly1305 | `02 \| 20 \| 32B x25519_pk \| a0 09 \| 1184B mlkem768_ek` = **1220 B** |

Where `20` = ULEB128(32). Inner `Vec<u8>` is sized but variable in principle; canonical lengths are 32 for all current uses.

### 1.2 `pke::Ciphertext`

```rust
enum Ciphertext {
    ElGamalOtpRistretto255(ElGamalOtpRistretto255Ciphertext),  // tag 0
    HpkeX25519ChaCha20Poly1305(HpkeCiphertext),                // tag 1
    HybridX25519MlKem768ChaCha20Poly1305(HybridCiphertext),    // tag 2
}

struct ElGamalOtpRistretto255Ciphertext {
    c0: Vec<u8>, c1: Vec<u8>, sym_ciph: Vec<u8>, mac: Vec<u8>
}
struct HpkeCiphertext {
    enc: Vec<u8>, aead_ct: Vec<u8>
}
struct HybridCiphertext {
    mlkem768_ct: Vec<u8>, aead_nonce: Vec<u8>, aead_ct: Vec<u8>
}
```

| Variant | Wire bytes |
|---------|------------|
| ElGamalOtpRistretto255 | `00 \| 20 \| 32B c0 \| 20 \| 32B c1 \| ULEB(L) \| L B sym_ciph \| 20 \| 32B mac` |
| HpkeX25519ChaCha20Poly1305 | `01 \| 20 \| 32B enc \| ULEB(L) \| L B aead_ct` (aead_ct = ct \|\| 16B Poly1305 tag) |
| HybridX25519MlKem768ChaCha20Poly1305 | `02 \| c0 08 \| 1088B mlkem768_ct \| 0c \| 12B nonce \| ULEB(L) \| L B outer_aead_ct` |

For the hybrid scheme, `outer_aead_ct` encrypts the serialized inner HPKE ciphertext and includes a 16-byte Poly1305 tag. For `P` plaintext bytes:

```text
inner_hpke_len = 33 + uleb_len(P + 16) + P + 16
outer_aead_len = inner_hpke_len + 16
total_len      = 1 + 2 + 1088 + 1 + 12 + uleb_len(outer_aead_len) + outer_aead_len
```

Examples: `P=32` -> **1203 B**, `P=1024` -> **2197 B**, `P=65536` -> **66711 B**.

### 1.3 `pke::DecryptionKey` (per scheme)

These never appear on the wire as part of a request — they live only on the worker's disk / env-var — but they are BCS-encoded in their hex CLI form:

| Scheme | Layout | Total |
|--------|--------|------:|
| ElGamalOtpRistretto255 | `00 \| 20 \| 32B enc_base \| 20 \| 32B priv_scalar` | **67 B** |
| HpkeX25519ChaCha20Poly1305 | `01 \| 20 \| 32B sk` | **34 B** |
| HybridX25519MlKem768ChaCha20Poly1305 | `02 \| 20 \| 32B x25519_sk \| 40 \| 64B mlkem768_seed` | **99 B** |

The leading scheme byte is consumed by `pke_decrypt_bytes` (`worker-components/vss-common/src/pke.rs`) to dispatch.

---

## 2. Worker-request wire format

Defined in `worker-components/network-node/src/verify.rs`, mirrored in `ts-sdk/src/_internal/common.ts` (and `aptos.ts` / `solana.ts` for the per-chain inner types).

### 2.1 Outer envelope

The HTTP request body is the **hex string** of `pke_encrypt(worker_enc_key, BCS(WorkerRequest))`. Wire-decoded, the inner is:

```rust
enum WorkerRequest {
    DecryptionBasicFlow(DecryptionBasicFlowRequest),    // tag 0
    DecryptionCustomFlow(DecryptionCustomFlowRequest),  // tag 1
    ThresholdVrf(ThresholdVrfRequest),                  // tag 2
}
```

Decryption variants carry an explicit `tibe_scheme: u8` so the handler serves the share formatted for the client's actual t-IBE choice instead of guessing from the share's group via `crypto::tibe_scheme_for_group`. The handler validates `t_ibe_scheme_group(tibe_scheme) == share.group_scheme` and rejects otherwise.

### 2.2 `DecryptionBasicFlowRequest`

```rust
struct DecryptionRequestPayload {
    keypair_id:        [u8; 32],
    epoch:             u64,
    contract_id:       ContractId,
    domain:            Vec<u8>,           // app-specific label (called `label` in spec docs and Move; field is named `domain` for historical reasons — see glossary)
    ephemeral_enc_key: pke::EncryptionKey,
}

struct DecryptionBasicFlowRequest {     // tag 0
    payload:           DecryptionRequestPayload,
    proof:             ProofOfPermission,
    tibe_scheme:       u8,
}
```

Wire layout:

```
after outer `00`: [DecryptionRequestPayload] [ProofOfPermission] [1B tibe_scheme]
```

### 2.3 `DecryptionCustomFlowRequest`

```rust
struct DecryptionCustomFlowRequest {    // tag 1
    keypair_id:  [u8; 32],
    epoch:       u64,
    contract_id: ContractId,
    label:       Vec<u8>,
    enc_pk:      pke::EncryptionKey,
    proof:       CustomFlowProof,
    tibe_scheme: u8,
}
```

Wire layout:

```
after outer `01`: [32B keypair_id] [8B epoch LE] [ContractId] [ULEB | label] [EncryptionKey] [CustomFlowProof] [1B tibe_scheme]
```

### 2.4 `ContractId`

```rust
enum ContractId {
    Aptos(AptosContractId),    // tag 0
    Solana(SolanaContractId),  // tag 1
}

struct AptosContractId {
    chain_id:      u8,
    module_addr:   [u8; 32],
    module_name:   String,
}

struct SolanaContractId {
    known_chain_name: String,    // e.g. "mainnet-beta", "devnet"
    program_id:       Vec<u8>,   // 32 bytes
}
```

| Variant | Wire bytes |
|---------|------------|
| Aptos | `00 \| 1B chain_id \| 32B module_addr \| ULEB(\|module_name\|) \| UTF-8` |
| Solana | `01 \| ULEB(\|known_chain_name\|) \| UTF-8 \| ULEB(32) \| 32B program_id` |

### 2.5 `ProofOfPermission` (basic flow)

```rust
enum ProofOfPermission {
    Aptos(AptosProofOfPermission),    // tag 0
    Solana(SolanaProofOfPermission),  // tag 1
}

struct AptosProofOfPermission {
    user_addr:    [u8; 32],
    pk_scheme:    u8,
    public_key:   Vec<u8>,
    sig_scheme:   u8,
    signature:    Vec<u8>,
    full_message: String,
}

struct SolanaProofOfPermission {
    inner_scheme: u8,            // 0 = legacy, 1 = versioned
    txn_bytes:    Vec<u8>,
}
```

The worker dispatches on the `(pk_scheme, sig_scheme)` pair. `public_key` and `signature` are framed as `Vec<u8>` here only for the table — the worker actually decodes the inner bytes per scheme via a custom serde impl (see `worker-components/network-node/src/verify/aptos/`). Supported pairings:

| `pk_scheme` | `sig_scheme` | Account type |
|-------------|--------------|--------------|
| 0 | 0 | Legacy Ed25519 (`Ed25519PublicKey` + `Ed25519Signature`) |
| 1 | 1 | `AnyPublicKey` / `AnySignature` (SingleKey). Inner variants: `Ed25519`, `Secp256k1Ecdsa`, `Secp256r1Ecdsa`+`WebAuthn` (passkeys), `Keyless`, `FederatedKeyless` |
| 2 | 2 | Legacy K-of-N `MultiEd25519` (`Scheme::MultiEd25519 = 0x01`). Flat-concat wire layout (`pk_1‖…‖pk_N‖threshold` and `sig_1‖…‖sig_K‖bitmap[4]`). Predates `MultiKey`; only raw Ed25519 positions. |
| 3 | 3 | `MultiKey` / `MultiKeyAuthenticator` (K-of-N over all five `AnyPublicKey` variants) |
| 4 | 4 | Bare `KeylessPublicKey` / `KeylessSignature` |
| 5 | 4 | `FederatedKeylessPublicKey` paired with `KeylessSignature` |

`full_message` is the UTF-8 pretty-message string the wallet signed over (or its hex form for the AptosConnect wallet path). For `pk_scheme=1` `AnyPublicKey<Secp256r1Ecdsa>`+`AnySignature<WebAuthn>` (passkeys), `full_message` is `hex(authenticator_data || SHA-256(clientDataJSON))`. For MultiKey requests with a WebAuthn position, the WebAuthn arm binds to the request payload via `clientDataJSON.challenge` (not `full_message`), so a single shared `full_message` covers the pretty-message-signing positions without breaking the WebAuthn one.

### 2.6 `CustomFlowProof` (custom flow)

```rust
enum CustomFlowProof {
    Aptos(Vec<u8>),               // tag 0; arbitrary payload, contract-defined
    Solana(SolanaProofOfPermission),  // tag 1; same shape as basic flow
}
```

### 2.7 Worker response

Each worker returns the **hex string** of:
```
pke_encrypt(ephemeral_enc_key, BCS(t-ibe::IdentityDecryptionKeyShare))
```

The `IdentityDecryptionKeyShare` BCS layout is (TS reference: `ts-sdk/src/t-ibe/bfibe-bls12381-shortpk-otp-hmac.ts::IdentityDecryptionKeyShare`):

```rust
struct IdentityDecryptionKeyShare {
    eval_point:  [u8; 32],   // Fr scalar (worker index + 1, LE)
    idk_share:   Vec<u8>,    // 96B (G2, scheme 0) or 48B (G1, scheme 1)
    proof:       u8,         // currently always 0x00 (no per-share proof; reserved)
}
```

Total bytes (excluding wire ULEBs): **129 B (scheme 0)** or **81 B (scheme 1)**.

---

## 3. IBE identity bytes (`fdd_bytes`)

The IBE identity passed to `hash_to_curve` is the BCS-concatenation of three fields, computed by both ends as:

```
identity := keypair_id (32B raw)
         || BCS(contract_id)        # (1 byte enum tag + chain-specific fields)
         || BCS(label)              # ULEB(len) || raw bytes
```

(In TS / Rust source the third argument is named `domain` for the basic flow and `label` for the custom flow; the bytes that go into the BCS-concat are the same.) This is implemented as `verify::identity_bytes(keypair_id, contract_id, label)` in Rust (`worker-components/network-node/src/verify.rs`) and as `FullDecryptionDomain.toBytes()` in TS (`ts-sdk/src/_internal/common.ts:115-160`).

> **Audit invariant.** A future change to ACE that, say, separates the `keypair_id` and `contract_id` for some new flow MUST keep `identity_bytes` byte-identical for already-encrypted ciphertexts to remain decryptable. The function above is the single source of truth.

---

## 4. Solana proof inner formats

Defined in `ace-anchor-kit/src/lib.rs`. Embedded inside the Solana txn's instruction data and validated by the worker.

### 4.1 `FullRequestBytes` (basic flow)

```rust
struct FullRequestBytes {
    keypair_id:        [u8; 32],
    epoch:             u64,
    ephemeral_enc_key: Vec<u8>,        // = bcs::to_bytes(&EncryptionKey)
    domain:            Vec<u8>,        // app-specific label (field name `domain` is historical, see §2.2)
}
```

Wire: `[32B keypair_id] [8B epoch LE] [ULEB(L) | L B enc_key_wire] [ULEB(D) | D B label]`.

### 4.2 `CustomFullRequestBytes`

```rust
struct CustomFullRequestBytes {
    keypair_id: [u8; 32],
    epoch:      u64,
    enc_pk:     Vec<u8>,
    label:      Vec<u8>,
    payload:    Vec<u8>,
}
```

Wire: `[32B] [8B] [ULEB|enc_pk] [ULEB|label] [ULEB|payload]`.

The worker's verification reconstructs these bytes locally and compares them byte-for-byte against the bytes embedded in the Solana txn's instruction data (after stripping the 8-byte Anchor discriminator + 4-byte LE vec-length).

---

## 5. Group elements

Defined in `contracts/group/sources/group.move` and `worker-components/vss-common/src/session.rs`.

### 5.1 `group::Element` enum (Move + Rust mirror)

```rust
enum BcsElement {
    Bls12381G1Element(BcsPublicPoint),  // tag 0
    Bls12381G2Element(BcsPublicPoint),  // tag 1
}

struct BcsPublicPoint { point_bytes: Vec<u8> }    // 48B (G1) or 96B (G2), compressed
```

Wire:
- G1 element: `00 | 30 | 48B compressed` (ULEB128(48) = 0x30) — **50 B**
- G2 element: `01 | 60 | 96B compressed` (ULEB128(96) = 0x60) — **98 B**

### 5.2 `group::Scalar` enum

```rust
enum BcsScalar {
    Bls12381Fr(BcsScalarBytes),    // tag 0
}

struct BcsScalarBytes { scalar_bytes: Vec<u8> }    // 32B LE
```

Wire: `00 | 20 | 32B LE` — **34 B**.

(Only one scheme defined today; the enum is over-specified for forward compatibility.)

### 5.3 PCS commitment, openings, and proofs

```rust
struct BcsPcsPublicParams {
    generator_g: BcsElement,
    generator_h: BcsElement,
}

struct BcsPcsCommitment { points: Vec<BcsElement> }

struct BcsPcsOpening {
    eval_position: u64,
    eval_value_p: BcsScalar,
    eval_value_r: BcsScalar,
}

struct BcsPcsDegreeCheckState {
    z_poly: Vec<BcsScalar>,
    accumulator: BcsElement,
    next_eval_position: u64,
}

struct BcsSigmaDlogLinearProof {
    t_vals: Vec<BcsElement>,
    z_vals: Vec<BcsScalar>,
}
```

All defined in `worker-components/vss-common/src/session.rs` and exactly mirror the on-chain Move structs.

---

## 6. VSS / DKG / DKR sessions (BCS mirror)

Workers read on-chain session state via `*_bcs()` view functions and decode with `bcs::from_bytes` against these mirror types.

### 6.1 `vss::Session` mirror (`BcsSession` in `session.rs`)

```rust
struct BcsSession {
    dealer:                    [u8; 32],
    share_holders:             Vec<[u8; 32]>,
    threshold:                 u64,
    public_base_element:       BcsElement,
    previous_public_key:       Option<BcsElement>,
    pcs_context:               BcsPcsPublicParams,
    state_code:                u8,
    deal_time_micros:          u64,
    dealer_contribution_0:     Option<BcsDealerContribution0>,
    dealer_commitment_check:   BcsPcsDegreeCheckState,
    share_holder_acks:         Vec<bool>,
    dealer_contribution_1:     Option<BcsDealerContribution1>,
    next_public_key_to_verify: u64,
    public_keys:               Vec<BcsElement>,
}

struct BcsDealerContribution0 {
    pcs_commitment:         BcsPcsCommitment,
    private_share_messages: Vec<pke::Ciphertext>,    // one per holder
    dealer_state:           Option<pke::Ciphertext>,
    consistency_proof:      Option<BcsSigmaDlogLinearProof>,
}

struct BcsDealerContribution1 {
    shares_to_reveal:   Vec<Option<BcsPcsOpening>>, // length = n + 1; index 0 is always None
    public_keys:        Vec<BcsElement>,            // s_i * public_base_element over {0, ..., n}
    public_key_proofs:  Vec<Option<BcsSigmaDlogLinearProof>>,
}
```

The Move-side struct is in `contracts/vss/sources/vss.move:75-104`; field order is identical.

**Plaintext shape of `private_share_messages[i]`** (after PKE decrypt):
```rust
struct BcsPcsOpening {
    eval_position: u64,
    eval_value_p: BcsScalar,
    eval_value_r: BcsScalar,
}
```

`eval_value_p` is the share value; `eval_value_r` is the Pedersen blinding value. The holder keeps `eval_value_r` private and uses it only to verify the opening against `pcs_commitment.points[eval_position]`.

### 6.2 `vss::DealerState` plaintext

The dealer encrypts a "dealer state" cipherblob (used to re-derive its polynomial after a crash). Defined in `worker-components/vss-common/src/vss_types.rs::DealerState`:

```rust
enum DealerState {
    Bls12381Fr {                                     // tag 0
        n: u64,
        coefs_poly_p: Vec<Vec<u8>>,                  // each = 32B Fr LE
    },
}
```

This is encrypted to the dealer's *own* PKE encryption key (`enc_keys[0]` in the dealer's view, which is itself, per the `dkg::Session` ordering). Workers don't currently consume it; it's there for crash recovery.

### 6.3 `dkg::Session` and `dkr::Session`

Both have view functions returning BCS bytes (`get_session_bcs`); the mirror Rust structs live in the relevant worker crates (`dkg-worker`, `dkr-src`, `dkr-dst`). Field-by-field layouts are direct Rust mirrors of the Move source listed in [`protocols.md`](./protocols.md) §3.1 and §4.1.

---

## 7. `network::State` snapshot

The `state_view_v0_bcs()` view function returns a flat-ish `StateViewV0` BCS struct. The TS SDK and the worker both decode it. Roughly:

```rust
struct StateViewV0 {
    epoch:                  u64,
    epoch_start_time_micros: u64,
    epoch_duration_micros:  u64,
    cur_nodes:              Vec<[u8; 32]>,
    cur_threshold:          u64,
    secrets:                Vec<SecretInfo>,
    proposals:              Vec<Option<ProposalView>>,
    epoch_change_info:      Option<EpochChangeView>,
}

struct SecretInfo {
    current_session: [u8; 32],
    keypair_id:      [u8; 32],
    scheme:          u8,
}

struct ProposalView {
    proposal:        ProposedEpochConfig,
    voting_session:  [u8; 32],
    votes:           Vec<bool>,
    voting_threshold: u64,
}

struct ProposedEpochConfig {
    nodes:                 Vec<[u8; 32]>,
    threshold:             u64,
    epoch_duration_micros: u64,
    secrets_to_retain:     Vec<[u8; 32]>,
    new_secrets:           Vec<u8>,         // group-scheme bytes
    description:           String,
    target_epoch:          u64,
}

struct EpochChangeView {
    triggering_proposal_idx: Option<u64>,
    session_addr:           [u8; 32],
    nxt_nodes:              Vec<[u8; 32]>,
    nxt_threshold:          u64,
}
```

Source of truth: `contracts/network/sources/network.move:120-188` (the producer) and the consumer in `ts-sdk/src/network/index.ts`.

---

## 8. Aptos `pretty(decryption_request)` (signed message)

This is **not** a BCS struct — it's a UTF-8 string the user signs in basic-flow Aptos. The worker reconstructs the same bytes and checks the user's signature covers them. Format (literal):

```
ACE Decryption Request
keypairId: 0x{64 hex chars}
epoch: {decimal}
contractId:
  scheme: aptos
  inner:
      chainId: {decimal}
      moduleAddr: 0x{64 hex chars}
      moduleName: {string}
domain: 0x{hex of label bytes}
ephemeralEncKey: {hex of EncryptionKey BCS, no 0x prefix}
```

(Note the 6-space indent on the `inner:` fields — derived from `pad = "  ".repeat(indent + 2)` in TS. The literal label `domain:` is what the SDK emits today; the bytes after it are the app-specific label per the spec — see §2.2.)

Two acceptance modes (`worker-components/network-node/src/verify.rs::verify_aptos_sig`):
- The user's `fullMessage` literally contains this string, OR
- The user's `fullMessage` contains the lowercase hex of UTF-8(this string) — to support AptosConnect wallets which embed the message hex-encoded.

---

## 9. Endianness and field-encoding cheat sheet

| Field type | Endianness | Where it shows up |
|------------|------------|-------------------|
| BLS12-381 Fr scalar | **LE** in 32 bytes (canonical, mod r) | `BcsScalar`, share plaintexts, `eval_point` |
| BLS12-381 G1 / G2 | per `arkworks-rs` / `noble-curves` compressed convention (BE-ish in spec, but the byte layout is what's shipped — **don't reinterpret**) | `BcsElement`, MasterPublicKey, IDK shares |
| BLS12-381 Gt | custom: noble big-endian limbs reversed to LE-per-48B-limb (`bls12381GtReprNobleToAptos`) | t-IBE seed only |
| u64 (BCS) | **LE** | epoch, threshold, time fields |
| ULEB128 | LSB first | All BCS lengths and enum tags |
| Solana `compact-u16` | LSB first, max 3 bytes | Solana txn parsing only |

---

## 10. Test coverage of wire formats

Round-trip / cross-implementation tests that gate wire-format changes:

| Test | Location | Asserts |
|------|----------|---------|
| `pke::tests::round_trip` (Rust) | `worker-components/vss-common/src/pke_hpke_x25519_chacha20poly1305.rs:170-180` | HPKE encrypt then decrypt yields original plaintext |
| `pke::tests::*_bcs_round_trip` (Rust) | same | EncryptionKey / Ciphertext BCS round-trip with byte-count assertions |
| Move `test_*_from_bytes_golden` | `contracts/pke/tests/` | Move decoder matches a TS-produced golden vector |
| `pnpm vitest` (TS) | `ts-sdk/tests/` | t-IBE schemes 0 and 1 round-trip; AEAD tamper rejection; wire-shape size assertions |
| Scenarios (`pnpm full-happy-path`, etc.) | `scenarios/` | End-to-end: encrypt → DKG → decrypt across TS / Rust / Move |

If you change a wire format and any of the above breaks but the others pass, you have introduced a silent cross-implementation drift. CI runs all four.
