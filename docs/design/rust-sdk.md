# ACE Rust SDK — design

Status: **draft for review** (2026-09-11). Decisions already taken with the owner: full mirror of
the TS/Python SDKs (Aptos only; Solana deferred), standalone crate that the worker components
will later depend on, `tokio` + `reqwest` async, distributed as a git dependency until the API
settles (crates.io later).

## 1. Goals / non-goals

**Goals**
- `ace-sdk` crate exposing the same capabilities as `@aptos-labs/ace-sdk` (TS) and `ace-sdk`
  (Python): group arithmetic, t-IBE (three schemes incl. streaming/seekable), threshold VRF,
  PKE, signatures, VSS/PCS/sigma protocols, DKG/DKR/network session views, discovery + known
  deployments, admin recovery, and the Aptos client flows (`IBE_Aptos`, `StreamIBE_Aptos`,
  `VRF_Aptos`).
- Byte-for-byte wire compatibility with TS/Python, proven by the shared cross-impl fixtures.
- One home for the crypto: `worker-components/*` eventually import it instead of carrying
  their own copies (`vss-common/src/{group,pke,sig,sigma_dlog_linear,share_reconstruction}.rs`).

**Non-goals (v1)**
- Solana flows (`ibe-for-solana*`, `custom-flow-solana`).
- WebAuthn assertion helpers (`*WithWebAuthnAssertion`) — the primitives are exposed so a caller
  can build them, but no browser-credential plumbing.
- Publishing to crates.io, `no_std`, WASM targets.
- Migrating the workers. That is a follow-up (§8, phase 4) once the SDK is stable.

## 2. Layout

```
rust-sdk/
  Cargo.toml            # workspace member of the repo root Cargo.toml
  README.md
  src/
    lib.rs              # module tree + prelude; mirrors ts-sdk/src/index.ts
    error.rs            # AceError + Result alias
    wire.rs             # Wire trait (BCS quartet), hex helpers
    utils.rs            # kdf, hmac_sha3_256, hash helpers (ts utils.ts)
    group/              # bls12381fr.rs, bls12381g1.rs, bls12381g2.rs, mod.rs (scheme-tagged)
    sig/                # ed25519
    pke/                # ristretto255 group, elgamal, elgamal_otp_ristretto255,
                        # hpke_x25519_chacha20poly1305, mod.rs
    pedersen_polynomial_commitment.rs
    sigma_dlog_linear.rs
    vss/                # dealing.rs, mod.rs
    dkg.rs  dkr.rs  network.rs
    t_ibe/              # shortpk_otp_hmac.rs, shortsig_aead.rs, shortsig_aead_stream.rs, mod.rs
    t_ibe_stream.rs
    admin_recovery.rs
    aptos/              # client.rs (fullnode views), discovery.rs, known_deployments.rs,
                        # common.rs (ContractID, worker request/proof types), wallet_message.rs,
                        # ibe.rs, ibe_stream.rs, vrf.rs
  tests/
    cross_impl.rs       # loads ../test-fixtures/*.json
```

One crate, two Cargo features:
- `default = ["aptos"]` — everything above.
- `aptos` — pulls `reqwest`, `tokio` and enables `aptos/` + `admin_recovery`. Off = pure crypto
  + wire types (what the workers need; keeps their dependency tree unchanged in phase 4).

Rust edition 2021; MSRV = whatever `rust-toolchain.toml` pins for the workers.

## 3. Dependencies

| concern | crate | note |
|---|---|---|
| BLS12-381 | `ark-bls12-381 0.4`, `ark-ec`, `ark-ff`, `ark-serialize` | same as `vss-common`. **Point encoding must be the zcash compressed format noble uses, not arkworks' flag layout** — `vss-common/src/group.rs` already handles this and is the reference |
| Ristretto255 / X25519 / Ed25519 | `curve25519-dalek 4`, `x25519-dalek`, `ed25519-dalek 2` | as vss-common |
| HPKE | `hpke 0.12` (x25519, chacha20poly1305) | as vss-common |
| AEAD / hashes / KDF | `chacha20poly1305`, `sha2`, `sha3`, `hkdf`, `hmac` | |
| BCS | `bcs 0.1` + `serde` | derive where the layout is plain; hand-written where TS uses a custom `serialize()` |
| Aptos REST | `reqwest` + `serde_json` | raw `/v1/view` and `/v1` like TS; no `aptos-sdk` (too heavy). `AccountAddress` = small newtype (§9) |
| async | `tokio` (rt, time), `reqwest` (json, rustls), `futures` (streams), `async-trait` | |
| errors | `thiserror` | |

## 4. Conventions

**Wire types.** Every type that crosses the wire implements
```rust
pub trait Wire: Sized {
    fn to_bytes(&self) -> Vec<u8>;
    fn from_bytes(b: &[u8]) -> Result<Self>;
    fn to_hex(&self) -> String;          // "0x…"
    fn from_hex(s: &str) -> Result<Self>;
}
```
mirroring the TS quartet. Scheme-tagged unions (`group::Element`, `pke::Ciphertext`,
`t_ibe::Ciphertext`, …) are Rust `enum`s whose u8 tag is the discriminant, serialized exactly as
`docs/auditor/wire-formats.md` specifies.

**Errors.** `pub type Result<T> = core::result::Result<T, AceError>` with a `thiserror` enum:
`Wire(String)`, `Crypto(String)`, `Verify(String)`, `InsufficientShares { need, got }`,
`Http { status, body }`, `Chain(String)`, `Signer(String)`, `Timeout`, … . Where TS returns
`Promise<Result<T>>` we return `Result<T>` — no nesting.

**Naming.** snake_case of the TS names; constants keep the TS names verbatim
(`SCHEME_BFIBE_BLS12381_SHORTSIG_AEAD`, `PRIMITIVE_BLS12381_THRESHOLD_VRF`, `USAGE_*`).

**Randomness.** Sampling fns take `&mut impl CryptoRngCore`; `*_os()` helpers use `OsRng`;
deterministic `*_with_randomness` variants exist wherever TS has them (`encryptWithRandomness`)
because the fixtures depend on them.

**Signing callback.** The Aptos flows take
```rust
#[async_trait]
pub trait MessageSigner: Send + Sync {
    fn account_address(&self) -> AccountAddress;
    async fn sign(&self, msg_to_sign: &str) -> Result<SignedMessage>; // { pub_key, signature, full_message }
}
```
with `Ed25519Signer` (from a private key) and `build_aptos_wallet_full_message(..)` provided;
wallets/keyless implement the trait themselves.

**Streaming.** `StreamIBE` encrypt/decrypt operate on `futures::Stream<Item = Result<Bytes>>`;
the seekable decryptor takes
```rust
#[async_trait]
pub trait RangeReader: Send + Sync {
    fn byte_length(&self) -> u64;
    async fn read_range(&self, offset: u64, len: u64) -> Result<Bytes>;
}
```
with `FileRangeReader` (tokio fs) and `HttpRangeReader` (reqwest `Range`) included.

## 5. Module mapping

| TS module (`ts-sdk/src`) | Python | Rust module | seed from `vss-common` | notes |
|---|---|---|---|---|
| `result.ts` | `result.py` | `error.rs` | — | idiomatic `Result` |
| `utils.ts` | `utils.py` | `utils.rs` | `crypto.rs` (partly) | kdf, hmac-sha3-256 |
| `group/*` | `group/*` | `group/*` | `group.rs` | G1/G2, Fr, `PrivateScalar`, `SecretShare`, `PcsCommitment`, `DealerState`, `reconstruct`, `split` |
| `sig/` | `sig/` | `sig/` | `sig.rs` | ed25519 |
| `pke/*` | `pke/*` | `pke/*` | `pke.rs`, `pke_hpke_x25519_chacha20poly1305.rs` | both schemes + tagged wrapper |
| `pedersen-polynomial-commitment/` | same | `pedersen_polynomial_commitment.rs` | — | PublicParams, Commitment, Opening, DegreeCheckState |
| `sigma-dlog-linear/` | same | `sigma_dlog_linear.rs` | `sigma_dlog_linear.rs` | vss-common has prover + verifier; TS only the type — expose both |
| `vss/*` | `vss/*` | `vss/*` | `vss_types.rs`, `share_reconstruction.rs` | Session view, contributions, dealing helpers |
| `dkg/`, `dkr/` | same | `dkg.rs`, `dkr.rs` | `session.rs` (partly) | session views (deserialize-only, as in TS) |
| `network/` | `network.py` | `network.rs` | — | State, SecretInfo, proposals, epoch change, `usage_for_primitive` |
| `t-ibe/*` | `t_ibe/*` | `t_ibe/*` | logic in `network-node/src/http_server/flows/*` (copy, do not import) | schemes 0, 1, 3 |
| `t-ibe-stream/` | `t_ibe_stream.py` | `t_ibe_stream.rs` | — | STREAM DEM, seekable (`docs/auditor/cryptography/t-ibe.md` §3) |
| `admin-recovery/` | `admin_recovery.py` | `admin_recovery.rs` | — | `aptos` feature |
| `_internal/common.ts` | `_internal/common.py` | `aptos/common.rs` | — | ContractID, FullDecryptionDomain, ProofOfPermission, request payloads, WorkerRequest |
| `_internal/discovery.ts` | `_internal/discovery.py` | `aptos/discovery.rs` | — | DiscoveryViewV0 + fetch |
| `known-deployments.ts` | `known_deployments.py` | `aptos/known_deployments.rs` | — | same ids/values (§9.2) |
| `aptos.ts`, `AceDeployment` | `_internal/aptos.py`, `_internal/deployment.py` | `aptos/client.rs` | `aptos.rs` | views, API-key header, chain id, discovery-or-fullnode state fetch |
| `ibe-for-aptos/` | `ibe_aptos.py` | `aptos/ibe.rs` | — | `fetch_pk`, `encrypt`, `BasicDecryptionSession`, `decrypt_basic_flow`, custom flow |
| `ibe-for-aptos-stream/` | `ibe_aptos_stream.py` | `aptos/ibe_stream.rs` | — | `encrypt_stream`, `StreamDecryptor`, seekable |
| `vrf-for-aptos/` | `vrf_aptos.py` | `aptos/vrf.rs` | — | payload types, `DerivationSession`, `derive`, share verify + reconstruct |
| `ibe-for-solana*`, `solana.ts` | — | — | — | **deferred** |

## 6. Compatibility & testing

- **Cross-impl fixtures** (`test-fixtures/*.json`) are the contract: `tests/cross_impl.rs` must
  decrypt every TS/Python-produced ciphertext, verify every share, and reproduce every
  deterministic output. Rust-produced vectors are appended to the same files so TS/Python CI
  cross-checks Rust too.
- Unit tests port the TS `*.test.ts` cases module by module (same inputs, same expected bytes).
- Integration tests (`--features aptos`, `#[ignore]` by default) run against the localnet the TS
  integration tests use: `encrypt → decrypt_basic_flow`, StreamIBE incl. range reads, `vrf::derive`.
- `cargo fmt --check`, `cargo clippy -D warnings`, `cargo test` join `.github/workflows/ci.yml`.

## 7. Documentation

`rust-sdk/README.md` (git-dep install, quickstart mirroring
`docs/developers/app-developer-guide/ibe-aptos-basic.md`), rustdoc on every public item, and Rust
snippets next to the TS/Python ones in the app-developer guides.

## 8. Phases

| phase | content | exit criterion |
|---|---|---|
| 0 | skeleton, CI, `error`, `wire`, `utils`, `group`, `sig`, `pke` | group/pke/sig fixtures pass |
| 1 | `t_ibe` (0, 1), `t_ibe_stream` (3), `pedersen_polynomial_commitment`, `sigma_dlog_linear` | all t-IBE fixtures + ported stream tests pass |
| 2 | `aptos/{client,discovery,known_deployments,common,wallet_message}`, `network`, `aptos/{ibe,ibe_stream,vrf}` | localnet round-trip for IBE, StreamIBE (incl. range), VRF |
| 3 | `vss`, `dkg`, `dkr`, `admin_recovery` | views deserialize real on-chain state; admin recovery matches the Python result on a test network |
| 4 (separate track) | worker migration: `vss-common` re-exports `ace-sdk` (default-features = false), duplicates deleted; `network-node` flows use `ace-sdk::t_ibe` | worker suites green; node diff-tested against a live network |

Each phase is one or more PRs against `release-v5`. Nothing under `worker-components/` changes
before phase 4.

## 9. Open questions

1. `AccountAddress`: hand-rolled 32-byte newtype vs `move-core-types` (large dep). Lean: newtype
   with Aptos short-form hex parsing.
2. `known_deployments` becomes triplicated (TS/Py/Rust). Generate all three from one JSON? Out of
   scope here; flagged because the Rust copy makes drift more likely.
3. Where does `HttpRangeReader` live — behind `aptos` (it needs `reqwest`) or its own `http` feature?
