# ACE Rust SDK (`ace-sdk`)

Rust mirror of the TypeScript (`@aptos-labs/ace-sdk`) and Python (`ace-sdk`) SDKs: threshold
IBE (block + streaming/seekable), threshold VRF, the underlying group / PKE / signature
primitives, on-chain view types (network state, DKG/DKR/VSS sessions), discovery, known
deployments, and admin recovery. Wire formats are byte-identical to the other SDKs and are
checked against the shared fixtures in `test-fixtures/`.

Module layout follows `ts-sdk/src` one-to-one; each module's doc comment names the TS file it
mirrors. Solana flows and WebAuthn helpers are not ported.

## Install (git dependency)

```toml
[dependencies]
ace-sdk = { git = "https://github.com/aptos-labs/ace.git", branch = "release-v5", package = "ace-sdk" }
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

Features: `aptos` (default) enables the network flows (`reqwest` + `tokio`). With
`default-features = false` you get the pure crypto and wire types only (what the worker
components will depend on).

## Quickstart: encrypt / decrypt with the basic flow

```rust
use ace_sdk::aptos::ibe::{decrypt_basic_flow, encrypt, DecryptBasicFlowArgs, EncryptArgs, Target};
use ace_sdk::aptos::{known_deployment, Ed25519Signer};
use ace_sdk::{AccountAddress, Wire};

#[tokio::main]
async fn main() -> ace_sdk::Result<()> {
    let dep = known_deployment("shelbynet-20260731").unwrap();
    let target = Target {
        ace_deployment: &dep.ace_deployment,
        keypair_id: dep.ibe_keypair_id,
        chain_id: dep.chain_id,
        module_addr: AccountAddress::from_str_relaxed("0x...")?, // your access-control module
        module_name: "my_acl",
    };
    let label = b"alice/2026/finance";

    // Anyone can encrypt: fetches the master public key from discovery (or the fullnode).
    let ct = encrypt(EncryptArgs { target, label, plaintext: b"hello", tibe_scheme: None, pk: None }).await?;
    let ct_bytes = ct.to_bytes();

    // Decrypting needs an account the module authorizes; the signer signs the wallet message.
    let signer = Ed25519Signer::new(&[0u8; 32], "my-app", dep.chain_id);
    let pt = decrypt_basic_flow(DecryptBasicFlowArgs { target, label, ciphertext: &ct_bytes, signer: &signer }).await?;
    assert_eq!(pt, b"hello");
    Ok(())
}
```

`MessageSigner` is a trait: implement it to plug in wallets or keyless accounts. Streaming
(`aptos::ibe_stream`), threshold VRF (`aptos::vrf::derive`) and admin recovery
(`admin_recovery::reconstruct_secret`) follow the same shape as their TS counterparts.

## Development

```sh
cargo test -p ace-sdk                        # unit + cross-impl fixture tests
cargo test -p ace-sdk -- --ignored           # live tests against shelbynet (network)
cargo check -p ace-sdk --no-default-features # pure-crypto configuration
```
