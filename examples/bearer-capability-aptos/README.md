# Bearer Capability Access — Aptos

A step-by-step demo of a **bearer signing capability** on top of ACE. The data owner uploads an
encrypted blob, derives a per-blob BLS keypair through ACE threshold VRF, and hands the
*private* half to a reader out-of-band. Anyone holding that private half can
decrypt; no on-chain identity is required from the reader.

You will:

1. Deploy a small Move contract (`capability_access`) that stores one BLS12-381
   pubkey per blob and exposes both the ACE VRF hook and custom-flow hook.
2. Encrypt a blob, derive `(accessPrivateKey, accessPublicKey)` via ACE
   threshold VRF, and register `accessPublicKey` on-chain.
3. Hand the resulting capability file to a reader and watch them
   decrypt with no Aptos account of their own.
4. Rotate the on-chain pubkey and watch the old capability stop working.

The demo runs against Aptos testnet by default using the SDK's `knownDeployments.preview20260714` deployment. To target a different ACE deployment, set `ACE_CONTRACT`, `IBE_KEYPAIR_ID`, and `VRF_KEYPAIR_ID`; optionally override `ACE_API_ENDPOINT`.

## How it works

The owner-side flow:

```text
encrypt(plaintext, ibeKeypairId) ──→ ciphertext        (ACE custom flow t-IBE)
VRF(contract_id, blob_id, vrfKeypairId) ──→ accessPrivateKey
accessPrivateKey * G1 ──→ accessPublicKey               (BLS12-381)
register(blob_suffix, accessPublicKey)   (on-chain)
capability.json = { blobIdHex, ciphertextHex, accessPrivateKeyHex }  (bearer capability)
```

The reader-side flow:

```text
parse capability.json
sign  BCS(SignableRequest { dst, label, user_epk, origin })
        with accessPrivateKey (BLS sig in G2)
payload = BCS({ origin, sig })
CustomDecryptionSession.decrypt({ ciphertext, payload })
   └─→ workers call capability_access::on_ace_decryption_request_custom_flow
        which verifies the sig under the registered accessPublicKey
   └─→ plaintext
```

Four properties:

- **Owner-only derivation.** The VRF request is signed by Alice's Aptos account, and `on_ace_vrf_request` only approves labels in Alice's `@<alice>/...` namespace.
- **Deterministic bearer key material.** The access keypair is derived from the ACE VRF keypair, the app contract id, and the blob label, then stored or distributed like any other bearer credential.
- **Bearer semantics.** The reader needs no on-chain identity. Whoever
  holds the key can sign and decrypt.
- **Revocation by overwrite.** Re-registering a new `accessPublicKey` under
  the same `blob_suffix` invalidates the old `accessPrivateKey` immediately.

## Cast

- **Alice** — data owner. Deploys the contract, encrypts the blob, derives the
  access keypair, registers the public half, and emits the capability.
- **Bob** — reader. Has no on-chain identity. Reads `data/capability.json` and runs
  one script to decrypt.
- **ACE workers** — the threshold-decryption network. Before releasing a
  share they call `capability_access::on_ace_decryption_request_custom_flow`
  on-chain, which verifies a BLS signature over
  `BCS(SignableRequest { dst, label, user_epk, origin })` under the
  registered pubkey.

## Prerequisites

- **Node.js ≥ 18** and **pnpm**
- **Aptos CLI** — `cargo install aptos` or download from [aptos.dev](https://aptos.dev/tools/aptos-cli/)
- **For testnet:** no ACE localnet is needed. The default target is `knownDeployments.preview20260714`. To target a different ACE deployment, set `ACE_CONTRACT`, `IBE_KEYPAIR_ID`, and `VRF_KEYPAIR_ID`; optionally set `ACE_API_ENDPOINT` and `ACE_API_KEY`.

- **For localnet:** set `ACE_NETWORK=localnet` or use the `*:localnet` scripts.
  From the repo root:

  ```bash
  pnpm install
  pnpm --filter ace-scenarios run-local-network-forever
  ```

  Wait until the terminal prints `ACE local network is READY`. Leave it running
  in another terminal. The script writes `/tmp/ace-localnet-config.json` with
  both `ibeKeypairId` and `vrfKeypairId`, which the demo steps below read.

In a separate terminal:

```bash
cd examples/bearer-capability-aptos
```

## Walkthrough

### Step 1 — Generate Alice and fund her

```bash
pnpm 1-setup
```

Generates a fresh Aptos keypair for Alice, prompts you to fund her on testnet,
and writes `data/alice.json`. Idempotent: skips both if she's already
provisioned.

### Step 2 — Alice deploys `capability_access`

```bash
pnpm 2-deploy-contract
```

Copies the Move package to a tempdir, rewrites the placeholder `admin = 0xcafe`
to Alice's actual address, publishes via the Aptos CLI, then calls
`capability_access::init` to set up the singleton registry. Writes the
contract address to `data/config.json`.

### Step 3 — Alice produces the bearer capability

```bash
pnpm 3-create-capability
```

Three things happen:

1. **Encrypt** `"Lyrics for song 1: hello sunshine!"` under ACE custom flow
   with `label = "@<alice_canonical>/song-1.mp3"`.
2. **Derive** `(accessPrivateKey, accessPublicKey)` through ACE threshold VRF
   using the app contract id and that same label. Alice signs the request, and
   `capability_access::on_ace_vrf_request` rejects requests outside Alice's
   `@<alice>/...` namespace.
3. **Register** the public half on-chain at
   `<alice>::capability_access::register("song-1.mp3", accessPublicKey)`.
4. **Emit** `data/capability.json` — `{ blobSuffix, blobIdHex, ciphertextHex,
   accessPrivateKeyHex }`. `accessPrivateKeyHex` is the actual bearer token,
   serialized as a 32-byte BLS Fr scalar. This single file is the bearer
   capability: hand it to whoever should be able to read.

### Step 4 — Bob decrypts

```bash
pnpm 4-decrypt
```

The bearer of `data/capability.json` runs this. The script:

- Creates a `CustomDecryptionSession`, which owns a fresh response PKE keypair and exposes only `encPk` for proof construction.
- Signs `BCS(SignableRequest { dst, label, user_epk, origin })` with
  `accessPrivateKey`.
- Wraps `payload = BCS({ origin, sig })` and calls
  `CustomDecryptionSession.decrypt`.
- ACE workers call `capability_access::on_ace_decryption_request_custom_flow`
  on-chain, which verifies the BLS sig under the registered
  `accessPublicKey`, then release their share. The SDK reconstructs and
  decrypts.

You should see the plaintext printed: `Lyrics for song 1: hello sunshine!`.

Bob has no Aptos account, no on-chain identity, no balance — possession of
`capability.json` is the only capability.

### Step 5 — Alice rotates the access pubkey

```bash
pnpm 5-rotate
```

Alice derives a replacement key from VRF label
`@<alice_canonical>/song-1.mp3#rotation-1` and submits
`register("song-1.mp3", newAccessPublicKey)`. The contract overwrites the old
entry. The `accessPrivateKey` Bob holds is now stale.

### Step 6 — Bob's old capability no longer works

```bash
pnpm 6-decrypt-after-rotate
```

Bob runs the same decrypt flow as step 4. Workers call the hook, which
looks up the new `accessPublicKey`, finds the BLS sig doesn't verify under
it, and refuses to release shares (HTTP 403 from each worker). The script
asserts the expected failure.

### Localnet Variant

To run the same walkthrough against a local ACE network, use the localnet
scripts:

```bash
pnpm 1-setup:localnet
pnpm 2-deploy-contract:localnet
pnpm 3-create-capability:localnet
pnpm 4-decrypt:localnet
pnpm 5-rotate:localnet
pnpm 6-decrypt-after-rotate:localnet
```

## Layout

```
examples/bearer-capability-aptos/
├── README.md
├── contract/
│   ├── Move.toml                    # admin = "0xcafe" placeholder
│   └── sources/
│       └── capability_access.move    # Registry + register + VRF/custom hooks
├── package.json                     # pnpm 1-setup, 2-deploy-contract, …
├── tsconfig.json
└── scripts/
    ├── common.ts                    # shared config + bearer-token crypto
    ├── 1-setup.ts
    ├── 2-deploy-contract.ts
    ├── 3-create-capability.ts
    ├── 4-decrypt.ts
    ├── 5-rotate.ts
    └── 6-decrypt-after-rotate.ts
```

State flows via JSON files under `data/` (created on first run, gitignored):

- `data/alice.json` — Alice's account.
- `data/config.json` — deployed `capability_access` contract address.
- `data/capability.json` — the bearer capability Alice produced in step 3.

## Where to look next

- **Move contract**: `contract/sources/capability_access.move`. Unit tests
  pin the VRF owner-label policy, BLS sig binding, DST domain separation,
  BCS-encoded `SignableRequest` layout, origin check, and rotation behavior.
  Run them with
  `cd contract && aptos move test --skip-fetch-latest-git-deps`.
- **Bearer-capability crypto**: `scripts/common.ts`. Mirrors the Move
  side byte-for-byte: `SignableRequest`/`ReaderProof` classes with
  `serialize` + `toBytes`, the BLS hash-to-curve DST
  (`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`) and VRF-output-to-BLS-key
  derivation.
- **Custom-flow integration**: `capability_access::on_ace_decryption_request_custom_flow`
  is the Move hook ACE workers call before releasing a share. It mirrors what
  the basic flow's `on_ace_decryption_request` does, but with a different
  proof shape — the proof is a contract-defined `payload` (BLS sig +
  claimed origin), not a wallet sig over a canonical transcript.
