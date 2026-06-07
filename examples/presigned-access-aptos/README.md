# Pre-Signed Access — Aptos

A step-by-step demo of the **bearer-token / "pre-signed URL"** pattern on top
of ACE — modeled on AWS S3 pre-signed URLs. The data owner uploads an
encrypted blob, derives a per-blob keypair via threshold VRF, and hands the
*private* half to a reader out-of-band. Anyone holding that private half can
decrypt; no on-chain identity is required from the reader.

You will:

1. Deploy a small Move contract (`presigned_access`) that stores one BLS12-381
   pubkey per blob and exposes the ACE custom-flow + tVRF hooks.
2. Encrypt a blob, derive a deterministic `(accessPrivateKey, accessPublicKey)`
   from `(keypair_id, contract_id, owner_addr, blob_suffix)` via ACE's
   threshold VRF, and register `accessPublicKey` on-chain.
3. Hand the resulting grant (a single JSON file) to a reader and watch them
   decrypt with no Aptos account of their own.
4. Rotate the on-chain pubkey and watch the old grant stop working.

The demo runs against a **local** ACE network (you'll bring it up with
`pnpm --filter ace-scenarios run-local-network-forever`).

## How it works

The owner-side flow:

```text
encrypt(plaintext) ──→ ciphertext        (ACE custom flow t-IBE)
tVRF(keypair_id, contract_id, owner, blob_suffix)
   └─→ vrfBytes ──→ (accessPrivateKey, accessPublicKey)  (BLS12-381)
register(blob_suffix, accessPublicKey)   (on-chain)
grant.json = { blobIdHex, ciphertextHex, accessPrivateKeyHex }
```

The reader-side flow:

```text
parse grant.json
sign  BCS(SignableRequest { dst, label, user_epk, origin })
        with accessPrivateKey (BLS sig in G2)
payload = BCS({ origin, sig })
ACE.tIBEforAptos.decryptCustomFlow({ label, encPk, encSk, payload, … })
   └─→ workers call presigned_access::on_ace_decryption_request_custom_flow
        which verifies the sig under the registered accessPublicKey
   └─→ plaintext
```

Three properties:

- **Deterministic derivation.** Re-running step 3 produces the exact same
  `accessPrivateKey` — the owner never has to store it. The VRF binds it to
  `(keypair_id, contract_id, owner, blob_suffix)`; same inputs → same scalar.
- **Bearer-token semantics.** The reader needs no on-chain identity. Whoever
  holds the key can sign and decrypt.
- **Revocation by overwrite.** Re-registering a new `accessPublicKey` under
  the same `blob_suffix` invalidates the old `accessPrivateKey` immediately.

## Cast

- **Alice** — data owner. Deploys the contract, encrypts the blob, derives the
  access keypair, registers the public half, and emits the grant.
- **Bob** — reader. Has no on-chain identity. Reads `data/grant.json` and runs
  one script to decrypt.
- **ACE workers** — the threshold-decryption network. Before releasing a
  share they call `presigned_access::on_ace_decryption_request_custom_flow`
  on-chain, which verifies a BLS signature over
  `BCS(SignableRequest { dst, label, user_epk, origin })` under the
  registered pubkey.

## Prerequisites

- **Node.js ≥ 18** and **pnpm**
- **Aptos CLI** — `cargo install aptos` or download from [aptos.dev](https://aptos.dev/tools/aptos-cli/)
- **A running ACE localnet.** From the repo root:

  ```bash
  pnpm install
  pnpm --filter ace-scenarios run-local-network-forever
  ```

  Wait for the `ACE local network is READY` banner. Leave it running in
  another terminal. The script writes `/tmp/ace-localnet-config.json`,
  which the demo steps below read.

In a separate terminal:

```bash
cd examples/presigned-access-aptos/demo-cli-flow
```

## Walkthrough

### Step 1 — Generate Alice and fund her

```bash
pnpm 1-setup
```

Generates a fresh Aptos keypair for Alice, funds her from the localnet faucet
(~2 APT — enough to deploy + register + rotate), and writes
`data/alice.json`. Idempotent: skips both if she's already provisioned.

### Step 2 — Alice deploys `presigned_access`

```bash
pnpm 2-deploy-contract
```

Copies the Move package to a tempdir, rewrites the placeholder `admin = 0xcafe`
to Alice's actual address, publishes via the Aptos CLI, then calls
`presigned_access::init` to set up the singleton registry. Writes the
contract address to `data/config.json`.

### Step 3 — Alice produces the pre-signed grant

```bash
pnpm 3-grant
```

Three things happen:

1. **Encrypt** `"Lyrics for song 1: hello sunshine!"` under ACE custom flow
   with `label = "@<alice_canonical>/song-1.mp3"`.
2. **Derive** `(accessPrivateKey, accessPublicKey)` via ACE's threshold VRF.
   The owner signs the canonical request bytes (`"0x" + hex(BCS(payload))`)
   with her Aptos account; workers verify her identity, return their VRF
   shares, and the SDK reconstructs 32 deterministic bytes. The first 32-bit
   chunk reduces mod the BLS Fr order to give `accessPrivateKey`;
   `accessPublicKey = accessPrivateKey · G1`.
3. **Register** the public half on-chain at
   `<alice>::presigned_access::register("song-1.mp3", accessPublicKey)`.
4. **Emit** `data/grant.json` — `{ blobSuffix, blobIdHex, ciphertextHex,
   accessPrivateKeyHex }`. This single file is the pre-signed URL: hand it
   to whoever should be able to read.

### Step 4 — Bob decrypts

```bash
pnpm 4-decrypt
```

The bearer of `data/grant.json` runs this. The script:

- Generates a fresh ephemeral PKE keypair (`encPk`, `encSk`) for the response.
- Signs `BCS(SignableRequest { dst, label, user_epk, origin })` with
  `accessPrivateKey`.
- Wraps `payload = BCS({ origin, sig })` and calls
  `ACE.tIBEforAptos.decryptCustomFlow`.
- ACE workers call `presigned_access::on_ace_decryption_request_custom_flow`
  on-chain, which verifies the BLS sig under the registered
  `accessPublicKey`, then release their share. The SDK reconstructs and
  decrypts.

You should see the plaintext printed: `Lyrics for song 1: hello sunshine!`.

Bob has no Aptos account, no on-chain identity, no balance — possession of
`grant.json` is the only capability.

### Step 5 — Alice rotates the access pubkey

```bash
pnpm 5-rotate
```

Alice picks a fresh scalar and submits
`register("song-1.mp3", newAccessPublicKey)`. The contract overwrites the
old entry. The `accessPrivateKey` Bob holds is now stale.

### Step 6 — Bob's old grant no longer works

```bash
pnpm 6-decrypt-after-rotate
```

Bob runs the same decrypt flow as step 4. Workers call the hook, which
looks up the new `accessPublicKey`, finds the BLS sig doesn't verify under
it, and refuses to release shares (HTTP 403 from each worker). The script
asserts the expected failure.

## Layout

```
examples/presigned-access-aptos/
├── README.md
├── contract/
│   ├── Move.toml                    # admin = "0xcafe" placeholder
│   └── sources/
│       └── presigned_access.move    # Registry + register + custom-flow hook
└── demo-cli-flow/
    ├── package.json                 # pnpm 1-setup, 2-deploy-contract, …
    ├── tsconfig.json
    └── scripts/
        ├── common.ts                # shared config + bearer-token crypto
        ├── 1-setup.ts
        ├── 2-deploy-contract.ts
        ├── 3-grant.ts
        ├── 4-decrypt.ts
        ├── 5-rotate.ts
        └── 6-decrypt-after-rotate.ts
```

State flows via JSON files under `data/` (created on first run, gitignored):

- `data/alice.json` — Alice's account.
- `data/config.json` — deployed `presigned_access` contract address.
- `data/grant.json` — the pre-signed grant Alice produced in step 3.

## Where to look next

- **Move contract**: `contract/sources/presigned_access.move`. Six unit tests
  pin the BLS sig binding, DST domain separation, BCS-encoded `SignableRequest`
  layout, origin check, and rotation behavior. Run them with
  `cd contract && aptos move test --skip-fetch-latest-git-deps`.
- **Bearer-token crypto**: `demo-cli-flow/scripts/common.ts`. Mirrors the Move
  side byte-for-byte: `SignableRequest`/`ReaderProof` classes with
  `serialize` + `toBytes`, the BLS hash-to-curve DST
  (`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_`), and the VRF-output →
  scalar reduction.
- **Custom-flow integration**: `presigned_access::on_ace_decryption_request_custom_flow`
  is the Move hook ACE workers call before releasing a share. It mirrors what
  the basic flow's `on_ace_decryption_request` does, but with a different
  proof shape — the proof is a contract-defined `payload` (BLS sig +
  claimed origin), not a wallet sig over a canonical transcript.
