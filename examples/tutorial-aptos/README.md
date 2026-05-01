# ACE Tutorial — Aptos Testnet

A step-by-step walkthrough of the ACE encryption flow on Aptos. You will:

1. Deploy a small Move contract (`simple_acl`) that gates a blob behind an allowlist.
2. Encrypt a secret under that contract's `check_permission` view.
3. Watch a fresh user fail to decrypt.
4. Add the user to the allowlist; watch them succeed.
5. Revoke access; watch them fail again.

The whole tutorial uses the public ACE testnet deployment, bundled in the SDK
as `ACE.knownDeployments.preview20260501`. You only need to fund **one** account
(Alice) with ~2 APT at the start — Bob's keypair is generated locally and never
sends an on-chain transaction.

## Cast

- **Alice** — content owner. Deploys the contract, encrypts a secret, manages
  the allowlist. The only account that needs APT.
- **Bob** — a curious would-be reader. Generated as a fresh keypair in step 4.
  Signs an off-chain proof when requesting decryption from ACE workers; never
  pays gas.
- **ACE workers** — the threshold-decryption network. Before releasing a key
  share they call `simple_acl::check_permission(user, domain)` on-chain. No
  single worker can decrypt alone; Bob needs a threshold of them to agree.

## Prerequisites

- **Node.js ≥ 18** and **pnpm**
- **Aptos CLI** — `cargo install aptos` or download from [aptos.dev](https://aptos.dev/tools/aptos-cli/)

Install dependencies from the repo root:

```bash
pnpm install
cd examples/tutorial-aptos
```

## Walkthrough

### Step 1 — Generate Alice's keypair and fund it

> *Alice is opening shop. She generates a fresh keypair on testnet and asks the
> faucet for ~2 APT — enough to deploy the contract and run a few transactions.*

```bash
pnpm 1-setup
```

The script prints Alice's address, then waits for you to fund her via the
[Aptos testnet faucet](https://aptos.dev/en/network/faucet) (the faucet hands
out 1 APT per click — click twice). Once you press Enter, the script verifies
the balance and saves Alice's keypair to `data/alice.json`.

### Step 2 — Alice deploys `simple_acl`

> *Alice deploys her access-control module. The Move package's named address
> `admin` is rewritten to her own address on the way in, so the deployed
> module's identity is `<alice>::simple_acl`. After publishing she calls
> `initialize` to create an empty blob registry.*

```bash
pnpm 2-deploy-contract
```

Saves the deployed module address to `data/config.json`.

### Step 3 — Alice encrypts and registers the blob

> *Alice ACE-encrypts her secret under the policy
> `(simple_acl::check_permission, blobName)`. Then she registers the blob
> on-chain. The blob's allowlist starts empty — only Alice (the owner) can
> decrypt.*

```bash
pnpm 3-encrypt
```

The ciphertext is saved to `data/blob.json`.

### Step 4 — Bob attempts to decrypt (and is denied)

> *Bob shows up out of nowhere, generates his own keypair, and tries to decrypt.
> ACE workers each simulate `simple_acl::check_permission(bob, blobName)` on
> testnet, which returns `false` because Bob isn't on the list. They refuse to
> release key shares; Bob's threshold-IBE decrypt fails.*

```bash
pnpm 4-decrypt-fail
```

Bob's keypair is persisted to `data/bob.json` for later steps. Bob never sends
a transaction — his only on-chain footprint is the address that workers see in
the proof-of-permission signature.

### Step 5 — Alice grants Bob access

> *Convinced Bob is who he says he is, Alice adds him to the allowlist.*

```bash
pnpm 5-grant-access
```

### Step 6 — Bob decrypts successfully

> *Bob retries with the same proof flow as before. This time the on-chain
> `check_permission` returns `true`, workers release their key shares, and Bob
> reconstructs the threshold key and decrypts the ciphertext.*

```bash
pnpm 6-decrypt-success
```

Expected output:

```
✓ Decryption succeeded.
  Plaintext: "Hello from the ACE tutorial!"
```

### Step 7 — Alice revokes; Bob fails again

> *Access is not a one-time grant. Every decryption request triggers a fresh
> on-chain check. Alice removes Bob from the allowlist and Bob's next attempt
> fails — even though he held the same ciphertext and credentials moments ago.*

```bash
pnpm 7-revoke
```

## What's in this tutorial

```
tutorial-aptos/
├── contract/
│   ├── Move.toml               ← named address `admin` rewritten at deploy time
│   └── sources/
│       └── simple_acl.move     ← Registry, register_blob, grant/revoke,
│                                  check_permission view (the ACE hook)
├── scripts/
│   ├── common.ts               ← paths, JSON helpers, persona file shapes
│   ├── 1-setup.ts              ← generate Alice, prompt fund
│   ├── 2-deploy-contract.ts    ← publish + initialize
│   ├── 3-encrypt.ts            ← ACE encrypt + register_blob
│   ├── 4-decrypt-fail.ts       ← generate Bob, attempt decrypt → expected fail
│   ├── 5-grant-access.ts       ← Alice adds Bob to allowlist
│   ├── 6-decrypt-success.ts    ← Bob retries → success
│   └── 7-revoke.ts             ← Alice removes Bob, Bob retries → expected fail
└── data/                        ← gitignored: alice.json, bob.json, config.json, blob.json
```

## What this tutorial intentionally does *not* cover

- **Custom flows.** This tutorial uses the **basic flow** (proof of permission =
  Ed25519 signature on the request). For ZK-proof-based ACLs see
  [`examples/zk-kyc`](../zk-kyc/README.md).
- **Pay-to-download / time locks.** See
  [`examples/shelby-explorer-acl-aptos`](../shelby-explorer-acl-aptos/README.md)
  for an access_control module with PayToDownload and TimeLock policies.
- **Solana.** See [`examples/pay-to-download-solana`](../pay-to-download-solana/README.md).
