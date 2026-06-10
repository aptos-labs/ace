# ACE Tutorial — Aptos Testnet

A step-by-step walkthrough of the ACE encryption flow on Aptos, framed as a
minimal pay-to-download marketplace. You will:

1. Deploy a small Move contract (`marketplace`) that gates per-item access.
2. Encrypt two items under that contract's ACE decryption hook, listing
   each one at an APT price.
3. Watch a fresh user fail to decrypt either item.
4. Pay for one item on-chain; watch the buyer decrypt that item.
5. Confirm the buyer **still cannot** decrypt the unpaid item — domain-binding
   isolates each ciphertext to its specific item name.

The whole tutorial uses the public ACE testnet deployment, bundled in the SDK
as `ACE.knownDeployments.preview20260610`. You only need to visit the faucet
once: a single click funds **Alice** with ~10 APT, and she will send Bob a
small allowance on-chain when he shows up in step 4.

## Cast

- **Alice** — marketplace operator. Deploys the contract, encrypts and lists
  items, receives APT payments.
- **Bob** — a buyer. Generated as a fresh keypair in step 4 and funded by
  Alice with a small allowance (testnet faucets are rate-limited, so the
  tutorial avoids asking you to visit the faucet twice). He pays Alice in APT
  for one item, then runs the standard ACE decryption flow.
- **ACE workers** — the threshold-decryption network. Before releasing a key
  share they call `marketplace::on_ace_decryption_request(itemName, user, origin)` on-chain.
  No single worker can decrypt alone; Bob needs a threshold of them to agree.

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
> faucet for some APT — enough to deploy the contract, list items, and send
> Bob an allowance later.*

```bash
pnpm 1-setup
```

The script prints Alice's address, then waits for you to fund her via the
[Aptos testnet faucet](https://aptos.dev/en/network/faucet) (one click drops
~10 APT — plenty for the tutorial). Once you press Enter, the script polls
until the drop lands and saves Alice's keypair to `data/alice.json`. The
script is idempotent: if Alice is already funded on a re-run, it skips the
prompt entirely.

### Step 2 — Alice deploys `marketplace`

> *Alice deploys her marketplace module. The Move package's named address
> `admin` is rewritten to her own address on the way in, so the deployed
> module's identity is `<alice>::marketplace`. After publishing she calls
> `initialize` to create an empty catalog.*

```bash
pnpm 2-deploy-contract
```

Saves the deployed module address to `data/config.json`.

### Step 3 — Alice encrypts and lists two items

> *Alice ACE-encrypts two items (`song-1.mp3` and `song-2.mp3`). Each
> ciphertext is bound to `(marketplace, itemName)` — meaning a worker will only
> release a key share when `on_ace_decryption_request(itemName, user, origin)` returns true.
> She then lists each item on-chain at a fixed APT price.*

```bash
pnpm 3-list
```

Ciphertexts and prices are saved to `data/catalog.json`.

### Step 4 — Bob shows up, gets a small allowance from Alice, and is denied

> *Bob is generated locally. Alice transfers ~0.2 APT to him on-chain — enough
> to buy one item plus gas (the testnet faucet is rate-limited at 5 calls/day,
> so we avoid asking you to fund twice). Without buying anything yet, Bob
> attempts to decrypt song-1. ACE workers each simulate
> `marketplace::on_ace_decryption_request("song-1.mp3", bob, origin)`, which returns `false`
> because Bob isn't on the buyer list. They refuse to release key shares;
> Bob's threshold-IBE decrypt fails.*

```bash
pnpm 4-decrypt-fail
```

Bob's keypair is persisted to `data/bob.json` for later steps.

### Step 5 — Bob buys song-1

> *Bob signs a `marketplace::buy` transaction. The contract transfers
> song-1's price in APT from Bob to Alice in the same call, then pushes Bob
> onto song-1's buyer list. Note: only song-1's buyer list — song-2 is
> untouched.*

```bash
pnpm 5-buy
```

### Step 6 — Bob decrypts song-1; song-2 stays sealed

> *Bob retries the same flow as step 4, against song-1 first: this time
> `on_ace_decryption_request` returns `true`, workers release shares, and Bob
> reconstructs the threshold key. Then Bob tries the exact same flow against
> song-2 — and is denied. Same Bob, same encryption keypair, same decryption
> code path; the only difference is the item name (the encryption "domain"),
> and the on-chain check answers per-item.*

```bash
pnpm 6-decrypt
```

Expected output:

```
✓ Decryption succeeded.
  Plaintext: "Lyrics for song 1: hello sunshine!"
...
✓ Decryption denied (expected).
  Domain-binding holds: paying for one item does not unlock another.
```

This last step is the punchline: domain-binding is what makes ACE's
per-ciphertext access control meaningful.

## What's in this tutorial

```
tutorial-aptos/
├── contract/
│   ├── Move.toml                ← named address `admin` rewritten at deploy time
│   └── sources/
│       └── marketplace.move     ← Catalog, list_item, buy, ACE decryption hook
├── scripts/
│   ├── common.ts                ← paths, JSON helpers, item specs, file shapes
│   ├── 1-setup.ts               ← generate Alice, prompt fund
│   ├── 2-deploy-contract.ts     ← publish + initialize
│   ├── 3-list.ts                ← encrypt 2 items + list_item for each
│   ├── 4-decrypt-fail.ts        ← generate + fund Bob, attempt decrypt → expected fail
│   ├── 5-buy.ts                 ← Bob calls marketplace::buy on song-1
│   └── 6-decrypt.ts             ← song-1 ✓, song-2 ✗ — domain-binding demo
└── data/                         ← gitignored: alice.json, bob.json, config.json, catalog.json
```

## What this tutorial intentionally does *not* cover

- **Custom flows.** This tutorial uses the **basic flow** (proof of permission =
  Ed25519 signature on the request). For an Aptos custom-flow example, see
  [`examples/presigned-access-aptos`](../presigned-access-aptos/README.md).
- **Refunds, revocation, time locks.** A real marketplace would model these.
- **Solana.** See [`examples/pay-to-download-solana`](../pay-to-download-solana/README.md).
