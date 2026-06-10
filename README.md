# ACE

ACE is a protocol for access-controlling encrypted data with smart contracts.

> ⚠️ **Prototype**: ACE is currently a prototype and not yet ready for production use.

With ACE, dApps can support privacy scenarios like these — without any single party holding a decryption key:
- **Pay-to-decrypt**: Alice sells her album as encrypted files; Bob can only decrypt after paying.
- **Time-locked release**: A journalist encrypts a story that auto-releases on January 1, 2027. Until then, no one can decrypt it.
- **ZK-gated access**: A DeFi protocol gates content to users who can prove age ≥ 18 via a zero-knowledge proof, without revealing the actual age.
- **The general pattern**: Encrypt now; let a contract decide who can decrypt later.

This monorepo provides a TypeScript SDK, worker binary, operator CLI, and examples for Aptos and Solana.

## Design Overview

### Roles

| Role | Responsibility |
|------|---------------|
| **App developer** | Deploys an access-control contract; encrypts data; integrates the SDK for user-side decryption |
| **End user** | Satisfies the access condition (pays, passes KYC, etc.); requests decryption |
| **Operator** | Runs a worker node that holds a share of the decryption key |

### Trust Assumptions

- **Threshold honest majority**: decryption requires `t`-of-`n` worker shares. No single worker — and no coalition smaller than `t` — can decrypt alone or learn the plaintext.
- **Contract is truth**: workers trust the on-chain view function unconditionally. If it returns `true`, they release their share. The security of the system reduces to the correctness of your contract and the integrity of the chain.
- **Workers run their own fullnodes** (in production): workers that rely on a shared RPC endpoint inherit the trust assumptions of that provider.

### Interaction Flow

```
App developer                 End user                      Operators (n workers)
─────────────────────         ─────────────────────         ─────────────────────
(1) Deploy access-control
    contract on-chain

(2) Encrypt plaintext
    → publish ciphertext
                              (3) Satisfy access condition
                                  (pay, prove identity, …)

                              (4) Submit decryption request
                                  (signature or ZK proof)
                                                            (5) Each worker simulates
                                                                the fixed ACE hook
                                                                on-chain;
                                                                if true, returns an
                                                                encrypted key share

                              (6) SDK collects ≥ t shares,
                                  reconstructs key, decrypts
```

Steps 1–2 happen once per piece of content. Steps 3–6 happen each time a user decrypts.

---

## Project Structure

| Package | Description |
|---------|-------------|
| [`docs/developers/app-developer-guide`](./docs/developers/app-developer-guide) | App developer how-tos for on-chain access policies and contract-gated derivation |
| [`docs/auditor`](./docs/auditor) | Protocol specifications (cryptography, trust model, protocols, wire formats) — start here for audit |
| [`ts-sdk`](./ts-sdk) | TypeScript SDK (`@aptos-labs/ace-sdk`) |
| [`cli`](./cli) | Operator CLI (`ace`) for node onboarding and management |
| [`worker-components`](./worker-components) | Rust worker binaries (HTTP server, DKG/DKR participants) |
| [`scenarios`](./scenarios) | Local network setup scripts |
| [`examples/tutorial-aptos`](./examples/tutorial-aptos) | Step-by-step ACE walkthrough on Aptos testnet — start here |
| [`examples/presigned-access-aptos`](./examples/presigned-access-aptos) | Aptos custom-flow example with pre-signed bearer access grants |
| [`examples/pay-to-download-solana`](./examples/pay-to-download-solana) | Pay-to-download example on Solana |

---

## App Developer Guide

App developers write the on-chain policy that ACE checks before decrypting data or deriving values scoped to a contract, account, and label, then use the TypeScript SDK from the client.

Start with the guide that matches your flow:

| Guide | What it covers |
|-------|----------------|
| [`Aptos account access`](./docs/developers/app-developer-guide/ibe-aptos-basic.md) | Your Aptos contract decides whether Aptos account X can access object Y |
| [`Solana account access`](./docs/developers/app-developer-guide/ibe-solana-basic.md) | Your Solana program decides whether Solana account X can access object Y |
| [`Aptos off-chain identity access`](./docs/developers/app-developer-guide/ibe-aptos-custom.md) | Your Aptos contract decides whether off-chain identity X can access object Y |
| [`Solana off-chain identity access`](./docs/developers/app-developer-guide/ibe-solana-custom.md) | Your Solana program decides whether off-chain identity X can access object Y |
| [`Aptos-approved derivation`](./docs/developers/app-developer-guide/vrf-aptos.md) | Your Aptos contract decides who can derive values for a given contract, account, and label |

The full guide index is at [`docs/developers/app-developer-guide`](./docs/developers/app-developer-guide).

---

## Operator Guide

Joining the ACE network requires coordination with the **admin** (who controls the ACE contract) and the **existing committee** (who votes to admit you).

```
Operator                              Admin / existing committee
────────────────────────────────      ─────────────────────────────────
                                      (1) Admin shares a deployment blob:
                                          { rpcUrl, aceAddr, rpcApiKey?,
                                            gasStationKey? }

(2) `pnpm dev node new` — paste blob;
    wizard generates keys, prints
    a docker/gcloud command to
    start the worker, registers
    on-chain

(3) Share account address with admin

                                      (4) `pnpm dev proposal new` — proposes
                                          adding the new node to the
                                          committee

                                      (5) Each committee member:
                                          `pnpm dev proposal review`
                                          until threshold is reached

(6) Node joins the committee and
    participates in the next DKG
```

**Install**

The CLI isn't on npm yet. Clone the repo and install dependencies:

```bash
git clone git@github.com:aptos-labs/ace.git
cd ace
pnpm install
```

All CLI commands below run as `pnpm dev <subcommand>` from the `cli/` directory:

```bash
cd cli
pnpm dev <subcommand>
```

To update later: `git pull && pnpm install`.

**Onboard a new node**

```bash
pnpm dev node new
```

The guided wizard asks for the deployment blob from the admin, generates node keys, prints the `docker run` or `gcloud run deploy` command to start the worker, and registers your node on-chain. At the end it prints your **account address** — send this to the admin.

**Useful commands**

```bash
pnpm dev network-status [-w]              # committee, epoch, active proposals, contract version
pnpm dev node status    [-w]              # your node's registration and key state
pnpm dev proposal new                     # propose a committee change (committee members or admin)
pnpm dev proposal review [-s <session>]   # review and vote on a proposal (interactive TUI)
pnpm dev node edit                        # update image, API key, or gas station key
pnpm dev node log [--since <t>] [--until <t>] [-w]   # stream or query node logs
pnpm dev node ls                          # list saved node profiles
pnpm dev node delete <alias>              # delete a saved node profile
pnpm dev node default <alias>             # set the default node profile

# Admin (deployment) side
pnpm dev deployment new                   # full deployment wizard (requires tagged clean commit)
pnpm dev deployment update-contracts      # republish all packages at NEXT_RELEASE version
pnpm dev deployment edit                  # edit RPC URL, API keys, alias of a deployment profile
pnpm dev deployment ls                    # list deployment profiles
pnpm dev deployment delete <alias>        # delete a deployment profile (local-only)
pnpm dev deployment default <alias>       # set the default deployment profile
```

**Fullnodes** *(optional for testing, recommended for production)*

> ⚠️ Workers that rely on a shared RPC endpoint inherit its trust assumptions — a malicious provider could return false permission results.

- **Aptos:** See [Run a public fullnode](https://aptos.dev/network/nodes/full-node)
- **Solana:** See [Setup a Solana RPC node](https://docs.solanalabs.com/operations/setup-an-rpc-node)

---

## Examples

| Example | Flow | Chain | Description |
|---------|------|-------|-------------|
| [tutorial-aptos](./examples/tutorial-aptos) | Basic | Aptos | Step-by-step tutorial — a minimal pay-to-download marketplace; demonstrates per-item label binding. One faucet click for Alice and go. |
| [presigned-access-aptos](./examples/presigned-access-aptos) | Custom + VRF | Aptos | Pre-signed access grants backed by ACE VRF-derived per-blob keys |
| [pay-to-download-solana](./examples/pay-to-download-solana) | Basic | Solana | Pay-to-download with Anchor programs |

## License

Apache 2.0
