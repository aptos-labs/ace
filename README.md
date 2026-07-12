# ACE

ACE is a protocol for contract-approved threshold secret derivation with smart contracts.

> Warning: ACE is currently a prototype and not yet ready for production use.

With ACE, dApps can derive deterministic bytes scoped to an app contract and label, while no single worker holds the master secret:

- **Per-object access keys**: derive stable key material for an owner and blob id only when the app contract approves.
- **Contract-scoped randomness**: derive app-specific randomness tied to on-chain policy.
- **Rotatable committees**: keep the same secret lineage while DKG/DKR resharing moves custody between worker committees.

This monorepo provides a TypeScript SDK, worker binaries, operator CLI, and local scenarios for Aptos-backed ACE deployments.

## Design Overview

### Roles

| Role | Responsibility |
|------|---------------|
| **App developer** | Deploys a Move policy hook and integrates the SDK for contract-approved derivation |
| **End user** | Signs a derivation request for a contract and label, binding the Aptos account that the app hook authorizes |
| **Operator** | Runs a worker node that holds a share of the threshold secret |

### Trust Assumptions

- **Threshold honest majority**: derivation requires `t`-of-`n` worker shares. No single worker, and no coalition smaller than `t`, can derive alone.
- **Contract is truth**: workers trust the on-chain view function unconditionally. If it returns `true`, they return their encrypted share. The security of the system reduces to the correctness of your contract and the integrity of the chain.
- **Workers run their own fullnodes** in production: workers that rely on a shared RPC endpoint inherit the trust assumptions of that provider.

### Interaction Flow

```text
App developer                 End user                      Operators (n workers)
---------------------         ---------------------         ---------------------
(1) Deploy policy
    contract on-chain

(2) Choose labels and
    application mapping
                              (3) Sign derivation request
                                  for contract/label and
                                  authorized account

                              (4) Submit encrypted worker
                                  request
                                                            (5) Each worker simulates
                                                                the fixed ACE hook
                                                                on-chain;
                                                                if true, returns an
                                                                encrypted VRF share

                              (6) SDK collects >= t shares,
                                  verifies, combines, and
                                  returns derived bytes
```

## Project Structure

| Package | Description |
|---------|-------------|
| [`docs/developers/app-developer-guide`](./docs/developers/app-developer-guide) | App developer guide for Aptos-approved derivation |
| [`docs/auditor`](./docs/auditor) | Protocol specifications for audit |
| [`ts-sdk`](./ts-sdk) | TypeScript SDK (`@aptos-labs/ace-sdk`) |
| [`cli`](./cli) | Operator CLI (`ace`) for node onboarding and management |
| [`worker-components`](./worker-components) | Rust worker binaries for VSS, DKG, DKR, network service, and storage |
| [`scenarios`](./scenarios) | Local network and end-to-end protocol scenarios |

## App Developer Guide

App developers write the on-chain policy that ACE checks before deriving values scoped to a contract and label, then use the TypeScript SDK from the client. The request also carries an Aptos account for authorization; include that account in the label if the output itself must be account-specific.

Start here:

| Guide | What it covers |
|-------|----------------|
| [`Aptos-approved derivation`](./docs/developers/app-developer-guide/vrf-aptos.md) | Your Aptos contract decides who can derive values for a given contract and label |

The full guide index is at [`docs/developers/app-developer-guide`](./docs/developers/app-developer-guide).

## Operator Guide

Joining the ACE network requires coordination with the **admin** who controls the ACE contract and the **existing committee** who votes to admit you.

```text
Operator                              Admin / existing committee
--------------------------------      ---------------------------------
                                      (1) Admin shares a deployment blob:
                                          { rpcUrl, aceAddr, rpcApiKey?,
                                            gasStationKey? }

(2) `pnpm dev node new` - paste blob;
    wizard generates keys, prints
    a docker/gcloud command to
    start the worker, registers
    on-chain

(3) Share account address with admin

                                      (4) `pnpm dev proposal new` - proposes
                                          adding the new node to the
                                          committee

                                      (5) Each committee member:
                                          `pnpm dev proposal review`
                                          until threshold is reached

(6) Node joins the committee and
    participates in the next DKG
```

### Install

The CLI is not on npm yet. Clone the repo and install dependencies:

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

### Useful Commands

```bash
pnpm dev network-status [-w]              # committee, epoch, active proposals, contract version
pnpm dev node status    [-w]              # your node's registration and key state
pnpm dev proposal new                     # propose a committee change
pnpm dev proposal review [-s <session>]   # review and vote on a proposal
pnpm dev node edit                        # update image, API key, or gas station key
pnpm dev node log [--since <t>] [--until <t>] [-w]   # stream or query node logs
pnpm dev node ls                          # list saved node profiles
pnpm dev node delete <alias>              # delete a saved node profile
pnpm dev node default <alias>             # set the default node profile

# Admin side
pnpm dev deployment new
pnpm dev deployment update-contracts
pnpm dev deployment edit
pnpm dev deployment ls
pnpm dev deployment delete <alias>
pnpm dev deployment default <alias>
```

### Fullnodes

Workers that rely on a shared RPC endpoint inherit its trust assumptions. Production operators should run or otherwise trust their Aptos fullnode.

- Aptos: [Run a public fullnode](https://aptos.dev/network/nodes/full-node)

## Local Scenarios

The `scenarios/` package contains the maintained end-to-end coverage, including offchain VSS, DKG, DKR, network epoch changes, and threshold VRF derivation.

## License

Apache 2.0
