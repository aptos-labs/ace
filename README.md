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
                                                                check_permission /
                                                                check_acl on-chain;
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
| [`ts-sdk`](./ts-sdk) | TypeScript SDK (`@aptos-labs/ace-sdk`) |
| [`operator-cli`](./operator-cli) | Operator CLI (`ace`) for node onboarding and management |
| [`worker-components`](./worker-components) | Rust worker binaries (HTTP server, DKG/DKR participants) |
| [`scenarios`](./scenarios) | Local network setup scripts |
| [`examples/tutorial-aptos`](./examples/tutorial-aptos) | Step-by-step ACE walkthrough on Aptos testnet — start here |
| [`examples/shelby-explorer-acl-aptos`](./examples/shelby-explorer-acl-aptos) | ACE ACL module from Shelby Explorer (allowlist / time-lock / pay-to-download) |
| [`examples/pay-to-download-solana`](./examples/pay-to-download-solana) | Pay-to-download example on Solana |
| [`examples/zk-kyc`](./examples/zk-kyc) | Age-gated decryption with Groth16 ZK proofs |

---

## App Developer Guide

Your job as an app developer is to deploy a Move contract with a single `#[view]` function that decides whether a given decryption request is allowed. ACE calls that function on-chain; if it returns `true`, the key is released. You also use the TypeScript SDK to encrypt and decrypt.

ACE supports two flows depending on what your contract needs to verify:

- **Basic Flow** — your contract receives the requestor's Aptos address (extracted from their signature). Good for allowlists, time-locks, and pay-to-download.
- **Custom Flow** — your contract receives an arbitrary `payload` byte string submitted by the requestor. Good for ZK proofs, Merkle witnesses, and other cryptographic credentials.

### The Contract Interface

This is the most important part. Your view function is the sole access gate — get the signature right.

**Basic Flow** — fixed signature, three parameters:

```move
#[view]
public fun check_permission(
    label: vector<u8>,     // the domain the ciphertext was encrypted under
    enc_pk: vector<u8>,    // requestor's ephemeral public key for this session
    user_addr: address,    // Aptos address that signed the decryption request
): bool
```

- `label` identifies what is being decrypted — it equals the `domain` bytes you passed to `encrypt`. Use it to look up your access records.
- `user_addr` is who is asking. Check your payment table, allowlist, etc. against this.
- `enc_pk` is the requestor's session key. Most contracts ignore it; it is there if you need to bind external proofs to a specific session (see Custom Flow).

**Custom Flow** — fixed signature, three parameters:

```move
#[view]
public fun check_acl(
    label: vector<u8>,     // the domain the ciphertext was encrypted under
    enc_pk: vector<u8>,    // requestor's ephemeral public key for this session
    payload: vector<u8>,   // arbitrary bytes submitted by the requestor
): bool
```

- `label` and `enc_pk` are the same as above.
- `payload` is whatever the requestor sends — a Groth16 proof, a Merkle proof, a signed attestation, etc. Your contract is fully responsible for deserializing and verifying it. A ZK proof should bind to `enc_pk` so that a captured proof cannot be replayed by a different requestor.

The function name can be anything — you pass it to the SDK at encrypt/decrypt time.

### SDK Usage

```typescript
import * as ACE from "@aptos-labs/ace-sdk";
import { AccountAddress } from "@aptos-labs/ts-sdk";

const aceDeployment = new ACE.AceDeployment({
    apiEndpoint: "https://fullnode.mainnet.aptoslabs.com/v1",
    contractAddr: AccountAddress.fromString("0x<ace-contract-addr>"),
});
```

For testnet, the SDK ships a registry of known deployments — skip the manual setup:

```typescript
const { aceDeployment, keypairId, chainId } = ACE.knownDeployments.preview20260501;
```

**Encrypt (both flows)**

```typescript
const ciphertext = (await ACE.AptosBasicFlow.encrypt({   // or AptosCustomFlow.encrypt
    aceDeployment,
    keypairId: AccountAddress.fromString("0x<keypair-id>"),
    chainId: 1,
    moduleAddr: AccountAddress.fromString("0xcafe"),
    moduleName: "album_store",
    functionName: "check_permission",
    domain: new TextEncoder().encode("album-001"),        // becomes `label` in your contract
    plaintext: albumData,
})).unwrapOrThrow("encryption failed");
```

**Decrypt — Basic Flow**

The requestor signs a challenge message that proves their identity:

```typescript
const session = ACE.AptosBasicFlow.DecryptionSession.create({
    aceDeployment,
    keypairId: AccountAddress.fromString("0x<keypair-id>"),
    chainId: 1,
    moduleAddr: AccountAddress.fromString("0xcafe"),
    moduleName: "album_store",
    functionName: "check_permission",
    domain: new TextEncoder().encode("album-001"),
    ciphertext,
});

const messageToSign = await session.getRequestToSign();
const plaintext = (await session.decryptWithProof({
    userAddr: bob.accountAddress,
    publicKey: bob.publicKey,
    signature: bob.sign(messageToSign),
})).unwrapOrThrow("decryption failed");
```

**Decrypt — Custom Flow**

The requestor builds a payload (e.g., a ZK proof) and supplies an ephemeral keypair that the payload should be bound to:

```typescript
const { encryptionKey, decryptionKey } = ACE.pke.keygen();
const encPk = new Uint8Array(encryptionKey.toBytes());
const encSk = new Uint8Array(decryptionKey.toBytes());

const payload: Uint8Array = buildMyPayload(encPk, ...); // bind proof to encPk

const plaintext = await ACE.AptosCustomFlow.decrypt({
    ciphertext,
    label: new TextEncoder().encode("my-label"),
    encPk,
    encSk,
    payload,
    aceDeployment,
    keypairId: AccountAddress.fromString("0x<keypair-id>"),
    chainId: 1,
    moduleAddr: AccountAddress.fromString("0xcafe"),
    moduleName: "my_verifier",
    functionName: "check_acl",
});
```

### Local Development

Start a full ACE network locally (3 workers + Aptos localnet):

```bash
cd scenarios
pnpm install
pnpm run-local-network-forever
```

Wait for the `ACE local network is READY` banner. The network writes `contractAddr` and `keypairId` to `/tmp/ace-localnet-config.json`.

---

## Operator Guide

Joining the ACE network requires coordination with the **admin** (who controls the ACE contract) and the **existing committee** (who votes to admit you).

```
Operator                              Admin / existing committee
────────────────────────────────      ─────────────────────────────────
                                      (1) Admin shares a deployment blob:
                                          { rpcUrl, aceAddr, rpcApiKey?,
                                            gasStationKey? }

(2) `ace new-node` — paste blob;
    wizard generates keys, prints
    a docker/gcloud command to
    start the worker, registers
    on-chain

(3) Share account address with admin

                                      (4) `ace new-proposal` — proposes
                                          adding the new node to the
                                          committee

                                      (5) Each committee member:
                                          `ace review-proposal`
                                          until threshold is reached

(6) Node joins the committee and
    participates in the next DKG
```

**Install**

The CLI isn't on npm yet — clone the repo and build:

```bash
git clone git@github.com:aptos-labs/ace.git
cd ace
pnpm install
pnpm --filter @aptos-labs/ace-cli build
cd operator-cli && npm link
```

`npm link` puts `ace` on your PATH. To update later: `git pull && pnpm install && pnpm --filter @aptos-labs/ace-cli build`.

**Onboard a new node**

```bash
ace new-node
```

The guided wizard asks for the deployment blob from the admin, generates node keys, prints the `docker run` or `gcloud run deploy` command to start the worker, and registers your node on-chain. At the end it prints your **account address** — send this to the admin.

**Useful commands**

```bash
ace network-status [-w]              # committee, epoch, active proposals
ace node-status    [-w]              # your node's registration and key state
ace new-proposal                     # propose a committee change (committee members only)
ace review-proposal [-s <session>]   # review and vote on a proposal (interactive TUI)
ace edit-node                        # update image, API key, or gas station key
ace log [--since <t>] [--until <t>] [-w]  # stream or query node logs
ace profile list                     # list saved node profiles
ace profile delete <alias>           # delete a saved profile
ace profile default <alias>          # set the default profile
```

**Fullnodes** *(optional for testing, recommended for production)*

> ⚠️ Workers that rely on a shared RPC endpoint inherit its trust assumptions — a malicious provider could return false permission results.

- **Aptos:** See [Run a public fullnode](https://aptos.dev/network/nodes/full-node)
- **Solana:** See [Setup a Solana RPC node](https://docs.solanalabs.com/operations/setup-an-rpc-node)

---

## Examples

| Example | Flow | Chain | Description |
|---------|------|-------|-------------|
| [tutorial-aptos](./examples/tutorial-aptos) | Basic | Aptos | Step-by-step tutorial — deploy contract, encrypt, decrypt, grant/revoke. Fund **one** account with ~2 APT and go. |
| [shelby-explorer-acl-aptos](./examples/shelby-explorer-acl-aptos) | Basic | Aptos | ACE ACL module from [Shelby Explorer](https://explorer.shelby.xyz/) — allowlist / time-lock / pay-to-download |
| [pay-to-download-solana](./examples/pay-to-download-solana) | Basic | Solana | Pay-to-download with Anchor programs |
| [zk-kyc](./examples/zk-kyc) | Custom | Aptos | Age-gated decryption with Groth16 ZK proofs |

## License

Apache 2.0
