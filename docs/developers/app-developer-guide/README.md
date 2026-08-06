# App Developer Guide

ACE lets an app encrypt data or derive values scoped to a contract, account, and label, then ask an on-chain policy whether a user is allowed to receive the result. Pick the guide that matches your chain and proof style.

| Guide | Use when | Typical apps |
|-------|----------|--------------|
| [`ibe-aptos-basic.md`](./ibe-aptos-basic.md) | Your Aptos contract decides whether Aptos account X can access object Y | pay-to-download, allowlists, time locks, subscriptions |
| [`ibe-solana-basic.md`](./ibe-solana-basic.md) | Your Solana program decides whether Solana account X can access object Y | pay-to-download, receipt-based access, PDA-backed ACLs |
| [`ibe-aptos-custom.md`](./ibe-aptos-custom.md) | Your Aptos contract decides whether off-chain identity X can access object Y | ZK-gated access, signed attestations, bearer-token style grants |
| [`ibe-solana-custom.md`](./ibe-solana-custom.md) | Your Solana program decides whether off-chain identity X can access object Y | ZK proofs, coupon codes, custom ACLs, off-chain credentials |
| [`vrf-aptos.md`](./vrf-aptos.md) | Your Aptos contract decides who can derive values for a given contract, account, and label | per-object signing keys, deterministic grants, app-scoped randomness |

## Vocabulary

- `aceDeployment`: the ACE network endpoint and ACE contract address. During preview, use the value provided by the ACE team or by a ready-to-run example/localnet config.
- `keypairId`: the ACE encryption key identifier, provided by the same ACE deployment or localnet config.
- `label`: app-chosen bytes that identify the encrypted object or VRF derivation. Your contract usually uses this as the lookup key.
- `contract id`: the app contract or program ACE checks for access decisions. Aptos uses `(chainId, moduleAddr, moduleName)`. Solana uses `(knownChainName, programId)`.
- `origin`: an Aptos wallet/WebAuthn application origin extracted by ACE from the signed message. Solana proofs do not currently include this field automatically.

## Connecting to the ACE network

Every SDK call takes an `aceDeployment`. Beyond `apiEndpoint` and `contractAddr`, three optional
fields control how the SDK reaches the network to read ACE config (epoch, node endpoints, keys).
They fall into **two mutually exclusive transport paths**:

| Path | When it is used | Transport | `clientConfig` applies? |
|------|-----------------|-----------|--------------------------|
| **Fullnode** | `apiKey` is set, **or** no `discoveryUrl` | Aptos client → fullnode REST view calls | Yes |
| **Discovery** | `discoveryUrl` is set **and** no `apiKey` | plain `fetch` of one aggregated snapshot | No |

- **`apiKey`** — attaches `Authorization: Bearer` to fullnode requests. Needed on rate-limited public
  endpoints. Cannot ship safely in client-side code.
- **`discoveryUrl`** — points at an ACE discovery service (needs no node API key). On this path the client makes
  **zero fullnode calls** (so no API key, no backend proxy), fetching one cached snapshot instead.
  Normally pre-filled in the `knownDeployments` entry, so upgrading the SDK is enough to benefit.
- **`clientConfig`** — forwarded verbatim to `AptosConfig` for the fullnode client (proxy, extra
  headers, `http2: false` for runtimes without HTTP/2).

Precedence when resolving the path: **`apiKey` → `discoveryUrl` → anonymous fullnode.** An explicit
`apiKey` always wins, so providing one keeps you on the fullnode path even if a `discoveryUrl` exists.

Practical consequences of the two-path split:

- `clientConfig` only affects the fullnode path. On the discovery path the SDK never builds an Aptos
  client, so proxy/header/HTTP-2 settings there have no effect — they are *not applicable* rather
  than silently dropped.
- A runtime **without HTTP/2** does not hang on the discovery path: it uses the platform `fetch`
  (HTTP/1.1 by default) and never touches the fullnode client that would attempt HTTP/2. (On the
  fullnode path, such a runtime should set `clientConfig: { http2: false }`.)
- Worker share requests (the direct calls to ACE nodes during decryption/VRF) are plain `fetch`
  POSTs on **both** paths and never need an API key.

```typescript
// No node API key: fullnode reads resolve from the discovery service (usually pre-set in knownDeployments).
const aceDeployment = new ACE.AceDeployment({
  apiEndpoint: "https://api.testnet.aptoslabs.com/v1", // still the fallback if no discoveryUrl/apiKey
  contractAddr: AccountAddress.fromString("0x<ace-contract-address>"),
  discoveryUrl: "https://<ace-discovery-host>",
});

// Fullnode with an HTTP/2 opt-out (e.g. a runtime that cannot negotiate HTTP/2):
const viaFullnode = knownDeployments["<name>"]
  .withApiKey("<node-api-key>")
  .withClientConfig({ http2: false });
```

## Common Build Order

1. Design your access policy data model.
2. Implement the ACE hook for the flow you chose.
3. Deploy the contract or program and initialize its policy state.
4. Encrypt or derive with the SDK using the same contract id and label your policy expects.
5. Build the client decryption or derivation path.
6. Deploy the web app or CLI wrapper, get the stable application origin, then configure the contract to accept only that origin when the flow carries one.

The examples linked from each guide are the best place to copy exact localnet setup commands.
