# App Developer Guide

ACE exposes Aptos-authorized threshold IBE decryption and threshold VRF derivation. Your app contract decides whether a request is allowed; the SDK verifies worker shares before combining them.

| Guide | Use when | Typical apps |
|-------|----------|--------------|
| [`ibe-aptos-basic.md`](./ibe-aptos-basic.md) | An Aptos account signs a decryption request and your hook authorizes that account | allowlists, paid content, timelocks |
| [`ibe-aptos-custom.md`](./ibe-aptos-custom.md) | Your app supplies its own proof bytes and verification hook | bearer capabilities, ZK authorization, attestations |
| [`vrf-aptos.md`](./vrf-aptos.md) | Your Aptos contract decides who can derive values for a given contract and label | per-object keys, deterministic app values, app-scoped randomness |

## Vocabulary

- `aceDeployment`: the ACE network endpoint and ACE contract address.
- `keypairId`: the ACE secret identifier, originally created by DKG and retained across DKR reshares.
- `label`: app-chosen bytes that identify the derivation purpose. Include the account in the label if the VRF output must be account-specific.
- `contract id`: the Aptos module ACE checks for access decisions, encoded as `(chainId, moduleAddr, moduleName)`.
- `account`: the Aptos account that signs the request and is passed to the policy hook for authorization. It is not part of the VRF input unless the app encodes it into `label`.
- `origin`: the Aptos wallet/WebAuthn application origin extracted by ACE from the signed message.

## Request and response limits

The TypeScript SDK enforces the worker wire limits before sending a request. Plan proof formats—especially ZK proofs—with these limits in mind.

| Field | Maximum encoded size |
| --- | ---: |
| `label` | 1 KiB |
| custom-flow `payload` | 16 KiB |
| Aptos wallet `fullMessage` | 16 KiB |
| WebAuthn `clientDataJSON` | 16 KiB |
| WebAuthn `authenticatorData` | 4 KiB |
| Aptos module name | 256 bytes |
| complete plaintext worker request | 64 KiB |
| aggregate worker response headers | 16 KiB |

The SDK also stops reading and cancels any worker response body larger than 64 KiB. High-level encrypt, decrypt, and VRF APIs return `Result`; `unwrapOrThrow("context")` throws an `Error` whose `cause` retains the underlying HTTP, parsing, or cryptographic failure.
