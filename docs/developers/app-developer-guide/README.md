# App Developer Guide

ACE lets an app encrypt data or derive app-specific values, then ask an on-chain policy whether a user is allowed to receive the result. Pick the guide that matches your chain and proof style.

| Guide | Use when | Typical apps |
|-------|----------|--------------|
| [`aptos-account-access.md`](./aptos-account-access.md) | Your Aptos contract decides whether Aptos account X can access object Y | pay-to-download, allowlists, time locks, subscriptions |
| [`solana-account-access.md`](./solana-account-access.md) | Your Solana program decides whether Solana account X can access object Y | pay-to-download, receipt-based access, PDA-backed ACLs |
| [`aptos-off-chain-identity-access.md`](./aptos-off-chain-identity-access.md) | Your Aptos contract decides whether off-chain identity X can access object Y | ZK-gated access, signed attestations, bearer-token style grants |
| [`solana-off-chain-identity-access.md`](./solana-off-chain-identity-access.md) | Your Solana program decides whether off-chain identity X can access object Y | ZK proofs, coupon codes, custom ACLs, off-chain credentials |
| [`aptos-approved-derivation.md`](./aptos-approved-derivation.md) | Your Aptos contract decides who can derive app-specific deterministic values | per-object signing keys, deterministic grants, app-scoped randomness |

## Vocabulary

- `aceDeployment`: the ACE network endpoint and ACE contract address. During preview, use the value provided by the ACE team or by a ready-to-run example/localnet config.
- `keypairId`: the ACE encryption key identifier, provided by the same ACE deployment or localnet config.
- `label`: app-chosen bytes that identify the encrypted object or VRF derivation. Your contract usually uses this as the lookup key.
- `contract id`: the app contract or program ACE checks for access decisions. Aptos uses `(chainId, moduleAddr, moduleName)`. Solana uses `(knownChainName, programId)`.
- `origin`: an Aptos wallet/WebAuthn application origin extracted by ACE from the signed message. Solana proofs do not currently include this field automatically.

## Common Build Order

1. Design your access policy data model.
2. Implement the ACE hook for the flow you chose.
3. Deploy the contract or program and initialize its policy state.
4. Encrypt or derive with the SDK using the same contract id and label your policy expects.
5. Build the client decryption or derivation path.
6. Deploy the web app or CLI wrapper, get the stable application origin, then configure the contract to accept only that origin when the flow carries one.

The examples linked from each guide are the best place to copy exact localnet setup commands.
