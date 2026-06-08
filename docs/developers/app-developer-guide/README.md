# App Developer Guide

ACE lets an app encrypt or derive secrets now, then ask an on-chain policy later whether a user may receive the key material needed to decrypt or derive. Pick the guide that matches your chain and proof style.

| Guide | Use when | Typical apps |
|-------|----------|--------------|
| [`aptos-account-access.md`](./aptos-account-access.md) | Your Aptos contract decides whether Aptos account X can access object Y | pay-to-download, allowlists, time locks, subscriptions |
| [`solana-account-access.md`](./solana-account-access.md) | Your Solana program decides whether Solana account X can access object Y | pay-to-download, receipt-based access, PDA-backed ACLs |
| [`aptos-off-chain-identity-access.md`](./aptos-off-chain-identity-access.md) | Your Aptos contract decides whether off-chain identity X can access object Y | ZK-gated access, signed attestations, bearer-token style grants |
| [`solana-off-chain-identity-access.md`](./solana-off-chain-identity-access.md) | Your Solana program decides whether off-chain identity X can access object Y | ZK proofs, coupon codes, custom ACLs, off-chain credentials |
| [`aptos-derived-access-keys.md`](./aptos-derived-access-keys.md) | Your Aptos contract decides whether account X can create the access key for object Y | per-object signing keys, deterministic grants, app-scoped randomness |

## Vocabulary

- `aceDeployment`: the ACE network endpoint and ACE contract address. Use a known deployment from `ACE.knownDeployments` or construct `new ACE.AceDeployment(...)`.
- `keypairId`: the on-chain ACE DKG session address for the threshold keypair.
- `label`: app-chosen bytes that identify the encrypted object or VRF derivation. Your contract usually uses this as the lookup key.
- `contract id`: the app contract that workers call or simulate. Aptos uses `(chainId, moduleAddr, moduleName)`. Solana uses `(knownChainName, programId)`.
- `origin`: an Aptos wallet/WebAuthn application origin extracted by ACE workers from the signed message. Solana proofs do not currently include this field automatically.

## Common Build Order

1. Design your access policy data model.
2. Implement the ACE hook for the flow you chose.
3. Deploy the contract or program and initialize its policy state.
4. Encrypt or derive with the SDK using the same contract id and label your policy expects.
5. Build the client decryption or derivation path.
6. Deploy the web app or CLI wrapper, get the stable application origin, then configure the contract to accept only that origin when the flow carries one.

The examples linked from each guide are the best place to copy exact localnet setup commands.
