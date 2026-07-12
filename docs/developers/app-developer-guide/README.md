# App Developer Guide

ACE exposes Aptos-authorized threshold IBE decryption and threshold VRF derivation. Your app contract decides whether a request is allowed; the SDK verifies worker shares before combining them.

| Guide | Use when | Typical apps |
|-------|----------|--------------|
| [`ibe-aptos-basic.md`](./ibe-aptos-basic.md) | An Aptos account signs a decryption request and your hook authorizes that account | allowlists, paid content, timelocks |
| [`ibe-aptos-custom.md`](./ibe-aptos-custom.md) | Your app supplies its own proof bytes and verification hook | presigned grants, ZK authorization, capability systems |
| [`vrf-aptos.md`](./vrf-aptos.md) | Your Aptos contract decides who can derive values for a given contract and label | per-object keys, deterministic grants, app-scoped randomness |

## Vocabulary

- `aceDeployment`: the ACE network endpoint and ACE contract address.
- `keypairId`: the ACE secret identifier, originally created by DKG and retained across DKR reshares.
- `label`: app-chosen bytes that identify the derivation purpose. Include the account in the label if the VRF output must be account-specific.
- `contract id`: the Aptos module ACE checks for access decisions, encoded as `(chainId, moduleAddr, moduleName)`.
- `account`: the Aptos account that signs the request and is passed to the policy hook for authorization. It is not part of the VRF input unless the app encodes it into `label`.
- `origin`: the Aptos wallet/WebAuthn application origin extracted by ACE from the signed message.

## Common Build Order

1. Design your derivation policy data model.
2. Implement the `on_ace_vrf_request(label, account, origin)` Move hook.
3. Deploy the contract and initialize policy state.
4. Derive with the SDK using the same contract id and label your policy expects.
5. Map the 32-byte VRF output into your app's key, token, nonce, or randomness format.
6. Deploy the web app or CLI wrapper, get the stable application origin, then configure the contract to accept only that origin.
