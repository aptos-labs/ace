# Aptos VRF: Move-Gated Derivation

## TLDR

Use ACE VRF when an Aptos contract should decide whether a user may derive deterministic threshold VRF bytes for `(keypairId, contract, account, label)`. It is useful for per-object access keys, deterministic grants, app-scoped random-looking bytes, and workflows where the app wants a reproducible secret without storing it.

You need to:

- Write a Move module with `on_ace_vrf_request(label, account, origin): bool`.
- Store whatever policy decides who may derive.
- Use `ACE.VRF_Aptos.DerivationSession` for wallet-driven clients, or `ACE.VRF_Aptos.derive` for one-shot scripts.
- Bind derivations to a stable label and lock the hook to your deployed origin.

## Walkthrough

Design the derivation policy. For a per-blob access-key app, `label` can be the blob id, `account` can be the owner or authorized issuer, and `origin` can pin the derivation to your app.

The hook name and signature are fixed:

```move
use std::string::String;

#[view]
public fun on_ace_vrf_request(
    label: vector<u8>,
    account: address,
    origin: String,
): bool acquires VrfPolicy {
    if (origin.bytes() != &EXPECTED_APP_ORIGIN) return false;
    is_allowed_to_derive(account, label)
}
```

Deploy the Move package and initialize policy. Record:

- `chainId`, `moduleAddr`, and `moduleName`.
- `aceDeployment` and `keypairId`.
- The label construction for each derivation.

For a wallet or web app, prefer the session API:

```typescript
import * as ACE from "@aptos-labs/ace-sdk";

const contractId = ACE.ContractID.newAptos({
  chainId,
  moduleAddr,
  moduleName: "presigned_access",
});

const session = await ACE.VRF_Aptos.DerivationSession.create({
  aceDeployment,
  keypairId,
  contractId,
  label,
  accountAddress: ownerAddress,
});

const message = await session.getRequestToSign();
const signed = await wallet.signMessage({
  message,
  nonce: crypto.randomUUID(),
  application: true,
  chainId,
  address: ownerAddress,
});

const vrfBytes = await session.deriveWithSignature({
  pubKey: signed.publicKey,
  signature: signed.signature,
  fullMessage: signed.fullMessage,
});
```

For CLIs or server-side jobs that already know how to sign, use the one-shot helper:

```typescript
const vrfBytes = await ACE.VRF_Aptos.derive({
  aceDeployment,
  keypairId,
  chainId,
  moduleAddr,
  moduleName: "presigned_access",
  label,
  accountAddress: ownerAddress,
  sign: async (message) => {
    const signed = await signAptosMessage(message);
    return {
      pubKey: signed.publicKey,
      signature: signed.signature,
      fullMessage: signed.fullMessage,
    };
  },
});
```

After deriving, turn the bytes into whatever your app needs. The presigned-access example maps 32 VRF bytes into a BLS12-381 private key and registers the public key on-chain.

As with Aptos basic IBE, deploy the client first, learn the stable origin, then update the contract or policy resource to accept only that origin.

## Remarks

- VRF output is deterministic for the same ACE keypair, contract id, account, and label.
- VRF output is not a public randomness beacon. The requestor and policy shape matter, and the caller can choose labels unless your app constrains them.
- Use domain-separated labels. For example, prefix labels with `access-key:v1:` or another app-specific tag.
- Keep derived secrets off-chain unless intentionally publishing them.
- If you convert VRF bytes into a scalar or keypair, use rejection sampling or a documented modulo reduction appropriate for the target group.
- The current SDK exposes the VRF flow for Aptos contracts.

## Ready-To-Run Examples

- [`examples/presigned-access-aptos`](../../../examples/presigned-access-aptos): derives per-blob access keys with ACE VRF, then uses custom IBE for readers.
- [`scenarios/test-threshold-vrf-derive-flow.ts`](../../../scenarios/test-threshold-vrf-derive-flow.ts): end-to-end localnet VRF derivation scenario.
- [`scenarios/threshold-vrf-origin`](../../../scenarios/threshold-vrf-origin): minimal origin-check Move hook.
