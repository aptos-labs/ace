# Aptos Custom IBE: Payload-Gated Decryption

## TLDR

Use this flow when an Aptos contract needs to verify an application-defined payload instead of a normal wallet identity proof. Typical examples are ZK proofs, Merkle witnesses, signed attestations, pre-signed access tokens, and account-abstraction style credentials.

You need to:

- Write a Move module with `on_ace_decryption_request_custom_flow(label, enc_pk, payload): bool`.
- Define and document the payload encoding.
- Bind the payload to `label`, `enc_pk`, and any app origin or audience you care about.
- Encrypt with `ACE.IBE_Aptos.encrypt`.
- Generate a per-request PKE keypair and call `ACE.IBE_Aptos.decryptCustomFlow`.

## Walkthrough

Design the payload before the hook. In a ZK-gated app, the payload might be a Groth16 proof plus public outputs. In a pre-signed-access app, it might be BCS bytes containing an origin and a signature from an access key.

The hook name and signature are fixed:

```move
#[view]
public fun on_ace_decryption_request_custom_flow(
    label: vector<u8>,
    enc_pk: vector<u8>,
    payload: vector<u8>,
): bool acquires VerifierState {
    // Decode payload.
    // Verify payload against policy state.
    // Return true only when the payload is bound to label and enc_pk.
}
```

The `enc_pk` is the requestor's ephemeral public key for this decryption session. Bind your proof or signature to it. That prevents someone from copying a valid payload and replaying it with their own response key.

Deploy the Move package, initialize verifier state, and record:

- `chainId`, `moduleAddr`, and `moduleName` for the module with the hook.
- `aceDeployment` and `keypairId`.
- Your payload version and encoding.

Encrypt exactly as in basic Aptos IBE, using the module that contains the custom hook:

```typescript
const ciphertext = (await ACE.IBE_Aptos.encrypt({
  aceDeployment,
  keypairId,
  chainId,
  moduleAddr,
  moduleName: "kyc_verifier",
  label,
  plaintext: privateContent,
})).unwrapOrThrow("ACE encrypt failed");
```

For decryption, generate a fresh PKE keypair, build the payload, and submit it:

```typescript
const { encryptionKey, decryptionKey } = await ACE.pke.keygen();
const encPk = encryptionKey.toBytes();
const encSk = decryptionKey.toBytes();

const payload = await buildPayload({
  label,
  encPk,
  origin: "https://app.example.com",
  credential,
});

const plaintext = await ACE.IBE_Aptos.decryptCustomFlow({
  ciphertext,
  label,
  encPk,
  encSk,
  payload,
  aceDeployment,
  keypairId,
  chainId,
  moduleAddr,
  moduleName: "kyc_verifier",
});
```

Custom Aptos IBE is a one-call SDK flow today. If your UI has multiple phases, keep `encPk`, `encSk`, and the payload inputs in your own session state until the user finishes the proof step.

Unlike basic Aptos IBE, custom flow does not automatically receive a wallet `origin` parameter. If origin matters, put it in the payload and verify it in the hook. The recommended real order is to deploy the web app, learn the exact origin, then update the contract state or republish the constant so only that origin is accepted.

## Remarks

- The hook must be deterministic and view-safe. Workers rely on the chain's answer.
- Never accept a payload that is not bound to `enc_pk`; replay protection depends on it.
- Prefer versioned payloads with explicit domain-separation strings.
- Check for trailing bytes after decoding structured payloads.
- Use `label` as part of the proof statement when the proof authorizes one specific object.
- Return `false` for malformed payloads where practical.

## Ready-To-Run Examples

- [`examples/zk-kyc`](../../../examples/zk-kyc): Groth16 age-gated decryption.
- [`examples/presigned-access-aptos`](../../../examples/presigned-access-aptos): pre-signed access grants with payload-origin binding.
- [`scenarios/custom-flow-aptos`](../../../scenarios/custom-flow-aptos): small code-based custom-flow scenario.
