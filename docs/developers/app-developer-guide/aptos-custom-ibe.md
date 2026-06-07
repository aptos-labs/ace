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

Design the payload before the hook. In a ZK-gated app, the payload might be a Groth16 proof plus public outputs. The example below uses the pre-signed-access pattern: each `label` has a registered BLS public key, and the reader's payload contains `(origin, sig)`. The signature must cover a domain-separation string, `label`, the reader's ephemeral response key `enc_pk`, and the claimed origin.

```move
module admin::presigned_access {
    use aptos_std::bcs;
    use aptos_std::bcs_stream;
    use aptos_std::bls12381;
    use aptos_std::table;
    use aptos_std::table::Table;
    use std::error;
    use std::option;
    use std::signer;

    const E_NOT_ADMIN: u64 = 1;
    const E_NOT_INITIALIZED: u64 = 2;
    const E_INVALID_ACCESS_PUBLIC_KEY: u64 = 3;
    const EXPECTED_APP_ORIGIN: vector<u8> = b"https://app.example.com";
    const SIGNABLE_REQUEST_DST: vector<u8> = b"ACE_PRESIGNED_ACCESS_v1";

    struct SignableRequest has copy, drop {
        dst: vector<u8>,
        label: vector<u8>,
        user_epk: vector<u8>,
        origin: vector<u8>,
    }

    struct Registry has key {
        access_public_keys: Table<vector<u8>, vector<u8>>,
    }

    public entry fun init(admin: &signer) {
        assert!(signer::address_of(admin) == @admin, error::permission_denied(E_NOT_ADMIN));
        if (!exists<Registry>(@admin)) {
            move_to(admin, Registry { access_public_keys: table::new() });
        };
    }

    public entry fun register(
        admin: &signer,
        label: vector<u8>,
        access_public_key: vector<u8>,
    ) acquires Registry {
        assert!(signer::address_of(admin) == @admin, error::permission_denied(E_NOT_ADMIN));
        assert!(exists<Registry>(@admin), error::not_found(E_NOT_INITIALIZED));
        let pk_opt = bls12381::public_key_from_bytes(access_public_key);
        assert!(option::is_some(&pk_opt), error::invalid_argument(E_INVALID_ACCESS_PUBLIC_KEY));

        let registry = borrow_global_mut<Registry>(@admin);
        registry.access_public_keys.upsert(label, access_public_key);
    }

    #[view]
    public fun on_ace_decryption_request_custom_flow(
        label: vector<u8>,
        enc_pk: vector<u8>,
        payload: vector<u8>,
    ): bool acquires Registry {
        if (!exists<Registry>(@admin)) return false;
        let registry = borrow_global<Registry>(@admin);
        if (!registry.access_public_keys.contains(label)) return false;
        let access_public_key_bytes = *registry.access_public_keys.borrow(label);

        // payload = BCS(origin: vector<u8>) || BCS(sig: vector<u8>)
        let stream = bcs_stream::new(payload);
        let claimed_origin = bcs_stream::deserialize_vector(&mut stream, |s| bcs_stream::deserialize_u8(s));
        let sig_bytes = bcs_stream::deserialize_vector(&mut stream, |s| bcs_stream::deserialize_u8(s));
        if (bcs_stream::has_remaining(&mut stream)) return false;
        if (claimed_origin != EXPECTED_APP_ORIGIN) return false;

        let pk_opt = bls12381::public_key_from_bytes(access_public_key_bytes);
        if (!option::is_some(&pk_opt)) return false;
        let pk = option::extract(&mut pk_opt);
        let sig = bls12381::signature_from_bytes(sig_bytes);
        let msg = bcs::to_bytes(&SignableRequest {
            dst: SIGNABLE_REQUEST_DST,
            label,
            user_epk: enc_pk,
            origin: claimed_origin,
        });
        bls12381::verify_normal_signature(&sig, &pk, msg)
    }
}
```

The hook name and signature are fixed. The internals are app-defined. In this pattern, `enc_pk` is part of the signed message, so someone who captures `(origin, sig)` cannot replay it with their own response key.

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
  moduleName: "presigned_access",
  label,
  plaintext: privateContent,
})).unwrapOrThrow("ACE encrypt failed");
```

For decryption, generate a fresh PKE keypair, build the payload, and submit it. In this example, `accessPrivateKey` is the BLS private key whose public key was registered for `label`:

```typescript
import { Serializer } from "@aptos-labs/ts-sdk";
import { bls12_381 } from "@noble/curves/bls12-381";

const { encryptionKey, decryptionKey } = await ACE.pke.keygen();
const encPk = encryptionKey.toBytes();
const encSk = decryptionKey.toBytes();

const origin = new TextEncoder().encode("https://app.example.com");
const dst = new TextEncoder().encode("ACE_PRESIGNED_ACCESS_v1");
const blsDst = new TextEncoder().encode("BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_");

const signable = new Serializer();
signable.serializeBytes(dst);
signable.serializeBytes(label);
signable.serializeBytes(encPk);
signable.serializeBytes(origin);
const sig = bls12_381.G2.hashToCurve(signable.toUint8Array(), { DST: blsDst })
  .multiply(accessPrivateKey)
  .toRawBytes(true);

const payloadSerializer = new Serializer();
payloadSerializer.serializeBytes(origin);
payloadSerializer.serializeBytes(sig);
const payload = payloadSerializer.toUint8Array();

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
  moduleName: "presigned_access",
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
