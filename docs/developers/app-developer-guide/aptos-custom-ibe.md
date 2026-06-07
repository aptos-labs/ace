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

    struct AppConfig has key {
        client_origin: vector<u8>,
    }

    public entry fun init(admin: &signer) {
        assert!(signer::address_of(admin) == @admin, error::permission_denied(E_NOT_ADMIN));
        if (!exists<Registry>(@admin)) {
            move_to(admin, Registry {
                access_public_keys: table::new(),
            });
        };
        if (!exists<AppConfig>(@admin)) {
            move_to(admin, AppConfig {
                client_origin: vector::empty(),
            });
        };
    }

    public entry fun set_client_origin(
        admin: &signer,
        origin: vector<u8>,
    ) acquires AppConfig {
        assert!(signer::address_of(admin) == @admin, error::permission_denied(E_NOT_ADMIN));
        assert!(exists<AppConfig>(@admin), error::not_found(E_NOT_INITIALIZED));
        let config = borrow_global_mut<AppConfig>(@admin);
        config.client_origin = origin;
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
    ): bool acquires Registry, AppConfig {
        if (!exists<Registry>(@admin)) return false;
        if (!exists<AppConfig>(@admin)) return false;
        let registry = borrow_global<Registry>(@admin);
        let config = borrow_global<AppConfig>(@admin);
        if (!registry.access_public_keys.contains(label)) return false;
        let access_public_key_bytes = *registry.access_public_keys.borrow(label);

        // payload = BCS(origin: vector<u8>) || BCS(sig: vector<u8>)
        let stream = bcs_stream::new(payload);
        let claimed_origin = bcs_stream::deserialize_vector(&mut stream, |s| bcs_stream::deserialize_u8(s));
        let sig_bytes = bcs_stream::deserialize_vector(&mut stream, |s| bcs_stream::deserialize_u8(s));
        if (bcs_stream::has_remaining(&mut stream)) return false;
        if (&claimed_origin != &config.client_origin) return false;

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

Deploy the Move package, initialize verifier state, and register the access public keys you want to accept. After deploying the client, call `set_client_origin` once with the client's stable origin. The origin is app-level configuration, separate from per-label public keys. Record:

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

const origin = new TextEncoder().encode(window.location.origin);
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

Unlike basic Aptos IBE, custom flow does not automatically receive a wallet `origin` parameter. If origin matters, put it in the payload and verify it in the hook. The recommended real order is to deploy the web app, learn the exact origin, then call a setter like `set_client_origin` once for the app so only that origin is accepted.

## Remarks

Design the payload as an authenticated statement, not just bytes that the hook happens to parse. A typical payload includes a version or domain-separation string, the app audience or origin if relevant, the subject being authorized, any expiry or nonce your policy needs, the policy-specific public claims, and an authenticator such as a signature, proof, or witness.

That authenticator should cover a canonical encoding of every field the hook relies on. At minimum, bind it to `label` and the per-request `enc_pk`. Binding `label` prevents a proof for one object from authorizing another object. Binding `enc_pk` prevents someone who sees a valid payload from replaying it with their own response key and receiving shares encrypted to themselves. If the grant is origin-bound, time-bound, or issuer-bound, include those fields in the signed statement or proof public inputs too, and have the hook reject mismatches and malformed encodings.

## Ready-To-Run Examples

- [`examples/zk-kyc`](../../../examples/zk-kyc): Groth16 age-gated decryption.
- [`examples/presigned-access-aptos`](../../../examples/presigned-access-aptos): pre-signed access grants with payload-origin binding.
- [`scenarios/custom-flow-aptos`](../../../scenarios/custom-flow-aptos): small code-based custom-flow scenario.
