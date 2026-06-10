# Aptos Off-Chain Identity Access: Can off-chain identity X access object Y?

## TLDR

ACE lets your app answer "can off-chain identity X access object Y?" from an Aptos contract. Use this guide when readers should prove access with an app-defined credential, such as a signed grant, ZK proof, Merkle witness, or attestation, instead of an Aptos wallet login.

To use it, you will:

- In your Move module, expose `on_ace_decryption_request_custom_flow(...)` as the source of truth for access decisions.
- Define the proof data your off-chain identity or credential will present.
- In your client, encrypt and decrypt objects with the SDK's `ACE.IBE_Aptos` custom-flow APIs.

## Example: pre-signed access grants

In this example, we show how to build pre-signed access grants with ACE. The high-level idea is to use an object ID as the lookup key, register an access public key for that object on-chain, and let a reader prove possession of the matching private key when decrypting.

The reader does not need an Aptos account in this pattern. The grant is simply possession of `accessPrivateKey`. When the reader wants to decrypt, they first generate a one-time public encryption key, `enc_pk`, and keep the matching secret key locally. ACE encrypts the data it returns to `enc_pk`, so the reader signs a small statement that names the object, the deployed app origin, and that `enc_pk`.

Concretely, the signed statement has these fields:

| Field | Meaning |
| --- | --- |
| `label` | The object ID for the encrypted content. |
| `enc_pk` | The one-time public encryption key for this decryption. |
| `origin` | The deployed app origin that should be allowed. |
| `sig` | `Sign(accessPrivateKey, BCS(dst, label, enc_pk, origin))`. |

The client sends `origin` and `sig` to ACE, encoded as `BCS(origin, sig)`. The hook loads `accessPublicKey` from `access_public_keys[label]`, checks that `origin` is the deployed app origin, and verifies that `sig` was made over the same `label`, `enc_pk`, and `origin`.

Each signed field has a job. Including `label` prevents a grant for one object from authorizing another object. Including `enc_pk` prevents someone who captures a valid `origin` and `sig` pair from replaying it with a different `enc_pk`. Including `origin` keeps the grant scoped to the deployed app.

### Contract changes

In this example, the Move module is named `presigned_access`. After you publish it, the SDK's `moduleAddr` is the publisher address and `moduleName` is `"presigned_access"`.

In the contract, we define the statement the grant key signs, store the registered public key for each object label, store app-level origin config, and expose `on_ace_decryption_request_custom_flow` to verify the decryption request.

ACE calls the contract through a view function with this fixed name and shape:

```move
public fun on_ace_decryption_request_custom_flow(
    label: vector<u8>,
    enc_pk: vector<u8>,
    payload: vector<u8>,
): bool
```

The third hook argument, `payload`, is the app-defined bytes for this flow. In this example, it contains `origin` and `sig`. ACE does not interpret those bytes or require a normal Aptos wallet identity proof. During decryption, ACE passes the encrypted object's `label`, the reader's one-time public encryption key `enc_pk`, and `payload` to the hook; the contract decides whether decryption should be allowed for this object.

Before writing the hook, define exactly what the reader signs. In this app, the signature should mean: the holder of `accessPrivateKey` approves decrypting this `label`, for this `enc_pk`, from this deployed app origin.

We encode that meaning as `SignableRequest`. The `dst` field is a version tag for this app and message format:

```move
const SIGNABLE_REQUEST_DST: vector<u8> = b"ACE_PRESIGNED_ACCESS_v1";

struct SignableRequest has copy, drop {
    dst: vector<u8>,
    label: vector<u8>,
    user_epk: vector<u8>,
    origin: vector<u8>,
}
```

Next, we store the public half of each grant. In this example, each encrypted object `label` has one registered BLS public key:

```move
struct Registry has key {
    access_public_keys: Table<vector<u8>, vector<u8>>,
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
```

Then we keep app origin as app-level config, separate from the per-label public keys:

```move
struct AppConfig has key {
    client_origin: vector<u8>,
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
```

Finally, the hook decodes `origin` and `sig`, rejects the wrong origin, rebuilds the signed statement, and verifies the signature under the public key registered for `label`:

```move
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
```

Putting those pieces together, the full module looks like this:

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

The hook name and signature are fixed, but the internals are app-defined. In this example, we store one access public key per `label`, decode the third argument as `BCS(origin) || BCS(sig)`, check that `origin` matches app-level config, and verify that `sig` covers `BCS(SignableRequest { dst, label, enc_pk, origin })` under the registered public key.

Before readers decrypt, we create or derive the access keypair for each `label`. The [Aptos-approved derivation guide](./vrf-aptos.md) shows a deterministic owner-side derivation; a server or issuer could also generate the keypair directly. Register only `accessPublicKey` on-chain. Keep `accessPrivateKey` off-chain and give it only to readers or grant-issuing systems that should be able to sign access statements.

Deploy the Move package, initialize verifier state, and register the access public keys you want to accept. After deploying the client, call `set_client_origin` once with the client's stable origin. The origin is app-level configuration, separate from per-label public keys. Record:

- `chainId`, `moduleAddr`, and `moduleName` for the module with the hook.
- `aceDeployment` and `keypairId` from the ACE deployment you target, such as a preview value provided by the ACE team or a localnet/example config.
- The version and encoding for your proof data.

### Client changes

Before the SDK calls, fill in the ACE deployment values and the app module identity:

```typescript
import * as ACE from "@aptos-labs/ace-sdk";
import { AccountAddress, Serializer } from "@aptos-labs/ts-sdk";
import { bls12_381 } from "@noble/curves/bls12-381";

const aceDeployment = new ACE.AceDeployment({
  apiEndpoint: "https://api.testnet.aptoslabs.com/v1",
  contractAddr: AccountAddress.fromString("0x<ace-contract-address>"),
});
const keypairId = AccountAddress.fromString("0x<ace-keypair-id>");
const chainId = 2; // Aptos testnet

const moduleAddr = AccountAddress.fromString("0x<app-module-address>");
const moduleName = "presigned_access"; // matches module <publisher>::presigned_access
```

In the client, encrypt under the module that contains the custom hook. The SDK calls the object ID bytes `label`; this example uses `objectId` as that label.

```typescript
const objectId = new TextEncoder().encode("0x<owner-address>/album/song-001");
const label = objectId;

const ciphertext = (await ACE.IBE_Aptos.encrypt({
  aceDeployment,
  keypairId,
  chainId,
  moduleAddr,
  moduleName,
  label,
  plaintext: privateContent,
})).unwrapOrThrow("ACE encrypt failed");
```

For decryption, we generate a fresh one-time encryption keypair, build the signed statement, encode `origin` and `sig` for the SDK, and submit them. In this example, `accessPrivateKey` is the BLS private key whose public key was registered for `label`:

```typescript
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
  moduleName,
});
```

This custom SDK flow is one call today. If your UI has multiple phases, keep `encPk`, `encSk`, and the proof inputs in your own session state until the user finishes the proof step.

Unlike the Aptos account access flow, custom flow does not automatically receive a wallet `origin` parameter. If origin matters, include it in the app-defined bytes passed as the SDK `payload` argument, and verify it in the hook. The recommended real order is to deploy the web app, learn the exact origin, then call a setter like `set_client_origin` once for the app so only that origin is accepted.

## Remarks

In the pre-signed-access pattern, the private key is a bearer capability. Anyone who obtains it can sign a valid statement for that `label`, so only hand it to readers who should have that power and avoid logging it or embedding it in an untrusted client. If you need identity-bound access instead of bearer access, make the signed statement or proof identify the reader, or use the Aptos account access flow.

## Ready-To-Run Examples

- [`examples/presigned-access-aptos`](../../../examples/presigned-access-aptos): pre-signed access grants with origin-bound signatures.
- [`scenarios/custom-flow-aptos`](../../../scenarios/custom-flow-aptos): small code-based custom-flow scenario.
