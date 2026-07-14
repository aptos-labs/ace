# Aptos Off-Chain Identity Access: Can off-chain identity X access object Y?

## TLDR

ACE lets your app answer "can off-chain identity X access object Y?" from an Aptos contract. Use this guide when readers should prove access with an app-defined credential, such as a bearer signing capability, ZK proof, Merkle witness, or attestation, instead of an Aptos wallet login.

To use it, you will:

- In your Move module, expose `on_ace_decryption_request_custom_flow(...)` as the source of truth for access decisions.
- Define the proof data your off-chain identity or credential will present.
- In your client, encrypt and decrypt objects with the SDK's `ACE.IBE_Aptos` custom-flow APIs.

## Example: bearer signing capabilities

In this example, we show how to build bearer signing capabilities with ACE. The high-level idea is to use an object ID as the lookup key, let the owner derive an access keypair through ACE threshold VRF, register the access public key for that object on-chain, and let a reader prove possession of the matching private key when decrypting.

The reader does not need an Aptos account in this pattern. The capability is possession of `accessPrivateKey`. When the reader wants to decrypt, they create a custom decryption session. The session generates a one-time public encryption key, `enc_pk`, and retains the matching secret key internally. ACE encrypts the data it returns to `enc_pk`, so the reader signs a small statement that names the object, the deployed app origin, and that `enc_pk`.

Concretely, the signed statement has these fields:

| Field | Meaning |
| --- | --- |
| `label` | The object ID for the encrypted content. |
| `enc_pk` | The one-time public encryption key for this decryption. |
| `origin` | The deployed app origin that should be allowed. |
| `sig` | `Sign(accessPrivateKey, BCS(dst, label, enc_pk, origin))`. |

The client sends `origin` and `sig` to ACE, encoded as `BCS(origin, sig)`. The custom-flow hook loads `accessPublicKey` from `access_public_keys[label]`, checks that `origin` is the deployed app origin, and verifies that `sig` was made over the same `label`, `enc_pk`, and `origin`. A separate threshold-VRF hook authorizes the owner to derive the access key material in the first place.

Each signed field has a job. Including `label` prevents a capability for one object from authorizing another object. Including `enc_pk` prevents someone who captures a valid `origin` and `sig` pair from replaying it with a different `enc_pk`. Including `origin` scopes the proof to the deployed app: the access key authorizes the reader, while the independently signed origin protects users from a malicious dapp replaying or soliciting a proof for a different application context.

### Contract changes

In this example, the Move module is named `capability_access`. After you publish it, the SDK's `moduleAddr` is the publisher address and `moduleName` is `"capability_access"`.

In the contract, we define the statement the capability key signs, store the registered public key for each object label, store app-level origin config, expose `on_ace_vrf_request` to authorize owner-side key derivation, and expose `on_ace_decryption_request_custom_flow` to verify reader decrypt requests.

ACE calls the contract through a view function with this fixed name and shape:

```move
public fun on_ace_decryption_request_custom_flow(
    label: vector<u8>,
    enc_pk: vector<u8>,
    payload: vector<u8>,
): bool
```

The third hook argument, `payload`, is the app-defined bytes for this flow. In this example, it contains `origin` and `sig`. ACE does not interpret those bytes or require a normal Aptos wallet identity proof. During decryption, ACE passes the encrypted object's `label`, the reader's one-time public encryption key `enc_pk`, and `payload` to the hook; the contract decides whether decryption should be allowed for this object.

Because this bearer example derives the access key through ACE threshold VRF, the same module also exposes the fixed VRF hook:

```move
public fun on_ace_vrf_request(
    label: vector<u8>,
    account: address,
    origin: String,
): bool
```

Workers call this before serving the VRF request. In this example, labels are shaped as `@<owner>/<object-path>`, so the hook approves only when `origin` matches the deployed app origin and `label` is in the signed `account`'s namespace. That is what makes the bearer key owner-derivable rather than globally derivable by anyone who knows the label.

Before writing the hook, define exactly what the reader signs. In this app, the signature should mean: the holder of `accessPrivateKey` approves decrypting this `label`, for this `enc_pk`, from this deployed app origin.

We encode that meaning as `SignableRequest`. The `dst` field is a version tag for this app and message format:

```move
const SIGNABLE_REQUEST_DST: vector<u8> = b"ACE_BEARER_CAPABILITY_v1";

struct SignableRequest has copy, drop {
    dst: vector<u8>,
    label: vector<u8>,
    user_epk: vector<u8>,
    origin: vector<u8>,
}
```

Next, we store the public half of each capability. In this example, each encrypted object `label` has one registered BLS public key:

```move
struct Registry has key {
    access_public_keys: Table<vector<u8>, vector<u8>>,
}

public entry fun register(
    admin: &signer,
    label: vector<u8>,
    access_public_key: vector<u8>,
) {
    assert!(admin.address_of() == @admin, error::permission_denied(E_NOT_ADMIN));
    assert!(exists<Registry>(@admin), error::not_found(E_NOT_INITIALIZED));
    let pk_opt = bls12381::public_key_from_bytes(access_public_key);
    assert!(pk_opt.is_some(), error::invalid_argument(E_INVALID_ACCESS_PUBLIC_KEY));

    let registry = &mut Registry[@admin];
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
) {
    assert!(admin.address_of() == @admin, error::permission_denied(E_NOT_ADMIN));
    assert!(exists<AppConfig>(@admin), error::not_found(E_NOT_INITIALIZED));
    let config = &mut AppConfig[@admin];
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
): bool {
    if (!exists<Registry>(@admin)) return false;
    if (!exists<AppConfig>(@admin)) return false;
    let registry = &Registry[@admin];
    let config = &AppConfig[@admin];
    if (!registry.access_public_keys.contains(label)) return false;
    let access_public_key_bytes = *registry.access_public_keys.borrow(label);

    let stream = bcs_stream::new(payload);
    let claimed_origin = bcs_stream::deserialize_vector(&mut stream, |s| bcs_stream::deserialize_u8(s));
    let sig_bytes = bcs_stream::deserialize_vector(&mut stream, |s| bcs_stream::deserialize_u8(s));
    if (bcs_stream::has_remaining(&mut stream)) return false;
    if (&claimed_origin != &config.client_origin) return false;

    let pk_opt = bls12381::public_key_from_bytes(access_public_key_bytes);
    if (!pk_opt.is_some()) return false;
    let pk = pk_opt.extract();
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
module admin::capability_access {
    use aptos_std::bcs;
    use aptos_std::bcs_stream;
    use aptos_std::bls12381;
    use aptos_std::string_utils;
    use aptos_std::table;
    use aptos_std::table::Table;
    use std::error;
    use std::string::{Self, String};

    const E_NOT_ADMIN: u64 = 1;
    const E_NOT_INITIALIZED: u64 = 2;
    const E_INVALID_ACCESS_PUBLIC_KEY: u64 = 3;
    const SIGNABLE_REQUEST_DST: vector<u8> = b"ACE_BEARER_CAPABILITY_v1";

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
        assert!(admin.address_of() == @admin, error::permission_denied(E_NOT_ADMIN));
        if (!exists<Registry>(@admin)) {
            move_to(admin, Registry {
                access_public_keys: table::new(),
            });
        };
        if (!exists<AppConfig>(@admin)) {
            move_to(admin, AppConfig {
                client_origin: vector[],
            });
        };
    }

    public entry fun set_client_origin(
        admin: &signer,
        origin: vector<u8>,
    ) {
        assert!(admin.address_of() == @admin, error::permission_denied(E_NOT_ADMIN));
        assert!(exists<AppConfig>(@admin), error::not_found(E_NOT_INITIALIZED));
        let config = &mut AppConfig[@admin];
        config.client_origin = origin;
    }

    public entry fun register(
        admin: &signer,
        label: vector<u8>,
        access_public_key: vector<u8>,
    ) {
        assert!(admin.address_of() == @admin, error::permission_denied(E_NOT_ADMIN));
        assert!(exists<Registry>(@admin), error::not_found(E_NOT_INITIALIZED));
        let pk_opt = bls12381::public_key_from_bytes(access_public_key);
        assert!(pk_opt.is_some(), error::invalid_argument(E_INVALID_ACCESS_PUBLIC_KEY));

        let registry = &mut Registry[@admin];
        registry.access_public_keys.upsert(label, access_public_key);
    }

    #[view]
    public fun on_ace_decryption_request_custom_flow(
        label: vector<u8>,
        enc_pk: vector<u8>,
        payload: vector<u8>,
    ): bool {
        if (!exists<Registry>(@admin)) return false;
        if (!exists<AppConfig>(@admin)) return false;
        let registry = &Registry[@admin];
        let config = &AppConfig[@admin];
        if (!registry.access_public_keys.contains(label)) return false;
        let access_public_key_bytes = *registry.access_public_keys.borrow(label);

        // payload = BCS(origin: vector<u8>) || BCS(sig: vector<u8>)
        let stream = bcs_stream::new(payload);
        let claimed_origin = bcs_stream::deserialize_vector(&mut stream, |s| bcs_stream::deserialize_u8(s));
        let sig_bytes = bcs_stream::deserialize_vector(&mut stream, |s| bcs_stream::deserialize_u8(s));
        if (bcs_stream::has_remaining(&mut stream)) return false;
        if (&claimed_origin != &config.client_origin) return false;

        let pk_opt = bls12381::public_key_from_bytes(access_public_key_bytes);
        if (!pk_opt.is_some()) return false;
        let pk = pk_opt.extract();
        let sig = bls12381::signature_from_bytes(sig_bytes);
        let msg = bcs::to_bytes(&SignableRequest {
            dst: SIGNABLE_REQUEST_DST,
            label,
            user_epk: enc_pk,
            origin: claimed_origin,
        });
        bls12381::verify_normal_signature(&sig, &pk, msg)
    }

    #[view]
    public fun on_ace_vrf_request(label: vector<u8>, account: address, origin: String): bool {
        if (!exists<AppConfig>(@admin)) return false;
        let config = &AppConfig[@admin];
        if (origin.bytes() != &config.client_origin) return false;
        let owner_prefix = create_full_blob_name(account, string::utf8(b""));
        bytes_strictly_starts_with(&label, owner_prefix.bytes())
    }

    public fun create_full_blob_name(owner_address: address, blob_name_suffix: String): String {
        let full_blob_name = string_utils::to_string_with_canonical_addresses(&owner_address);
        full_blob_name.append_utf8(b"/");
        full_blob_name.append(blob_name_suffix);
        full_blob_name
    }

    fun bytes_strictly_starts_with(bytes: &vector<u8>, prefix: &vector<u8>): bool {
        let prefix_len = prefix.length();
        let bytes_len = bytes.length();
        if (bytes_len <= prefix_len) return false;

        let i = 0;
        while (i < prefix_len) {
            if (*bytes.borrow(i) != *prefix.borrow(i)) return false;
            i = i + 1;
        };
        true
    }
}
```

The custom-flow hook name and signature are fixed, but the internals are app-defined. In this example, we store one access public key per `label`, decode the third argument as `BCS(origin) || BCS(sig)`, check that `origin` matches app-level config, and verify that `sig` covers `BCS(SignableRequest { dst, label, enc_pk, origin })` under the registered public key. The VRF hook uses the same origin config and rejects requests signed by any account other than the owner namespace in the label.

Before readers decrypt, the owner derives a BLS access keypair from ACE threshold VRF. The VRF input is bound to the ACE VRF keypair, the app contract id, and the object label; the Aptos signature authorizes the request, and `on_ace_vrf_request` enforces that the signed account owns the label namespace. Register only `accessPublicKey` on-chain; keep `accessPrivateKey` off-chain and give it only to readers or capability-issuing systems that should be able to sign access statements. Using the client handles shown below, derivation looks like this:

```typescript
const owner = getOwnerAccount(); // controls the @<owner>/... namespace
const vrfBytes = (await ACE.VRF_Aptos.derive({
  aceDeployment,
  keypairId: vrfKeypairId,
  chainId,
  moduleAddr,
  moduleName,
  label,
  accountAddress: owner.accountAddress,
  sign: async (message) => {
    const fullMessage = ACE.VRF_Aptos.buildAptosWalletFullMessage({
      accountAddress: owner.accountAddress,
      application: appOrigin,
      chainId,
      message,
      nonce: crypto.randomUUID(),
    });
    return {
      pubKey: owner.publicKey,
      signature: owner.sign(fullMessage),
      fullMessage,
    };
  },
})).unwrapOrThrow("ACE VRF derive failed");

const accessPrivateKey = BigInt(`0x${bytesToHex(vrfBytes)}`) % bls12_381.fields.Fr.ORDER;
if (accessPrivateKey === 0n) throw new Error("VRF output reduced to zero");
const accessPublicKey = bls12_381.G1.ProjectivePoint.BASE
  .multiply(accessPrivateKey)
  .toRawBytes(true);

// Submit accessPublicKey to capability_access::register and distribute
// accessPrivateKey only through your secure capability-delivery channel.
```

Deploy the Move package, initialize verifier state, and register the access public keys you want to accept. After deploying the client, call `set_client_origin` once with the client's stable origin. The origin is app-level configuration, separate from per-label public keys. Record:

- `chainId`, `moduleAddr`, and `moduleName` for the module with the hook.
- `aceDeployment`, `ibeKeypairId`, and `vrfKeypairId` from the ACE deployment you target, such as SDK `knownDeployments` values or a localnet/example config.
- The version and encoding for your proof data.

### Client changes

Before the SDK calls, fill in the ACE deployment values and the app module identity:

```typescript
import * as ACE from "@aptos-labs/ace-sdk";
import { AccountAddress, Serializer } from "@aptos-labs/ts-sdk";
import { bls12_381 } from "@noble/curves/bls12-381";
import { bytesToHex } from "@noble/hashes/utils";

const aceDeployment = new ACE.AceDeployment({
  apiEndpoint: "https://api.testnet.aptoslabs.com/v1",
  contractAddr: AccountAddress.fromString("0x<ace-contract-address>"),
});
const ibeKeypairId = AccountAddress.fromString("0x<ace-ibe-keypair-id>");
const vrfKeypairId = AccountAddress.fromString("0x<ace-vrf-keypair-id>");
const chainId = 2; // Aptos testnet
const appOrigin = "https://<your-deployed-app-origin>";

const moduleAddr = AccountAddress.fromString("0x<app-module-address>");
const moduleName = "capability_access"; // matches module <publisher>::capability_access
```

In the client, encrypt under the module that contains the custom hook. The SDK calls the object ID bytes `label`; this example uses a canonical `@<owner>/<object-path>` blob id as that label.

```typescript
const objectId = new TextEncoder().encode("@<owner-canonical-address>/album/song-001");
const label = objectId;

const ciphertext = (await ACE.IBE_Aptos.encrypt({
  aceDeployment,
  keypairId: ibeKeypairId,
  chainId,
  moduleAddr,
  moduleName,
  label,
  plaintext: privateContent,
})).unwrapOrThrow("ACE encrypt failed");
```

If you encrypt many objects with the same ACE keypair and t-IBE scheme, fetch the public key once and pass it to each encryption call. If you use a non-default `tibeScheme`, pass it to `fetchPk` too.

```typescript
const pk = (await ACE.IBE_Aptos.fetchPk({
  aceDeployment,
  keypairId: ibeKeypairId,
})).unwrapOrThrow("ACE public key fetch failed");

const ciphertext = (await ACE.IBE_Aptos.encrypt({
  aceDeployment,
  keypairId: ibeKeypairId,
  chainId,
  moduleAddr,
  moduleName,
  label,
  plaintext: privateContent,
  pk,
})).unwrapOrThrow("ACE encrypt failed");
```

For decryption, create a session that owns the fresh one-time encryption keypair, build the signed statement against its `encPk`, encode `origin` and `sig`, and submit them through that same session. In this example, `accessPrivateKey` is the BLS private key whose public key was registered for `label`:

```typescript
const session = await ACE.IBE_Aptos.CustomDecryptionSession.create({
  aceDeployment,
  keypairId: ibeKeypairId,
  chainId,
  moduleAddr,
  moduleName,
  label,
});
const encPk = session.getEncryptionKeyBytes();

const origin = new TextEncoder().encode(window.location.origin);
const dst = new TextEncoder().encode("ACE_BEARER_CAPABILITY_v1");
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

const plaintext = (await session.decrypt({
  ciphertext,
  payload,
})).unwrapOrThrow("ACE custom decrypt failed");
```

Keep the session alive until the proof and decrypt phases finish; it prevents mixing an `encPk` from one request with an `encSk` from another. You can also fetch the worker results first and open the ciphertext locally later. If the ciphertext uses a non-default t-IBE scheme, pass the same `tibeScheme` to the fetch call.

```typescript
const identityKeyShares =
  (await session.fetchIdentityKeyShares({
    payload,
  })).unwrapOrThrow("ACE fetch identity key shares failed");

const plaintext = ACE.IBE_Aptos.decryptWithIdentityKeyShares({
  ciphertext,
  identityKeyShares,
}).unwrapOrThrow("ACE local decrypt failed");
```

Unlike the Aptos account access flow, custom flow does not automatically receive a wallet `origin` parameter. If origin matters, include it in the app-defined bytes passed as the SDK `payload` argument and verify it in the hook. The trusted capability signer should derive the actual origin from its application or wallet context rather than accepting an arbitrary caller-supplied claim. Deploy the web app, learn the exact origin, then call a setter like `set_client_origin` once for the app so only that origin is accepted.

## Remarks

This pattern intentionally grants a bearer signing capability. Anyone who obtains the private key can issue any number of fresh requests for that `label`; rotating the label's registered public key revokes every holder of the old key at once, not one reader individually. Only hand the key to readers who should have that power, and avoid logging it or embedding it in an untrusted dapp. If you need identity-bound or per-reader revocation, encode reader identity into the proof and policy, or use the Aptos account access flow.

## Ready-To-Run Examples

- [`examples/bearer-capability-aptos`](../../../examples/bearer-capability-aptos): bearer signing capabilities with origin-bound signatures.
- [`scenarios/custom-flow-aptos`](../../../scenarios/custom-flow-aptos): small code-based custom-flow scenario.
