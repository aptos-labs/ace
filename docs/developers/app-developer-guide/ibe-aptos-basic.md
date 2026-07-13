# Aptos Account Access: Can Aptos account X access object Y?

## TLDR

ACE lets your app answer "can Aptos account X access object Y?" from an Aptos contract.
Use this guide when your users have Aptos accounts and your app can store its access policy on-chain.

To use it, you will:

- In your Move module, expose `on_ace_decryption_request(...)` as the source of truth for access decisions.
- In your client, encrypt and decrypt objects with the SDK's `ACE.IBE_Aptos` APIs.

## Example: allowlisted content catalog

In this example, we show how to build an allowlist-style content catalog with ACE.
The high-level idea is to use a full object ID as the catalog lookup key, encrypt each content item under that same ID, store the allowlist on-chain, and let ACE ask the contract before decrypting for a user.

### Contract changes

In this example, the Move module is named `content_access`. After you publish it, the SDK's `moduleAddr` is the publisher address and `moduleName` is `"content_access"`.

First, we can store the object ID-to-allowlist mapping in a table.

```move
struct ItemInfo has store, drop {
    allowlist: vector<address>,
}

struct Catalog has key {
    items: Table<vector<u8>, ItemInfo>,
}
```

We allow the owner of an object to update its allowlist using the following entry functions.

```move
/// We assume the full object ID contains owner info.
fun extract_owner_from_full_object_id(object_id: vector<u8>): address;

public entry fun register_item(owner: &signer, full_object_id: vector<u8>) {
    assert!(owner.address_of() == extract_owner_from_full_object_id(full_object_id), error::permission_denied(E_NOT_OWNER));
    let catalog = &mut Catalog[@admin];
    if (!catalog.items.contains(full_object_id)) {
        catalog.items.add(full_object_id, ItemInfo { allowlist: vector[] });
    };
}

public entry fun grant(owner: &signer, full_object_id: vector<u8>, reader: address) {
    assert!(owner.address_of() == extract_owner_from_full_object_id(full_object_id), error::permission_denied(E_NOT_OWNER));
    let catalog = &mut Catalog[@admin];
    assert!(catalog.items.contains(full_object_id), error::not_found(E_ITEM_NOT_FOUND));
    let item = catalog.items.borrow_mut(full_object_id);
    if (!item.allowlist.contains(&reader)) {
        item.allowlist.push_back(reader);
    };
}
```

Finally, as required by ACE, we implement the fixed-shape view function to correctly execute the access policy based on the contract state.

```move
#[view]
public fun on_ace_decryption_request(
    full_object_id: vector<u8>,
    user: address,
    origin: String,
): bool {
    // Owner should always have access.
    if (extract_owner_from_full_object_id(full_object_id) == user) return true;

    if (!exists<Catalog>(@admin)) return false;
    let catalog = &Catalog[@admin];
    if (!catalog.items.contains(full_object_id)) return false;
    let item = catalog.items.borrow(full_object_id);
    item.allowlist.contains(&user)
}
```

NOTE: parameter `origin` is currently ignored. We will worry about it later.

### Client changes

In the client, we use the same object ID bytes that the contract uses for lookup. The SDK calls those bytes the `label`; in this app, we simply use `full_object_id` as the IBE `label`.

Before the SDK calls, fill in the ACE deployment values. These are not derived from your app contract. During preview, use the `aceDeployment` and `keypairId` provided by the ACE team or by a ready-to-run example/localnet config; once public deployments are available, this should point to the public registry.

```typescript
import * as ACE from "@aptos-labs/ace-sdk";
import { AccountAddress } from "@aptos-labs/ts-sdk";

const aceDeployment = new ACE.AceDeployment({
  apiEndpoint: "https://api.testnet.aptoslabs.com/v1",
  contractAddr: AccountAddress.fromString("0x<ace-contract-address>"),
});
const keypairId = AccountAddress.fromString("0x<ace-keypair-id>");
const chainId = 2; // Aptos testnet

const moduleAddr = AccountAddress.fromString("0x<app-module-address>");
const moduleName = "content_access"; // matches module <publisher>::content_access
```

Encrypt before or after listing the item on-chain, but use the same bytes for `full_object_id` in Move and `label` in the SDK:

```typescript
const fullObjectId = new TextEncoder().encode("0x<owner-address>/album/song-001");
const label = fullObjectId;

const ciphertext = (await ACE.IBE_Aptos.encrypt({
  aceDeployment,
  keypairId,
  chainId,
  moduleAddr,
  moduleName,
  label,
  plaintext: songBytes,
})).unwrapOrThrow("ACE encrypt failed");
```

If you encrypt many objects with the same ACE keypair and t-IBE scheme, fetch the public key once and pass it to each encryption call. If you use a non-default `tibeScheme`, pass it to `fetchPk` too.

```typescript
const pk = (await ACE.IBE_Aptos.fetchPk({
  aceDeployment,
  keypairId,
})).unwrapOrThrow("ACE public key fetch failed");

const ciphertext = (await ACE.IBE_Aptos.encrypt({
  aceDeployment,
  keypairId,
  chainId,
  moduleAddr,
  moduleName,
  label,
  plaintext: songBytes,
  pk,
})).unwrapOrThrow("ACE encrypt failed");
```

These parameters tell ACE which app contract and object ID this ciphertext belongs to. In this example, the SDK `label` is the full object ID, so decrypting the content will check access for that same object ID.

For decryption, prefer the session-style API in wallets and web apps. It lets you build the canonical request first, show or pass it to the wallet, then submit the proof:

```typescript
const session = await ACE.IBE_Aptos.BasicDecryptionSession.create({
  aceDeployment,
  keypairId,
  chainId,
  moduleAddr,
  moduleName,
  label,
  ciphertext,
});

const message = await session.getRequestToSign();
// AIP-62 signMessage does not return the account public key. Obtain and
// normalize this from the wallet's connected account as an Aptos `PublicKey`.
const connectedAccountPublicKey = getConnectedAccountPublicKey();
const signed = await wallet.signMessage({
  message,
  nonce: crypto.randomUUID(),
  address: true,
  application: true,
  chainId: true,
});

// This assumes the adapter returns an Aptos SDK `Signature` object. If it
// returns serialized bytes or hex instead, normalize it at the adapter boundary.

const plaintext = (await session.decryptWithProof({
  userAddr: userAddress,
  publicKey: connectedAccountPublicKey,
  signature: signed.signature,
  fullMessage: signed.fullMessage,
})).unwrapOrThrow("ACE decrypt failed");
```

If you need to store or pass around the worker results before opening the ciphertext, fetch the identity key shares first and finish locally:

```typescript
const identityKeyShares = (await session.fetchIdentityKeySharesWithProof({
  userAddr: userAddress,
  publicKey: connectedAccountPublicKey,
  signature: signed.signature,
  fullMessage: signed.fullMessage,
})).unwrapOrThrow("ACE fetch identity key shares failed");

const plaintext = ACE.IBE_Aptos.decryptWithIdentityKeyShares({
  ciphertext,
  identityKeyShares,
}).unwrapOrThrow("ACE local decrypt failed");
```

The `address`, `application`, and `chainId` AIP-62 inputs are boolean inclusion flags, not address or chain-id values. ACE verifies that `fullMessage` contains the exact SDK-generated hexadecimal BCS request, verifies the signature and connected account key against Aptos, and passes the signed `application` value to the Move hook as `origin`.

For passkey accounts, use the dedicated WebAuthn path. The SDK constructs the challenge and converts the browser's DER ECDSA assertion into the Aptos WebAuthn proof shape:

```typescript
const challenge = await session.getRequestToSignForWebAuthn();
const credential = await navigator.credentials.get({
  publicKey: {
    challenge,
    rpId: window.location.hostname,
    allowCredentials,
    userVerification: "required",
  },
}) as PublicKeyCredential;
const response = credential.response as AuthenticatorAssertionResponse;

const plaintext = (await session.decryptWithWebAuthnAssertion({
  userAddr: userAddress,
  publicKey: connectedPasskeyPublicKey,
  authenticatorData: new Uint8Array(response.authenticatorData),
  clientDataJSON: new Uint8Array(response.clientDataJSON),
  signature: new Uint8Array(response.signature),
})).unwrapOrThrow("ACE passkey decrypt failed");
```

For key reuse before you have a specific ciphertext, create the session with `tibeScheme` instead of `ciphertext`.

For scripts or backend services that sign directly with an Aptos account, build the same wallet-style `fullMessage` before signing. Do not sign `message` by itself; sign the full string returned by `buildAptosWalletFullMessage`.

```typescript
const plaintext = (await ACE.IBE_Aptos.decryptBasicFlow({
  aceDeployment,
  keypairId,
  chainId,
  moduleAddr,
  moduleName,
  label,
  ciphertext,
  accountAddress: serviceAccount.accountAddress,
  sign: async (message) => {
    const fullMessage = ACE.IBE_Aptos.buildAptosWalletFullMessage({
      accountAddress: serviceAccount.accountAddress,
      application: "https://<your-deployed-app-origin>",
      chainId,
      message,
      nonce: crypto.randomUUID(),
    });
    return {
      pubKey: serviceAccount.publicKey,
      signature: serviceAccount.sign(fullMessage),
      fullMessage,
    };
  },
})).unwrapOrThrow("ACE decrypt failed");
```

The important detail for the next step is that the signed wallet message includes the application origin. ACE passes that value to `on_ace_decryption_request` as the `origin` argument, so the contract can reject requests signed for the wrong app.

### Check request origin

Now that the client signs an application-scoped wallet message, we can harden the contract by checking the request origin. This is separate from item policy: it is one deployed-client setting, not one value per item. The goal is to prevent a malicious app from tricking a user into signing a decryption request for your contract from the wrong origin.

To do that, we store the expected client origin in a separate config resource:

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

Then we make the hook reject requests whose wallet-signed origin does not match that app-level config:

```move
#[view]
public fun on_ace_decryption_request(
    full_object_id: vector<u8>,
    user: address,
    origin: String,
): bool {
    if (!exists<Catalog>(@admin)) return false;
    if (!exists<AppConfig>(@admin)) return false;
    let catalog = &Catalog[@admin];
    let config = &AppConfig[@admin];
    if (origin.bytes() != &config.client_origin) return false;
    if (extract_owner_from_full_object_id(full_object_id) == user) return true;
    if (!catalog.items.contains(full_object_id)) return false;
    let item = catalog.items.borrow(full_object_id);
    item.allowlist.contains(&user)
}
```

Putting those pieces together, the assembled module sketch looks like this. It intentionally leaves the app-specific `extract_owner_from_full_object_id` parser as a declaration; replace that declaration with your encoding's real implementation before compiling.

```move
module admin::content_access {
    use aptos_std::table;
    use aptos_std::table::Table;
    use std::error;
    use std::string::String;

    const E_NOT_ADMIN: u64 = 1;
    const E_ITEM_NOT_FOUND: u64 = 2;
    const E_NOT_INITIALIZED: u64 = 3;
    const E_NOT_OWNER: u64 = 4;

    struct ItemInfo has store, drop {
        allowlist: vector<address>,
    }

    struct Catalog has key {
        items: Table<vector<u8>, ItemInfo>,
    }

    struct AppConfig has key {
        client_origin: vector<u8>,
    }

    public entry fun init(admin: &signer) {
        assert!(admin.address_of() == @admin, error::permission_denied(E_NOT_ADMIN));
        if (!exists<Catalog>(@admin)) {
            move_to(admin, Catalog {
                items: table::new(),
            });
        };
        if (!exists<AppConfig>(@admin)) {
            move_to(admin, AppConfig {
                client_origin: vector[],
            });
        };
    }

    /// We assume the full object ID contains owner info.
    fun extract_owner_from_full_object_id(object_id: vector<u8>): address;

    public entry fun set_client_origin(
        admin: &signer,
        origin: vector<u8>,
    ) {
        assert!(admin.address_of() == @admin, error::permission_denied(E_NOT_ADMIN));
        assert!(exists<AppConfig>(@admin), error::not_found(E_NOT_INITIALIZED));
        let config = &mut AppConfig[@admin];
        config.client_origin = origin;
    }

    public entry fun register_item(owner: &signer, full_object_id: vector<u8>) {
        assert!(owner.address_of() == extract_owner_from_full_object_id(full_object_id), error::permission_denied(E_NOT_OWNER));
        let catalog = &mut Catalog[@admin];
        if (!catalog.items.contains(full_object_id)) {
            catalog.items.add(full_object_id, ItemInfo { allowlist: vector[] });
        };
    }

    public entry fun grant(owner: &signer, full_object_id: vector<u8>, reader: address) {
        assert!(owner.address_of() == extract_owner_from_full_object_id(full_object_id), error::permission_denied(E_NOT_OWNER));
        let catalog = &mut Catalog[@admin];
        assert!(catalog.items.contains(full_object_id), error::not_found(E_ITEM_NOT_FOUND));
        let item = catalog.items.borrow_mut(full_object_id);
        if (!item.allowlist.contains(&reader)) {
            item.allowlist.push_back(reader);
        };
    }

    #[view]
    public fun on_ace_decryption_request(
        full_object_id: vector<u8>,
        user: address,
        origin: String,
    ): bool {
        if (!exists<Catalog>(@admin)) return false;
        if (!exists<AppConfig>(@admin)) return false;
        let catalog = &Catalog[@admin];
        let config = &AppConfig[@admin];
        if (origin.bytes() != &config.client_origin) return false;
        if (extract_owner_from_full_object_id(full_object_id) == user) return true;
        if (!catalog.items.contains(full_object_id)) return false;
        let item = catalog.items.borrow(full_object_id);
        item.allowlist.contains(&user)
    }
}
```

Use `full_object_id` as the object ID in the contract and pass the same bytes as `label` to `encrypt`. Use `user` as the authenticated requester. Use `origin` to reject signatures made for another app. `AppConfig.client_origin` is one app-level value, not item policy. Keep it empty while the client is not ready, then call `set_client_origin` once after deploying the web app or CLI wrapper and learning the real production origin.

Deploy the Move package, run `init`, register your object IDs, and grant whatever test access you need. Once the client is deployed, call `set_client_origin` with its stable origin. Do not repeat this per object ID. Record:

- `chainId`: the Aptos chain id.
- `moduleAddr`: the account that published your module.
- `moduleName`: the Move module containing `on_ace_decryption_request`.
- `aceDeployment` and `keypairId`: from the ACE deployment you target, such as a preview value provided by the ACE team or a localnet/example config.

## Remarks

Once a user is allowed to decrypt something, assume they can keep the plaintext. They may save it, copy it, screenshot it, or simply remember it. Revoking that user's access in the contract can prevent future ACE decryption requests, but it does not make already revealed plaintext disappear. If your application needs ongoing control after decryption, ACE can still gate access to the encrypted content, but the plaintext should stay inside your own DRM-style client instead of being exposed directly to the user.

## Ready-To-Run Examples

- [`examples/tutorial-aptos`](../../../examples/tutorial-aptos): minimal pay-to-download marketplace.
