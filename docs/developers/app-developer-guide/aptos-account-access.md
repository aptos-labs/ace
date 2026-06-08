# Aptos Account Access: Can account X access object Y?

## TLDR

Use this flow when an Aptos contract can decide decryption from three values: the encrypted object's `label`, the requestor's Aptos account address, and the application `origin` that the user signed for. It is the right default for allowlists, subscriptions, time locks, and pay-to-download flows where a purchase function writes entitlement state on-chain.

You need to:

- Write a Move module with `on_ace_decryption_request(label, account, origin): bool`.
- Store enough policy state to answer that view function.
- Encrypt with `ACE.IBE_Aptos.encrypt`.
- Decrypt with `ACE.IBE_Aptos.BasicDecryptionSession`, asking the user's wallet to sign the session request.
- Lock the hook to the deployed web app origin once the origin is stable.

## Example walkthrough: Allowlisted content catalog

In this example, we show how to build an allowlist-style content catalog with ACE. The high-level idea is to encrypt each content item with ACE, maintain the access policy on-chain, and let that policy gate whether ACE workers may release decryption shares for a user.

### 1. Design the contract

In the contract, we need three pieces: a table that stores the allowlist for each content label, entry functions that update that table, and the ACE view function `on_ace_decryption_request`, which reads the table and approves or rejects each request.

To work with ACE basic IBE, we expose a hook with this fixed shape:

```move
public fun on_ace_decryption_request(
    label: vector<u8>,
    account: address,
    origin: String,
): bool
```

ACE workers call this hook before releasing decryption shares. If the hook returns `true`, the requester may decrypt. If it returns `false`, workers withhold shares.

First, we define the access policy. The catalog is keyed by the same `label` that the client passes to `ACE.IBE_Aptos.encrypt`, and each item stores the accounts that may decrypt it:

```move
struct Item has store, drop {
    readers: vector<address>,
}

struct Catalog has key {
    items: Table<vector<u8>, Item>,
}
```

Then we expose entry functions that create catalog items and grant readers access. In a real subscription or pay-to-download app, the grant write would usually happen inside purchase or subscription logic; here we keep the writer simple so the ACE hook is easy to see.

```move
public entry fun register_item(admin: &signer, label: vector<u8>) acquires Catalog {
    assert!(signer::address_of(admin) == @admin, error::permission_denied(E_NOT_ADMIN));
    let catalog = borrow_global_mut<Catalog>(@admin);
    if (!catalog.items.contains(label)) {
        catalog.items.add(label, Item { readers: vector::empty() });
    };
}

public entry fun grant(admin: &signer, label: vector<u8>, reader: address) acquires Catalog {
    assert!(signer::address_of(admin) == @admin, error::permission_denied(E_NOT_ADMIN));
    let catalog = borrow_global_mut<Catalog>(@admin);
    assert!(catalog.items.contains(label), error::not_found(E_ITEM_NOT_FOUND));
    let item = catalog.items.borrow_mut(label);
    if (!item.readers.contains(&reader)) {
        item.readers.push_back(reader);
    };
}
```

Finally, the hook consumes that state: it finds the item by `label`, then checks whether the requesting `account` is in `readers`.

```move
#[view]
public fun on_ace_decryption_request(
    label: vector<u8>,
    account: address,
    _origin: String,
): bool acquires Catalog {
    if (!exists<Catalog>(@admin)) return false;
    let catalog = borrow_global<Catalog>(@admin);
    if (!catalog.items.contains(label)) return false;
    let item = catalog.items.borrow(label);
    item.readers.contains(&account)
}
```

At this point, the hook only models the business policy. It ignores `origin` while we focus on the allowlist; the client step below shows where `origin` comes from, and the final step adds that check.

### 2. Use the SDK in the client

In the client, we use the same `label` that the contract uses for lookup. We first encrypt the content under that label, then ask the user's wallet to sign a decryption request for the same label.

Encrypt before or after listing the item on-chain, but use the same `label` in both places:

```typescript
import * as ACE from "@aptos-labs/ace-sdk";
import { AccountAddress } from "@aptos-labs/ts-sdk";

const label = new TextEncoder().encode("album/song-001");

const ciphertext = (await ACE.IBE_Aptos.encrypt({
  aceDeployment,
  keypairId,
  chainId,
  moduleAddr: AccountAddress.fromString("0x<app-module-address>"),
  moduleName: "content_access",
  label,
  plaintext: songBytes,
})).unwrapOrThrow("ACE encrypt failed");
```

These parameters bind the ciphertext to one ACE keypair, one app contract, and one label. Workers will only release shares for a request with the same tuple.

For decryption, prefer the session-style API in wallets and web apps. It lets you build the canonical request first, show or pass it to the wallet, then submit the proof:

```typescript
const session = await ACE.IBE_Aptos.BasicDecryptionSession.create({
  aceDeployment,
  keypairId,
  chainId,
  moduleAddr: AccountAddress.fromString("0x<app-module-address>"),
  moduleName: "content_access",
  label,
  ciphertext,
});

const message = await session.getRequestToSign();
const signed = await wallet.signMessage({
  message,
  nonce: crypto.randomUUID(),
  application: true,
  chainId,
  address: userAddress,
});

const plaintext = (await session.decryptWithProof({
  userAddr: userAddress,
  publicKey: signed.publicKey,
  signature: signed.signature,
  fullMessage: signed.fullMessage,
})).unwrapOrThrow("ACE decrypt failed");
```

For scripts or backend jobs that already know how to sign, `ACE.IBE_Aptos.decryptBasicFlow` wraps the same sequence in one function.

The important detail for the next step is that ACE workers extract the application origin from the Aptos wallet message in `signed.fullMessage` and pass it to `on_ace_decryption_request` as the `origin` argument. That gives the contract enough information to reject requests signed for the wrong app.

### 3. Check request origin

Now that the client signs an application-scoped wallet message, we can harden the contract by checking the request origin. This is separate from item policy: it is one deployed-client setting, not one value per item. The goal is to prevent a malicious app from tricking a user into signing a decryption request for your contract from the wrong origin.

To do that, we store the expected client origin in a separate config resource:

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

Then we make the hook reject requests whose wallet-signed origin does not match that app-level config:

```move
#[view]
public fun on_ace_decryption_request(
    label: vector<u8>,
    account: address,
    origin: String,
): bool acquires Catalog, AppConfig {
    if (!exists<Catalog>(@admin)) return false;
    if (!exists<AppConfig>(@admin)) return false;
    let catalog = borrow_global<Catalog>(@admin);
    let config = borrow_global<AppConfig>(@admin);
    if (origin.bytes() != &config.client_origin) return false;
    if (!catalog.items.contains(label)) return false;
    let item = catalog.items.borrow(label);
    item.readers.contains(&account)
}
```

Putting those pieces together, the final module looks like this:

```move
module admin::content_access {
    use aptos_std::table;
    use aptos_std::table::Table;
    use std::error;
    use std::signer;
    use std::string::String;

    const E_NOT_ADMIN: u64 = 1;
    const E_ITEM_NOT_FOUND: u64 = 2;
    const E_NOT_INITIALIZED: u64 = 3;

    struct Item has store, drop {
        readers: vector<address>,
    }

    struct Catalog has key {
        items: Table<vector<u8>, Item>,
    }

    struct AppConfig has key {
        client_origin: vector<u8>,
    }

    public entry fun init(admin: &signer) {
        assert!(signer::address_of(admin) == @admin, error::permission_denied(E_NOT_ADMIN));
        if (!exists<Catalog>(@admin)) {
            move_to(admin, Catalog {
                items: table::new(),
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

    public entry fun register_item(admin: &signer, label: vector<u8>) acquires Catalog {
        assert!(signer::address_of(admin) == @admin, error::permission_denied(E_NOT_ADMIN));
        let catalog = borrow_global_mut<Catalog>(@admin);
        if (!catalog.items.contains(label)) {
            catalog.items.add(label, Item { readers: vector::empty() });
        };
    }

    public entry fun grant(admin: &signer, label: vector<u8>, reader: address) acquires Catalog {
        assert!(signer::address_of(admin) == @admin, error::permission_denied(E_NOT_ADMIN));
        let catalog = borrow_global_mut<Catalog>(@admin);
        assert!(catalog.items.contains(label), error::not_found(E_ITEM_NOT_FOUND));
        let item = catalog.items.borrow_mut(label);
        if (!item.readers.contains(&reader)) {
            item.readers.push_back(reader);
        };
    }

    #[view]
    public fun on_ace_decryption_request(
        label: vector<u8>,
        account: address,
        origin: String,
    ): bool acquires Catalog, AppConfig {
        if (!exists<Catalog>(@admin)) return false;
        if (!exists<AppConfig>(@admin)) return false;
        let catalog = borrow_global<Catalog>(@admin);
        let config = borrow_global<AppConfig>(@admin);
        if (origin.bytes() != &config.client_origin) return false;
        if (!catalog.items.contains(label)) return false;
        let item = catalog.items.borrow(label);
        item.readers.contains(&account)
    }
}
```

Use `label` as the object id that your client also passes to `encrypt`. Use `account` as the authenticated requester. Use `origin` to reject signatures made for another app. `AppConfig.client_origin` is one app-level value, not item policy. Keep it empty while the client is not ready, then call `set_client_origin` once after deploying the web app or CLI wrapper and learning the real production origin.

Deploy the Move package, run `init`, register your items, and grant whatever test access you need. Once the client is deployed, call `set_client_origin` with its stable origin. Do not repeat this per label. Record:

- `chainId`: the Aptos chain id.
- `moduleAddr`: the account that published your module.
- `moduleName`: the Move module containing `on_ace_decryption_request`.
- `aceDeployment` and `keypairId`: from `ACE.knownDeployments` or your local ACE network config.

## Remarks

Once a user is allowed to decrypt something, assume they can keep the plaintext. They may save it, copy it, screenshot it, or simply remember it. Revoking that user's access in the contract can prevent future ACE decryption requests, but it does not make already revealed plaintext disappear. If your application needs ongoing control after decryption, ACE can still gate access to the encrypted content, but the plaintext should stay inside your own DRM-style client instead of being exposed directly to the user.

## Ready-To-Run Examples

- [`examples/tutorial-aptos`](../../../examples/tutorial-aptos): minimal pay-to-download marketplace.
- [`examples/shelby-explorer-acl-aptos`](../../../examples/shelby-explorer-acl-aptos): allowlist, time lock, and pay-to-download policies.
