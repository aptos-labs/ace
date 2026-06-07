# Aptos Basic IBE: Move-Gated Decryption

## TLDR

Use this flow when an Aptos contract can decide decryption from three values: the encrypted object's `label`, the requestor's Aptos account address, and the application `origin` that the user signed for. It is the right default for allowlists, subscriptions, time locks, and pay-to-download flows where a purchase function writes entitlement state on-chain.

You need to:

- Write a Move module with `on_ace_decryption_request(label, account, origin): bool`.
- Store enough policy state to answer that view function.
- Encrypt with `ACE.IBE_Aptos.encrypt`.
- Decrypt with `ACE.IBE_Aptos.BasicDecryptionSession`, asking the user's wallet to sign the session request.
- Lock the hook to the deployed web app origin once the origin is stable.

## Walkthrough

Start with the access policy. This walkthrough uses an allowlist-style content catalog keyed by `label`, where each item records the accounts that may decrypt it. The ACE hook is a view function with a fixed name and fixed signature. This minimal module defines the entitlement state the hook reads:

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

The parameters bind the ciphertext to one ACE keypair, one app contract, and one label. Workers will only release shares for a request with the same tuple.

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

After the client is deployed, make the origin check final. For Aptos wallet messages, ACE workers extract the application origin from the signed full message and pass it to your hook. A contract that does not check `origin` can be tricked into serving requests signed for another app.

## Remarks

Once a user is allowed to decrypt something, assume they can keep the plaintext. They may save it, copy it, screenshot it, or simply remember it. Revoking that user's access in the contract can prevent future ACE decryption requests, but it does not make already revealed plaintext disappear. If your application needs ongoing control after decryption, ACE can still gate access to the encrypted content, but the plaintext should stay inside your own DRM-style client instead of being exposed directly to the user.

## Ready-To-Run Examples

- [`examples/tutorial-aptos`](../../../examples/tutorial-aptos): minimal pay-to-download marketplace.
- [`examples/shelby-explorer-acl-aptos`](../../../examples/shelby-explorer-acl-aptos): allowlist, time lock, and pay-to-download policies.
