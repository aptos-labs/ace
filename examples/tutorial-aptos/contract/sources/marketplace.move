// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Tutorial: a minimal pay-to-download marketplace gating ACE-encrypted items.
///
/// The admin lists items at fixed APT prices. A buyer pays the price in a
/// single transaction and is added to the item's buyer list. ACE workers
/// invoke `on_ace_decryption_request(item_name, user, origin)` before releasing key shares,
/// so a buyer can decrypt only the items they have actually paid for, and only
/// when the request was signed for this app's origin (anti-replay across dapps).
module admin::marketplace {
    use std::error;
    use std::string::String;
    use aptos_std::table;
    use aptos_std::table::Table;
    use aptos_framework::aptos_account;

    /// Caller is not the admin.
    const E_NOT_ADMIN: u64 = 1;
    /// Item does not exist in the catalog.
    const E_ITEM_NOT_FOUND: u64 = 2;
    /// An item with this name has already been listed.
    const E_ITEM_ALREADY_LISTED: u64 = 3;

    /// The dapp origin that ACE requests must be signed for. Must match
    /// `TUTORIAL_APP_ORIGIN` in `scripts/common.ts`. The hook rejects any
    /// request whose wallet `application:` line names a different origin.
    const EXPECTED_APP_ORIGIN: vector<u8> = b"https://tutorial.ace.aptos.dev";

    struct Item has store, drop {
        price: u64,
        buyers: vector<address>,
    }

    /// The admin's catalog of items for sale, keyed by item name.
    struct Catalog has key {
        items: Table<vector<u8>, Item>,
    }

    /// Initialize an empty catalog. Must be called once by the admin after deploy.
    public entry fun initialize(admin: &signer) {
        assert!(@admin == admin.address_of(), error::permission_denied(E_NOT_ADMIN));
        if (!exists<Catalog>(@admin)) {
            move_to(admin, Catalog { items: table::new() });
        };
    }

    /// List a new item at `price` octas (1 APT = 100_000_000 octas).
    /// Aborts if an item with the same name is already listed.
    public entry fun list_item(admin: &signer, name: vector<u8>, price: u64) {
        assert!(@admin == admin.address_of(), error::permission_denied(E_NOT_ADMIN));
        let catalog = &mut Catalog[@admin];
        assert!(!catalog.items.contains(name), error::already_exists(E_ITEM_ALREADY_LISTED));
        catalog.items.add(name, Item { price, buyers: vector[] });
    }

    /// Pay the item's price in APT to the admin, then join its buyer list.
    /// After this, `on_ace_decryption_request(name, buyer, origin)` returns true.
    public entry fun buy(buyer: &signer, name: vector<u8>) {
        let catalog = &mut Catalog[@admin];
        assert!(catalog.items.contains(name), error::invalid_argument(E_ITEM_NOT_FOUND));
        let item = catalog.items.borrow_mut(name);
        aptos_account::transfer(buyer, @admin, item.price);
        let buyer_addr = buyer.address_of();
        if (!item.buyers.contains(&buyer_addr)) {
            item.buyers.push_back(buyer_addr);
        };
    }

    #[view]
    /// The hook ACE workers call before releasing a decryption key share.
    /// Returns true iff the request was signed for this app's origin and
    /// `account` is the admin or has bought item `label`.
    public fun on_ace_decryption_request(
        label: vector<u8>,
        account: address,
        origin: String,
    ): bool {
        if (origin.bytes() != &EXPECTED_APP_ORIGIN) return false;
        if (account == @admin) return true;
        let catalog = &Catalog[@admin];
        if (!catalog.items.contains(label)) return false;
        let item = catalog.items.borrow(label);
        item.buyers.contains(&account)
    }
}
