// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Tutorial: a minimal pay-to-download marketplace gating ACE-encrypted items.
///
/// The admin lists items at fixed APT prices. A buyer pays the price in a
/// single transaction and is added to the item's buyer list. ACE workers
/// invoke `check_permission(user, item_name)` before releasing key shares,
/// so a buyer can decrypt only the items they have actually paid for.
module admin::marketplace {
    use std::error;
    use std::signer::address_of;
    use std::vector;
    use aptos_std::table;
    use aptos_std::table::Table;
    use aptos_framework::aptos_account;

    /// Caller is not the admin.
    const E_NOT_ADMIN: u64 = 1;
    /// Item does not exist in the catalog.
    const E_ITEM_NOT_FOUND: u64 = 2;
    /// An item with this name has already been listed.
    const E_ITEM_ALREADY_LISTED: u64 = 3;

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
        assert!(@admin == address_of(admin), error::permission_denied(E_NOT_ADMIN));
        if (!exists<Catalog>(@admin)) {
            move_to(admin, Catalog { items: table::new() });
        };
    }

    /// List a new item at `price` octas (1 APT = 100_000_000 octas).
    /// Aborts if an item with the same name is already listed.
    public entry fun list_item(admin: &signer, name: vector<u8>, price: u64) acquires Catalog {
        assert!(@admin == address_of(admin), error::permission_denied(E_NOT_ADMIN));
        let catalog = borrow_global_mut<Catalog>(@admin);
        assert!(!catalog.items.contains(name), error::already_exists(E_ITEM_ALREADY_LISTED));
        catalog.items.add(name, Item { price, buyers: vector::empty() });
    }

    /// Pay the item's price in APT to the admin, then join its buyer list.
    /// After this, `check_permission(buyer, name)` returns true.
    public entry fun buy(buyer: &signer, name: vector<u8>) acquires Catalog {
        let catalog = borrow_global_mut<Catalog>(@admin);
        assert!(catalog.items.contains(name), error::invalid_argument(E_ITEM_NOT_FOUND));
        let item = catalog.items.borrow_mut(name);
        aptos_account::transfer(buyer, @admin, item.price);
        let buyer_addr = address_of(buyer);
        if (!item.buyers.contains(&buyer_addr)) {
            item.buyers.push_back(buyer_addr);
        };
    }

    #[view]
    /// The hook ACE workers call before releasing a decryption key share.
    /// Returns true iff `user` is the admin or has bought item `domain`.
    public fun check_permission(user: address, domain: vector<u8>): bool acquires Catalog {
        if (user == @admin) return true;
        let catalog = borrow_global<Catalog>(@admin);
        if (!catalog.items.contains(domain)) return false;
        let item = catalog.items.borrow(domain);
        item.buyers.contains(&user)
    }
}
