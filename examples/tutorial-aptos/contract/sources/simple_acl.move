// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Tutorial: a minimal ACL contract that gates ACE-encrypted blobs.
///
/// One admin owns a registry of blobs. For each blob, the owner maintains an
/// allowlist of addresses that may decrypt. The `check_permission` view is
/// what ACE workers call before releasing key shares.
module admin::simple_acl {
    use std::error;
    use std::signer::address_of;
    use std::vector;
    use aptos_std::table;
    use aptos_std::table::Table;

    /// Caller is not the admin.
    const E_NOT_ADMIN: u64 = 1;
    /// Blob does not exist in the registry.
    const E_BLOB_NOT_FOUND: u64 = 2;
    /// Caller is not the blob owner.
    const E_NOT_OWNER: u64 = 3;
    /// User is not in the blob's allowlist (only used when distinguishing in tests).
    const E_NOT_ALLOWED: u64 = 4;

    struct Blob has store, drop {
        owner: address,
        allowlist: vector<address>,
    }

    /// Global blob registry, stored at the admin address.
    struct Registry has key {
        blobs: Table<vector<u8>, Blob>,
    }

    /// Initialize the registry. Must be called once by the admin.
    public entry fun initialize(admin: &signer) {
        assert!(@admin == address_of(admin), error::permission_denied(E_NOT_ADMIN));
        if (!exists<Registry>(@admin)) {
            move_to(admin, Registry { blobs: table::new() });
        };
    }

    /// Register a new blob. The signer becomes the blob's owner.
    /// If a blob with this name already exists, it is overwritten.
    public entry fun register_blob(owner: &signer, name: vector<u8>) acquires Registry {
        let registry = borrow_global_mut<Registry>(@admin);
        let blob = Blob { owner: address_of(owner), allowlist: vector::empty() };
        registry.blobs.upsert(name, blob);
    }

    /// Add `user` to the allowlist for `name`. Only the blob owner may call.
    public entry fun grant_access(owner: &signer, name: vector<u8>, user: address) acquires Registry {
        let registry = borrow_global_mut<Registry>(@admin);
        assert!(registry.blobs.contains(name), error::invalid_argument(E_BLOB_NOT_FOUND));
        let blob = registry.blobs.borrow_mut(name);
        assert!(blob.owner == address_of(owner), error::permission_denied(E_NOT_OWNER));
        if (!blob.allowlist.contains(&user)) {
            blob.allowlist.push_back(user);
        };
    }

    /// Remove `user` from the allowlist for `name`. Only the blob owner may call.
    /// No-op if the user isn't on the list.
    public entry fun revoke_access(owner: &signer, name: vector<u8>, user: address) acquires Registry {
        let registry = borrow_global_mut<Registry>(@admin);
        assert!(registry.blobs.contains(name), error::invalid_argument(E_BLOB_NOT_FOUND));
        let blob = registry.blobs.borrow_mut(name);
        assert!(blob.owner == address_of(owner), error::permission_denied(E_NOT_OWNER));
        let (found, idx) = blob.allowlist.index_of(&user);
        if (found) {
            blob.allowlist.remove(idx);
        };
    }

    #[view]
    /// The hook ACE workers call before releasing a decryption key share.
    /// Returns true iff the user is the blob owner or appears in its allowlist.
    public fun check_permission(user: address, domain: vector<u8>): bool acquires Registry {
        let registry = borrow_global<Registry>(@admin);
        if (!registry.blobs.contains(domain)) return false;
        let blob = registry.blobs.borrow(domain);
        if (blob.owner == user) return true;
        blob.allowlist.contains(&user)
    }
}
