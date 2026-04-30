// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Demo ACE hook for the custom-flow scenario.
///
/// The admin stores an access code for each label. ACE workers call
/// `check_acl(label, enc_pk, payload)` as a view function; it returns `true`
/// iff `payload` matches the stored code for `label`.
///
/// In a production system the payload would be a zero-knowledge proof and
/// `check_acl` would verify it on-chain. Here we use a simple code comparison
/// as an illustrative stand-in.
module admin::check_acl_demo {
    use std::error;
    use std::signer::address_of;
    use aptos_std::table;
    use aptos_std::table::Table;

    const E_ONLY_ADMIN: u64 = 1;

    struct AclStore has key {
        /// Maps label (IBE domain bytes) to the expected proof/payload bytes.
        codes: Table<vector<u8>, vector<u8>>,
    }

    /// Create the AclStore. Must be called by the admin before any codes are set.
    public entry fun initialize(admin: &signer) {
        assert!(@admin == address_of(admin), error::permission_denied(E_ONLY_ADMIN));
        if (!exists<AclStore>(@admin)) {
            move_to(admin, AclStore { codes: table::new() });
        };
    }

    /// Store (or replace) the access code for `label`.
    public entry fun set_access_code(
        admin: &signer,
        label: vector<u8>,
        code: vector<u8>,
    ) acquires AclStore {
        assert!(@admin == address_of(admin), error::permission_denied(E_ONLY_ADMIN));
        let store = borrow_global_mut<AclStore>(@admin);
        store.codes.upsert(label, code);
    }

    // ACE hook — return true iff `payload` equals the stored code for `label`.
    // Signature: check_acl(label, enc_pk, payload) -> bool
    #[view]
    public fun check_acl(
        label: vector<u8>,
        _enc_pk: vector<u8>,
        payload: vector<u8>,
    ): bool acquires AclStore {
        if (!exists<AclStore>(@admin)) return false;
        let store = borrow_global<AclStore>(@admin);
        if (!store.codes.contains(label)) return false;
        store.codes.borrow(label) == &payload
    }
}
