// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Shelby S3 demo policy for ACE basic flow.
///
/// Files are encrypted before upload. Each encrypted file is registered under
/// its ACE domain/file id with an owner and an allowlist of reader addresses.
/// A "pre-signed access token" is represented as a fresh Ed25519 private key;
/// its derived Aptos address is added to the file allowlist at upload time.
module admin::shelby_s3 {
    use std::error;
    use std::signer::address_of;
    use aptos_std::table;
    use aptos_std::table::Table;

    const E_NOT_ADMIN: u64 = 1;
    const E_FILE_ALREADY_REGISTERED: u64 = 2;
    const E_FILE_NOT_FOUND: u64 = 3;
    const E_NOT_OWNER: u64 = 4;

    struct FileRecord has store, drop {
        owner: address,
        readers: vector<address>,
    }

    struct Registry has key {
        files: Table<vector<u8>, FileRecord>,
    }

    public entry fun initialize(admin: &signer) {
        assert!(@admin == address_of(admin), error::permission_denied(E_NOT_ADMIN));
        if (!exists<Registry>(@admin)) {
            move_to(admin, Registry { files: table::new() });
        };
    }

    /// Register an encrypted file and immediately add the bearer token address.
    ///
    /// The `file_id` must exactly match the ACE encryption domain. The token
    /// address can be an unfunded/nonexistent Aptos account; ACE only needs the
    /// token holder to sign the decryption request with the matching private key.
    public entry fun register_file(
        owner: &signer,
        file_id: vector<u8>,
        token_reader: address,
    ) acquires Registry {
        let registry = borrow_global_mut<Registry>(@admin);
        assert!(
            !registry.files.contains(file_id),
            error::already_exists(E_FILE_ALREADY_REGISTERED),
        );

        registry.files.add(file_id, FileRecord {
            owner: address_of(owner),
            readers: vector[token_reader],
        });
    }

    /// Add another wallet address or bearer-token address to a file.
    public entry fun grant_access(owner: &signer, file_id: vector<u8>, reader: address) acquires Registry {
        let registry = borrow_global_mut<Registry>(@admin);
        assert!(registry.files.contains(file_id), error::not_found(E_FILE_NOT_FOUND));

        let record = registry.files.borrow_mut(file_id);
        assert!(record.owner == address_of(owner), error::permission_denied(E_NOT_OWNER));
        if (!record.readers.contains(&reader)) {
            record.readers.push_back(reader);
        };
    }

    #[view]
    /// ACE workers call this before releasing decryption key shares.
    ///
    /// Basic flow supplies `user` from the request signature. If the reader
    /// signs with the access-token private key, `user` is the token's address.
    public fun check_permission(user: address, file_id: vector<u8>): bool acquires Registry {
        if (!exists<Registry>(@admin)) return false;

        let registry = borrow_global<Registry>(@admin);
        if (!registry.files.contains(file_id)) return false;

        let record = registry.files.borrow(file_id);
        record.owner == user || record.readers.contains(&user)
    }

    #[view]
    public fun is_registered(file_id: vector<u8>): bool acquires Registry {
        exists<Registry>(@admin) && borrow_global<Registry>(@admin).files.contains(file_id)
    }

    #[test(admin = @admin, owner = @0xaa)]
    fun bearer_token_flow(admin: &signer, owner: &signer) acquires Registry {
        initialize(admin);

        register_file(owner, b"alice/report.pdf", @0xbb);

        assert!(check_permission(@0xaa, b"alice/report.pdf"), 1);
        assert!(check_permission(@0xbb, b"alice/report.pdf"), 2);
        assert!(!check_permission(@0xcc, b"alice/report.pdf"), 3);
        assert!(!check_permission(@0xbb, b"alice/other.pdf"), 4);

        grant_access(owner, b"alice/report.pdf", @0xdd);
        assert!(check_permission(@0xdd, b"alice/report.pdf"), 5);
    }
}
