// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Access Control Module for ACE
/// 
/// This module implements on-chain access control for encrypted content using ACE.
/// Content owners can register encrypted blobs and control who can decrypt them using
/// different access policies:
/// - Allowlist: Only specified addresses can decrypt
/// - TimeLock: Anyone can decrypt after a specified time
/// - PayToDownload: Users must pay to gain decryption access
///
/// The `check_permission` function serves as the hook that ACE workers call to verify
/// if a user has permission to decrypt a particular blob before releasing key shares.
module admin::access_control {
    use std::error;
    use std::signer::address_of;
    use std::string::{String, utf8};
    use aptos_std::bcs_stream;
    use aptos_std::bcs_stream::BCSStream;
    use aptos_std::string_utils;
    use aptos_std::table;
    use aptos_std::table::Table;
    use aptos_framework::timestamp::now_microseconds;
    #[test_only]
    use std::bcs;
    #[test_only]
    use aptos_framework::aptos_coin::{Self, AptosCoin};
    #[test_only]
    use aptos_framework::coin;
    #[test_only]
    use aptos_framework::timestamp;

    // ============================================================================
    // Error Codes
    // ============================================================================

    /// Returned when BCS deserialization fails (e.g., malformed input bytes)
    const E_DESERIALIZATION_FAILED: u64 = 1;
    /// Returned when an unknown policy mode variant is encountered during deserialization
    const E_UNKNOWN_POLICY_MODE: u64 = 2;
    /// Returned when trying to access a blob that doesn't exist in the registry
    const E_BLOB_NOT_FOUND: u64 = 3;
    /// Returned when trying to purchase a blob that doesn't have PayToDownload policy
    const E_BLOB_NOT_PURCHASABLE: u64 = 4;
    /// Returned when a non-owner tries to perform an owner-only action
    const E_YOU_ARE_NOT_OWNER: u64 = 5;
    /// Returned when user is not in the allowlist for a blob
    const E_BLOB_NOT_IN_ALLOWLIST_NODE: u64 = 6;
    /// Returned when a non-admin tries to call admin-only functions
    const E_ONLY_ADMIN_CAN_CALL_THIS: u64 = 7;
    /// Returned when the default module is called but a custom module should be used
    const E_SHOULD_CALL_CUSTOM_MODULE_INSTEAD: u64 = 8;
    /// Should never be reached - indicates a logic error
    const E_UNREACHABLE: u64 = 9;
    /// Returned when data from a newer version is encountered
    const E_DATA_FROM_FUTURE_VERSION: u64 = 10;

    // ============================================================================
    // Access Policy Schemes (used as enum variant tags in BCS serialization)
    // ============================================================================

    /// Allowlist mode: only addresses in the list can decrypt
    const SCHEME_ALLOWLIST: u8 = 0;
    /// TimeLock mode: anyone can decrypt after `locked_until` timestamp
    const SCHEME_TIMELOCK: u8 = 1;
    /// PayToDownload mode: users must pay the price to gain access
    const SCHEME_PAY_TO_DOWNLOAD: u8 = 2;

    // ============================================================================
    // Data Structures
    // ============================================================================

    /// Defines who can access an encrypted blob.
    /// Each variant represents a different access control mechanism.
    enum AccessPolicy has copy, drop, store {
        /// Only addresses in this list can decrypt (owner always has access)
        Allowlist { addresses: vector<address> }
        /// Anyone can decrypt after the specified timestamp (in microseconds)
        TimeLock { locked_until: u64 }
        /// Users must pay the specified amount (in octas) to gain access
        PayToDownload { price: u64 }
    }

    /// Metadata for a registered encrypted blob.
    struct BlobMetadata has copy, drop, store {
        /// The address that owns this blob and can modify its policy
        owner: address,
        /// The current access policy governing who can decrypt
        access_policy: AccessPolicy,
    }

    /// Global registry storing all blob metadata, keyed by full blob name.
    /// Stored at the admin address.
    struct BlobMap has key {
        blobs: Table<String, BlobMetadata>,
    }

    /// Collection of purchase receipts for a user.
    /// Each user who purchases content has their own ReceiptCollection.
    struct ReceiptCollection has key {
        /// Maps full blob name -> purchase count (1 = purchased)
        receipts: Table<String, u64>,
    }

    /// Information needed to register a new blob.
    struct RegistrationInfo has drop {
        /// The blob name suffix (combined with owner address to form full name)
        blob_name_suffix: String,
        /// The initial access policy for this blob
        access_policy: AccessPolicy,
    }

    // ============================================================================
    // Public Entry Functions
    // ============================================================================

    /// Initialize the access control module.
    /// Must be called by the admin before any blobs can be registered.
    /// Creates the global BlobMap if it doesn't exist.
    public entry fun initialize(admin: &signer) {
        // Only the admin can initialize the module
        assert!(@admin == address_of(admin), error::permission_denied(E_ONLY_ADMIN_CAN_CALL_THIS));
        if (!exists<BlobMap>(@admin)) {
            move_to(admin, BlobMap { blobs: table::new() });
        };
    }

    /// Register multiple blobs at once.
    /// Takes BCS-serialized registration info and registers each blob.
    public entry fun register_blobs(owner: &signer, regs_serialized: vector<u8>) acquires BlobMap {
        let regs = regs_from_bytes(regs_serialized);
        regs.for_each(|reg| register_blob(owner, reg));
    }

    /// Register a single blob with the given metadata.
    /// The full blob name is created by combining the owner's address with the suffix.
    /// If a blob with the same name already exists, it will be overwritten.
    public fun register_blob(owner: &signer, reg: RegistrationInfo) acquires BlobMap {
        let RegistrationInfo { blob_name_suffix, access_policy } = reg;
        let owner_addr = address_of(owner);
        // Full blob name format: "0x<owner_address>/<blob_name_suffix>"
        let full_blob_name = create_full_blob_name(owner_addr, blob_name_suffix);
        let blobs = borrow_global_mut<BlobMap>(@admin);
        let metadata = BlobMetadata {
            owner: owner_addr,
            access_policy,
        };
        // upsert: insert if not exists, update if exists
        blobs.blobs.upsert(full_blob_name, metadata);
    }

    /// Update the access policy for a blob.
    /// Only the blob owner can call this function.
    /// Takes the policy as BCS-serialized bytes.
    public entry fun force_update_policy(owner: &signer, blob_name_suffix: String, policy_bytes: vector<u8>) acquires BlobMap {
        let new_policy = access_policy_from_bytes(policy_bytes);
        force_update_policy_internal(owner, blob_name_suffix, new_policy);
    }

    /// Internal implementation for updating access policy.
    /// Verifies the blob exists and updates its policy.
    public fun force_update_policy_internal(owner: &signer, blob_name_suffix: String, new_policy: AccessPolicy) acquires BlobMap {
        let map = borrow_global_mut<BlobMap>(@admin);
        let owner_addr = address_of(owner);
        let full_blob_name = create_full_blob_name(owner_addr, blob_name_suffix);
        if (map.blobs.contains(full_blob_name)) {
            let metadata = map.blobs.borrow_mut(full_blob_name);
            metadata.access_policy = new_policy;
        } else {
            abort(error::invalid_argument(E_BLOB_NOT_FOUND))
        }
    }

    /// Purchase access to a PayToDownload blob.
    /// Transfers the price from consumer to owner and records a receipt.
    /// Aborts if the blob doesn't use PayToDownload policy.
    public entry fun purchase(consumer: &signer, full_blob_name: String) acquires ReceiptCollection, BlobMap {
        let consumer_addr = address_of(consumer);
        let blob_map = borrow_global<BlobMap>(@admin);
        let metadata = blob_map.blobs.borrow(full_blob_name);
        match (metadata.access_policy) {
            AccessPolicy::PayToDownload { price } => {
                // Transfer payment from consumer to blob owner
                aptos_framework::aptos_account::transfer(consumer, metadata.owner, price);
            }
            _ => {
                // Can only purchase blobs with PayToDownload policy
                abort(error::invalid_state(E_BLOB_NOT_PURCHASABLE));
            }
        };
        // Record the purchase receipt for this consumer
        let receipts = borrow_global_mut<ReceiptCollection>(consumer_addr);
        receipts.receipts.upsert(full_blob_name, 1);
    }

    /// Initialize a receipt collection for a new buyer.
    /// Must be called before a user can purchase any blobs.
    public entry fun init_new_buyer(consumer: &signer) {
        move_to(consumer, ReceiptCollection { receipts: table::new() });
    }

    // ============================================================================
    // ACE Hook
    // ============================================================================

    #[view]
    /// The core access control check called by ACE workers.
    /// 
    /// This view function determines if a user has permission to decrypt a blob.
    /// Workers call this before releasing decryption key shares.
    /// 
    /// Returns true if the user has access, false otherwise.
    /// 
    /// Access is granted if:
    /// - The user is the blob owner (always has access), OR
    /// - For Allowlist: the user's address is in the allowlist
    /// - For TimeLock: the current time is past the lock timestamp
    /// - For PayToDownload: the user has a purchase receipt
    public fun check_permission(user: address, full_blob_name: vector<u8>): bool acquires ReceiptCollection, BlobMap {
        let full_blob_name = utf8(full_blob_name);
        let blob_map = borrow_global<BlobMap>(@admin);
        
        // Blob must exist in the registry
        if (!blob_map.blobs.contains(full_blob_name)) return false;
        
        let metadata = blob_map.blobs.borrow(full_blob_name);
        
        // Owner always has access to their own blobs
        if (metadata.owner == user) return true;
        
        // Check access based on the policy type
        match (&metadata.access_policy) {
            AccessPolicy::PayToDownload { .. } => {
                // User must have a purchase receipt
                if (!exists<ReceiptCollection>(user)) return false;
                borrow_global<ReceiptCollection>(user).receipts.contains(full_blob_name)
            },
            AccessPolicy::Allowlist { addresses } => {
                // User must be in the allowlist
                addresses.contains(&user)
            }
            AccessPolicy::TimeLock { locked_until} => {
                // Current time must be past the lock timestamp
                now_microseconds() >= *locked_until
            }
        }
    }

    // ============================================================================
    // Deserialization Helpers
    // ============================================================================

    /// Deserialize a vector of RegistrationInfo from BCS bytes.
    public fun regs_from_bytes(bytes: vector<u8>): vector<RegistrationInfo> {
        let stream = bcs_stream::new(bytes);
        let ret = bcs_stream::deserialize_vector(&mut stream, |s|deserialize_reg_info(s));
        // Ensure all bytes were consumed (no trailing garbage)
        assert!(!bcs_stream::has_remaining(&mut stream), error::invalid_argument(E_DESERIALIZATION_FAILED));
        ret
    }

    /// Deserialize an AccessPolicy from BCS bytes.
    public fun access_policy_from_bytes(bytes: vector<u8>): AccessPolicy {
        let stream = bcs_stream::new(bytes);
        let ret = deserialize_access_policy(&mut stream);
        // Ensure all bytes were consumed (no trailing garbage)
        assert!(!bcs_stream::has_remaining(&mut stream), error::invalid_argument(E_DESERIALIZATION_FAILED));
        ret
    }

    /// Deserialize a single RegistrationInfo from a BCS stream.
    public fun deserialize_reg_info(stream: &mut BCSStream): RegistrationInfo {
        let blob_name_suffix =  bcs_stream::deserialize_string(stream);
        let access_policy = deserialize_access_policy(stream);
        RegistrationInfo { blob_name_suffix, access_policy }
    }

    /// Deserialize an AccessPolicy from a BCS stream.
    /// The first byte indicates the variant (scheme), followed by variant-specific data.
    public fun deserialize_access_policy(stream: &mut BCSStream): AccessPolicy {
        let variant = bcs_stream::deserialize_u8(stream);
        if (variant == SCHEME_ALLOWLIST) {
            let addresses = bcs_stream::deserialize_vector(stream, |s|bcs_stream::deserialize_address(s));
            AccessPolicy::Allowlist { addresses }
        } else if (variant == SCHEME_TIMELOCK) {
            let locked_until = bcs_stream::deserialize_u64(stream);
            AccessPolicy::TimeLock { locked_until }
        } else if (variant == SCHEME_PAY_TO_DOWNLOAD) {
            let price = bcs_stream::deserialize_u64(stream);
            AccessPolicy::PayToDownload { price }
        } else {
            abort(error::invalid_argument(E_UNKNOWN_POLICY_MODE))
        }
    }

    // ============================================================================
    // Utility Functions
    // ============================================================================

    /// Create a full blob name from owner address and suffix.
    /// Format: "0x<canonical_owner_address>/<blob_name_suffix>"
    /// Example: "0x00000000000000000000000000000000000000000000000000000000000000aa/movies/star-wars.mov"
    public fun create_full_blob_name(owner_address: address, blob_name_suffix: String): String {
        let full_blob_name = string_utils::to_string_with_canonical_addresses(&owner_address);
        full_blob_name.append_utf8(b"/");
        full_blob_name.append(blob_name_suffix);
        full_blob_name
    }

    // ============================================================================
    // Tests
    // ============================================================================

    #[test(framework = @0x1, admin = @admin, alice = @0xaa, bob = @0xbb, carl = @0xcc)]
    /// Comprehensive test demonstrating all three access control modes:
    /// 1. Allowlist mode with dynamic updates
    /// 2. TimeLock mode with time progression
    /// 3. PayToDownload mode with purchase flow
    fun example_flow(framework: &signer, admin: &signer, alice: &signer, bob: &signer, carl: &signer) acquires BlobMap, ReceiptCollection {
        // ====== Test Setup ======
        // Initialize timestamp for time-based tests
        timestamp::set_time_has_started_for_testing(framework);
        // Initialize the access control module
        initialize(admin);
        
        // Setup test coins: give each user 100 APT (in octas)
        let (burn_cap, mint_cap) = aptos_coin::initialize_for_test(framework);
        let mint_amount = 100000000u64;
        coin::deposit(@0xaa, coin::mint<AptosCoin>(mint_amount, &mint_cap));
        coin::deposit(@0xbb, coin::mint<AptosCoin>(mint_amount, &mint_cap));
        coin::deposit(@0xcc, coin::mint<AptosCoin>(mint_amount, &mint_cap));
        coin::destroy_mint_cap(mint_cap);
        coin::destroy_burn_cap(burn_cap);

        // ====== Test 1: Allowlist Mode ======
        // Alice registers "star-wars.mov" with Bob (@0xbb) in the allowlist
        let star_wars_file_name = utf8(b"movies/star-wars.mov");
        let star_wars_full_name = create_full_blob_name(@0xaa, star_wars_file_name);
        
        // Before registration: Carl cannot access (blob doesn't exist yet)
        assert!(!check_permission(@0xcc, *star_wars_full_name.bytes()),
            0 /* Carl should not have access - blob not registered yet */);
        
        // Alice registers the blob with Bob in the allowlist
        register_blob(alice, RegistrationInfo {
            blob_name_suffix: star_wars_file_name,
            access_policy: AccessPolicy::Allowlist { addresses: vector[@0xbb] }
        });
        
        // Alice (owner) always has access to her own blobs
        assert!(check_permission(@0xaa, *star_wars_full_name.bytes()),
            1 /* Alice is the owner, should always have access */);
        // Bob is in the allowlist, so he has access
        assert!(check_permission(@0xbb, *star_wars_full_name.bytes()),
            2 /* Bob is in the allowlist, should have access */);
        // Carl is NOT in the allowlist
        assert!(!check_permission(@0xcc, *star_wars_full_name.bytes()),
            3 /* Carl is not in allowlist, should be denied */);
        
        // Alice updates the allowlist to include both Carl and Bob
        let new_policy = AccessPolicy::Allowlist { addresses: vector[@0xcc, @0xbb] };
        force_update_policy(alice, star_wars_file_name, bcs::to_bytes(&new_policy));
        
        // After policy update: all three should have access
        assert!(check_permission(@0xaa, *star_wars_full_name.bytes()),
            4 /* Alice is still the owner */);
        assert!(check_permission(@0xbb, *star_wars_full_name.bytes()),
            5 /* Bob is still in the updated allowlist */);
        assert!(check_permission(@0xcc, *star_wars_full_name.bytes()),
            6 /* Carl is now in the updated allowlist */);

        // ====== Test 2: TimeLock Mode ======
        // Alice registers "matrix.mov" with a 60-second time lock
        let matrix_file_name = utf8(b"movies/matrix.mov");
        let matrix_full_name = create_full_blob_name(@0xaa, matrix_file_name);
        let matrix_full_name_bytes = *matrix_full_name.bytes();
        
        // Register with time lock: locked for 60 seconds from now
        register_blob(alice, RegistrationInfo {
            blob_name_suffix: matrix_file_name,
            access_policy: AccessPolicy::TimeLock { locked_until: now_microseconds() + 60_000_000 },
        });
        
        // Before time passes: only owner has access
        assert!(check_permission(@0xaa, matrix_full_name_bytes),
            7 /* Alice is the owner, bypass time lock */);
        assert!(!check_permission(@0xbb, matrix_full_name_bytes),
            8 /* Bob cannot access - time lock not expired */);
        assert!(!check_permission(@0xcc, matrix_full_name_bytes),
            9 /* Carl cannot access - time lock not expired */);
        
        // Fast forward time by 61 seconds
        timestamp::fast_forward_seconds(61);
        
        // After time passes: everyone has access
        assert!(check_permission(@0xaa, matrix_full_name_bytes),
            10 /* Alice still has access as owner */);
        assert!(check_permission(@0xbb, matrix_full_name_bytes),
            11 /* Bob can now access - time lock expired */);
        assert!(check_permission(@0xcc, matrix_full_name_bytes),
            12 /* Carl can now access - time lock expired */);

        // ====== Test 3: PayToDownload Mode ======
        // Alice registers "titanic.mov" with a price of 10000 octas
        let titanic_file_name = utf8(b"movies/titanic.move");
        let titanic_full_name = create_full_blob_name(@0xaa, titanic_file_name);
        let price = 10000;
        
        // Before registration: no one can access
        assert!(!check_permission(@0xcc, *titanic_full_name.bytes()),
            13 /* Carl cannot access - blob not registered */);
        
        // Register with pay-to-download policy
        register_blob(alice, RegistrationInfo {
            blob_name_suffix: titanic_file_name,
            access_policy: AccessPolicy::PayToDownload { price },
        });
        
        // After registration: only owner has access (no one has paid)
        assert!(check_permission(@0xaa, *titanic_full_name.bytes()),
            14 /* Alice is the owner */);
        assert!(!check_permission(@0xbb, *titanic_full_name.bytes()),
            15 /* Bob has not purchased */);
        assert!(!check_permission(@0xcc, *titanic_full_name.bytes()),
            16 /* Carl has not purchased */);
        
        // Carl purchases access
        init_new_buyer(carl);  // Initialize Carl's receipt collection
        purchase(carl, titanic_full_name);
        
        // After purchase: Carl now has access
        assert!(check_permission(@0xcc, *titanic_full_name.bytes()),
            17 /* Carl purchased access, should be approved */);

        // Verify Carl's balance decreased by the price
        assert!(mint_amount - price == coin::balance<aptos_coin::AptosCoin>(@0xcc),
            18 /* Carl's balance should decrease by the price paid */);
        
        // Alice updates the price to half (for future purchases)
        let half_price = price / 2;
        let half_price_policy = AccessPolicy::PayToDownload { price: half_price };
        force_update_policy(alice, titanic_file_name, bcs::to_bytes(&half_price_policy));
        
        // Bob purchases at the new (lower) price
        init_new_buyer(bob);
        purchase(bob, titanic_full_name);
        
        // Verify Bob now has access
        assert!(check_permission(@0xbb, *titanic_full_name.bytes()),
            19 /* Bob purchased access at the new price */);
        // Verify Bob only paid the reduced price
        assert!(mint_amount - half_price == coin::balance<aptos_coin::AptosCoin>(@0xbb),
            20 /* Bob should have paid the new half price */);
    }
}
