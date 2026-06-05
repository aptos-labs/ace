// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Shelby pre-signed access: one BLS12-381 bearer pubkey per blob.
///
/// Owner uploads `enc_blob` for `blob_id = @<owner>/<suffix>` to Shelby,
/// derives a deterministic BLS keypair `(ask, apk)` from `(owner, blob_id)`
/// via ACE's threshold VRF, and registers `apk` on-chain here. The owner
/// shares `ask` out-of-band as a single-token access grant ("pre-signed
/// URL" semantics): anyone who holds `ask` can sign a decryption-key-share
/// request and the ACE workers will accept it.
///
/// Worker calls `on_ace_decryption_request_custom_flow(label, enc_pk, payload)`
/// before releasing a share. Access is granted iff `payload` is a valid BLS
/// signature over `BCS(SignableRequest { dst, label, enc_pk })` under the
/// bearer pubkey previously registered for `label`. Binding `enc_pk` into
/// the signed message stops an eavesdropper from replaying a captured
/// signature with their own ephemeral encryption key; the explicit `dst`
/// tag prevents the same key from being reused to forge messages for
/// other schemes that happen to share `(label, enc_pk)`; and BCS's
/// length-prefixed encoding rules out naive-concatenation ambiguity
/// across variable-length fields.
///
/// Overwrite-by-same-owner = revoke + reissue: registering a new `apk` for
/// the same blob invalidates the old `ask`.
module admin::presigned_access {
    use std::bcs;
    use std::error;
    use std::option;
    use std::signer;
    use std::string::{Self, String};
    use aptos_std::bls12381;
    use aptos_std::string_utils;
    use aptos_std::table::{Self, Table};

    /// Domain-separation tag for the BLS signed message. Bumping it
    /// invalidates every outstanding `ask` even if the registered `apk`
    /// is unchanged — useful for protocol-level breaking changes.
    const SIGNABLE_REQUEST_DST: vector<u8> = b"ACE_PRESIGNED_ACCESS_v1";

    /// What `ask` actually signs. BCS-encoded by the reader, fed to
    /// `bls12381::verify_normal_signature` by `on_ace_decryption_request_custom_flow`.
    /// BCS for a struct = concat of its field encodings; each
    /// `vector<u8>` is ULEB128(len)||bytes, so the layout is
    /// `ULEB(|dst|)|dst | ULEB(|label|)|label | ULEB(|enc_pk|)|enc_pk`.
    struct SignableRequest has copy, drop {
        dst: vector<u8>,
        label: vector<u8>,
        enc_pk: vector<u8>,
    }

    /// Module not initialized at `@admin` yet.
    const E_NOT_INITIALIZED: u64 = 1;
    /// Caller is not the module's deployer (initialization only).
    const E_NOT_ADMIN: u64 = 2;
    /// Supplied bytes are not a valid BLS12-381 G1 public key.
    const E_INVALID_APK: u64 = 3;

    /// Singleton at `@admin`. `entries[blob_id] = apk_bytes` (48-byte
    /// compressed BLS12-381 G1 element). `blob_id` is the canonical
    /// `@<owner>/<suffix>` UTF-8 string.
    struct Registry has key {
        entries: Table<vector<u8>, vector<u8>>,
    }

    /// Create the singleton registry. Idempotent.
    public entry fun init(admin: &signer) {
        assert!(signer::address_of(admin) == @admin, error::permission_denied(E_NOT_ADMIN));
        if (!exists<Registry>(@admin)) {
            move_to(admin, Registry { entries: table::new() });
        };
    }

    /// Register (or overwrite) the bearer pubkey for `@<owner>/<suffix>`.
    /// `owner` here is `signer`, so the blob_id key is self-namespaced to
    /// the caller's address: two distinct accounts can never collide on
    /// the same key, and the same account can overwrite freely (= revoke
    /// + reissue).
    public entry fun register(
        owner: &signer,
        blob_name_suffix: String,
        apk: vector<u8>,
    ) acquires Registry {
        assert!(exists<Registry>(@admin), error::not_found(E_NOT_INITIALIZED));
        // Fail closed on garbage pubkeys at write-time rather than later
        // at every verify call.
        let pk_opt = bls12381::public_key_from_bytes(apk);
        assert!(option::is_some(&pk_opt), error::invalid_argument(E_INVALID_APK));

        let blob_id = create_full_blob_name(signer::address_of(owner), blob_name_suffix);
        let registry = borrow_global_mut<Registry>(@admin);
        registry.entries.upsert(*blob_id.bytes(), apk);
    }

    #[view]
    /// ACE custom-flow hook. Returns true iff `payload` is a valid BLS12-381
    /// signature over `BCS(SignableRequest { dst, label, enc_pk })` under
    /// the bearer pubkey previously registered for `label`. The signature
    /// suite is the IETF min-pubkey-size variant with DST
    /// `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` (matches Aptos's native
    /// `aptos_std::bls12381::verify_normal_signature`).
    public fun on_ace_decryption_request_custom_flow(
        label: vector<u8>,
        enc_pk: vector<u8>,
        payload: vector<u8>,
    ): bool acquires Registry {
        if (!exists<Registry>(@admin)) return false;
        let registry = borrow_global<Registry>(@admin);
        if (!registry.entries.contains(label)) return false;
        let apk_bytes = *registry.entries.borrow(label);
        let pk_opt = bls12381::public_key_from_bytes(apk_bytes);
        if (!option::is_some(&pk_opt)) return false; // unreachable: register() validates
        let pk = option::extract(&mut pk_opt);
        let sig = bls12381::signature_from_bytes(payload);
        let msg = bcs::to_bytes(&SignableRequest {
            dst: SIGNABLE_REQUEST_DST,
            label,
            enc_pk,
        });
        bls12381::verify_normal_signature(&sig, &pk, msg)
    }

    /// Canonical blob_id constructor. Matches Shelby's convention used by
    /// `shelby-explorer-acl-aptos`: `@<canonical-64-hex-owner>/<suffix>`.
    public fun create_full_blob_name(owner_address: address, blob_name_suffix: String): String {
        let full_blob_name = string_utils::to_string_with_canonical_addresses(&owner_address);
        full_blob_name.append_utf8(b"/");
        full_blob_name.append(blob_name_suffix);
        full_blob_name
    }

    // ─────────────────── tests ───────────────────

    #[test_only] use aptos_framework::account;

    // Fixture generated by tools/gen-fixture.ts (also pasted in README):
    // sk = 0x0102…1f20; owner = @0xcafe; suffix = "song.mp3"; enc_pk = 0xdeadbeefcafebabe.
    #[test(admin = @admin)]
    fun happy_path_verifies(admin: &signer) acquires Registry {
        account::create_account_for_test(@admin);
        init(admin);
        let apk = x"96a20bb9485ff6d8950955a629e8043a43775968ac133eb7b19c5f0389a2253676abdd6c86c7b68d38a1b7f6af8650e7";
        register(admin, string::utf8(b"song.mp3"), apk);

        let label   = x"40303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030636166652f736f6e672e6d7033";
        let enc_pk  = x"deadbeefcafebabe";
        let sig     = x"ad2ba97f1d4bdbc495b7bd3ca251525c00cb7acd8e2372e5659950459bc4369ee48e4ee3e6eedc0c7dc125a26a3f05851440a33501bff570077096f51e31cc4d55f630c337e7547e04ddf1a78c73f488afb315e8ebc592ebcd26e460a452b6af";
        assert!(on_ace_decryption_request_custom_flow(label, enc_pk, sig), 100);
    }

    // Tamper with one byte of enc_pk — sig should no longer verify.
    #[test(admin = @admin)]
    fun mismatched_enc_pk_rejected(admin: &signer) acquires Registry {
        account::create_account_for_test(@admin);
        init(admin);
        let apk = x"96a20bb9485ff6d8950955a629e8043a43775968ac133eb7b19c5f0389a2253676abdd6c86c7b68d38a1b7f6af8650e7";
        register(admin, string::utf8(b"song.mp3"), apk);

        let label    = x"40303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030636166652f736f6e672e6d7033";
        let bad_pk   = x"deadbeefcafebabf";  // last byte flipped
        let sig      = x"ad2ba97f1d4bdbc495b7bd3ca251525c00cb7acd8e2372e5659950459bc4369ee48e4ee3e6eedc0c7dc125a26a3f05851440a33501bff570077096f51e31cc4d55f630c337e7547e04ddf1a78c73f488afb315e8ebc592ebcd26e460a452b6af";
        assert!(!on_ace_decryption_request_custom_flow(label, bad_pk, sig), 101);
    }

    // Unregistered blob_id → hook returns false (no abort).
    #[test(admin = @admin)]
    fun unknown_blob_returns_false(admin: &signer) acquires Registry {
        account::create_account_for_test(@admin);
        init(admin);
        let label  = b"@deadbeef/never-registered";
        let enc_pk = x"deadbeefcafebabe";
        let sig    = x"ad2ba97f1d4bdbc495b7bd3ca251525c00cb7acd8e2372e5659950459bc4369ee48e4ee3e6eedc0c7dc125a26a3f05851440a33501bff570077096f51e31cc4d55f630c337e7547e04ddf1a78c73f488afb315e8ebc592ebcd26e460a452b6af";
        assert!(!on_ace_decryption_request_custom_flow(label, enc_pk, sig), 102);
    }

    // Garbage apk bytes → register aborts; nothing is stored.
    #[test(admin = @admin)]
    #[expected_failure(abort_code = 0x10003, location = Self)]
    fun register_rejects_garbage_apk(admin: &signer) acquires Registry {
        account::create_account_for_test(@admin);
        init(admin);
        let garbage = x"00112233";
        register(admin, string::utf8(b"song.mp3"), garbage);
    }

    // Regression: BCS length-prefixing rules out the naive-`a||b`
    // ambiguity. A sig over (label="ab", enc_pk="cDEF") must NOT
    // verify when re-interpreted as (label="abc", enc_pk="DEF") even
    // though the naive concatenations are byte-equal ("abcDEF"). Both
    // labels are registered under the same apk so the apk lookup
    // succeeds in both cases; only the BCS encoding stops the replay.
    #[test(admin = @admin)]
    fun bcs_prevents_concat_ambiguity(admin: &signer) acquires Registry {
        account::create_account_for_test(@admin);
        init(admin);
        let apk = x"96a20bb9485ff6d8950955a629e8043a43775968ac133eb7b19c5f0389a2253676abdd6c86c7b68d38a1b7f6af8650e7";
        // Register the same apk under raw labels "ab" and "abc" via the
        // public Table directly — we bypass `register`'s blob_name
        // construction since these labels aren't `@<addr>/<suffix>`-shaped.
        let registry = borrow_global_mut<Registry>(@admin);
        registry.entries.upsert(b"ab", apk);
        registry.entries.upsert(b"abc", apk);

        let label_a = b"ab";
        let enc_a   = b"cDEF";
        let label_b = b"abc";
        let enc_b   = b"DEF";
        let sig = x"a3baa0ff575102ae1c5eeed11b72aecd7474ac10e84cefc6ad498f9071ff39c78b046b11ea48ac38767f08e3c1324d890d95514a67dd5923184c5fcd3335d9b8da0539bf2ec5499f664eddaf3e841242642cd82317ee4e40680489dc8f1cb7d1";

        assert!(on_ace_decryption_request_custom_flow(label_a, enc_a, sig), 120);
        assert!(!on_ace_decryption_request_custom_flow(label_b, enc_b, sig), 121);
    }

    // Re-registering with a new apk under the same suffix overwrites
    // (= revokes the old ask). Sig from the old apk should now reject.
    #[test(admin = @admin)]
    fun overwrite_revokes_previous_apk(admin: &signer) acquires Registry {
        account::create_account_for_test(@admin);
        init(admin);

        // First registration uses the spike apk.
        let apk_v1 = x"96a20bb9485ff6d8950955a629e8043a43775968ac133eb7b19c5f0389a2253676abdd6c86c7b68d38a1b7f6af8650e7";
        register(admin, string::utf8(b"song.mp3"), apk_v1);

        // Sanity: sig under apk_v1 verifies pre-overwrite.
        let label  = x"40303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030636166652f736f6e672e6d7033";
        let enc_pk = x"deadbeefcafebabe";
        let sig_v1 = x"ad2ba97f1d4bdbc495b7bd3ca251525c00cb7acd8e2372e5659950459bc4369ee48e4ee3e6eedc0c7dc125a26a3f05851440a33501bff570077096f51e31cc4d55f630c337e7547e04ddf1a78c73f488afb315e8ebc592ebcd26e460a452b6af";
        assert!(on_ace_decryption_request_custom_flow(label, enc_pk, sig_v1), 110);

        // Overwrite with a second well-formed apk (cribbed from aptos-stdlib
        // bls12381 tests — any valid G1 pk that differs from `apk_v1` works).
        let apk_v2 = x"808864c91ae7a9998b3f5ee71f447840864e56d79838e4785ff5126c51480198df3d972e1e0348c6da80d396983e42d7";
        register(admin, string::utf8(b"song.mp3"), apk_v2);

        // The old sig must no longer verify.
        assert!(!on_ace_decryption_request_custom_flow(label, enc_pk, sig_v1), 111);
    }
}
