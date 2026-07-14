// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Bearer capability access: one BLS12-381 public key per blob.
///
/// Owner uploads `enc_blob` for `blob_id = @<owner>/<suffix>` to some
/// off-chain object store, derives a BLS keypair
/// `(access_private_key, access_public_key)` via ACE threshold VRF over
/// `(contract_id, blob_id)`, and registers `access_public_key` on-chain here.
/// The VRF request must be signed by the owner; this module's
/// `on_ace_vrf_request` hook only approves labels in the signing account's
/// `@<owner>/...` namespace.
/// The owner shares `access_private_key` out-of-band as a single-token
/// signing capability: anyone who holds `access_private_key` can ask the ACE workers
/// to release a decryption-key share — provided they sign for this
/// dapp's origin.
///
/// Worker calls `on_ace_decryption_request_custom_flow(label, user_epk, payload)`
/// before releasing a share. Custom flow leaves the `payload` shape to
/// the contract, so this contract defines:
///
///   payload     = BCS({ claimed_origin, sig })
///   signed_msg  = BCS(SignableRequest { dst, label, user_epk, claimed_origin })
///   sig is a BLS sig over signed_msg under the registered `access_public_key`.
///
/// Access is granted iff `claimed_origin == EXPECTED_APP_ORIGIN` AND
/// `sig` verifies. Binding `user_epk` stops an eavesdropper from replaying
/// a captured signature with their own ephemeral encryption key; binding
/// `claimed_origin` mirrors what the basic flow gets for free via
/// wallet-`fullMessage` extraction — a wallet/helper holding `access_private_key` should
/// refuse to sign for an origin other than the actual requester's, so
/// a malicious dapp at `evil.com` can't get the wallet to produce a
/// signature claiming to be this dapp's origin. The explicit `dst` tag
/// prevents the same key from being reused to forge messages for other
/// schemes that happen to share `(label, user_epk, origin)`, and BCS's
/// length-prefixed encoding rules out naive-concatenation ambiguity
/// across variable-length fields.
///
/// `EXPECTED_APP_ORIGIN` is dapp-scope, not blob-scope: one deployment
/// of this contract represents one dapp at one origin, exactly as the
/// `tutorial-aptos` marketplace does. Owners don't pick the origin —
/// the dapp does, at deploy time.
///
/// Overwrite-by-same-owner = revoke + reissue: registering a new `access_public_key`
/// for the same blob invalidates the old `access_private_key`.
module admin::capability_access {
    use std::bcs;
    use std::error;
    use std::string::{Self, String};
    use aptos_std::bcs_stream;
    use aptos_std::bls12381;
    use aptos_std::string_utils;
    use aptos_std::table;
    use aptos_std::table::Table;

    /// Domain-separation tag for the BLS signed message. Bumping it
    /// invalidates every outstanding `access_private_key` even if the registered `access_public_key`
    /// is unchanged — useful for protocol-level breaking changes.
    const SIGNABLE_REQUEST_DST: vector<u8> = b"ACE_BEARER_CAPABILITY_v1";

    /// The dapp origin that ACE requests must be signed for. Must match
    /// the `application` value that any wallet/helper holding `access_private_key`
    /// attests to before signing. Cribbed by `tools/gen-fixture.ts` and
    /// by the TS-side reader scripts.
    const EXPECTED_APP_ORIGIN: vector<u8> = b"https://example.com";

    /// Module not initialized at `@admin` yet.
    const E_NOT_INITIALIZED: u64 = 1;
    /// Caller is not the module's deployer (initialization only).
    const E_NOT_ADMIN: u64 = 2;
    /// Supplied bytes are not a valid BLS12-381 G1 public key.
    const E_INVALID_APK: u64 = 3;

    /// What `access_private_key` actually signs. BCS-encoded by the reader, then
    /// `bls12381::verify_normal_signature`'d by the hook. BCS for a
    /// struct = concat of its field encodings; each `vector<u8>` is
    /// ULEB128(len)||bytes.
    struct SignableRequest has copy, drop {
        dst: vector<u8>,
        label: vector<u8>,
        user_epk: vector<u8>,
        origin: vector<u8>,
    }

    /// Singleton at `@admin`. `entries[blob_id] = access_public_key_bytes` (48-byte
    /// compressed BLS12-381 G1 element). `blob_id` is the canonical
    /// `@<owner>/<suffix>` UTF-8 string.
    struct Registry has key {
        entries: Table<vector<u8>, vector<u8>>,
    }

    /// Create the singleton registry. Idempotent.
    public entry fun init(admin: &signer) {
        assert!(admin.address_of() == @admin, error::permission_denied(E_NOT_ADMIN));
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
        access_public_key: vector<u8>,
    ) {
        assert!(exists<Registry>(@admin), error::not_found(E_NOT_INITIALIZED));
        // Fail closed on garbage pubkeys at write-time rather than later
        // at every verify call.
        let pk_opt = bls12381::public_key_from_bytes(access_public_key);
        assert!(pk_opt.is_some(), error::invalid_argument(E_INVALID_APK));

        let blob_id = create_full_blob_name(owner.address_of(), blob_name_suffix);
        let registry = &mut Registry[@admin];
        registry.entries.upsert(*blob_id.bytes(), access_public_key);
    }

    #[view]
    /// ACE custom-flow hook. Returns true iff (a) the reader's claimed
    /// origin matches this dapp's `EXPECTED_APP_ORIGIN` and (b) `sig`
    /// is a valid BLS12-381 signature over
    /// `BCS(SignableRequest { dst, label, user_epk, claimed_origin })`
    /// under the registered `access_public_key`. The signature suite is the IETF
    /// min-pubkey-size variant with DST
    /// `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` (matches Aptos's
    /// native `aptos_std::bls12381::verify_normal_signature`).
    public fun on_ace_decryption_request_custom_flow(
        label: vector<u8>,
        user_epk: vector<u8>,
        payload: vector<u8>,
    ): bool {
        if (!exists<Registry>(@admin)) return false;
        let registry = &Registry[@admin];
        if (!registry.entries.contains(label)) return false;
        let access_public_key_bytes = *registry.entries.borrow(label);

        let stream = bcs_stream::new(payload);
        let claimed_origin = bcs_stream::deserialize_vector(&mut stream, |s| bcs_stream::deserialize_u8(s));
        let sig_bytes      = bcs_stream::deserialize_vector(&mut stream, |s| bcs_stream::deserialize_u8(s));
        if (bcs_stream::has_remaining(&mut stream)) return false;
        if (claimed_origin != EXPECTED_APP_ORIGIN) return false;

        let pk_opt = bls12381::public_key_from_bytes(access_public_key_bytes);
        if (!pk_opt.is_some()) return false; // unreachable: register() validates
        let pk = pk_opt.extract();
        let sig = bls12381::signature_from_bytes(sig_bytes);
        let msg = bcs::to_bytes(&SignableRequest {
            dst: SIGNABLE_REQUEST_DST,
            label,
            user_epk,
            origin: claimed_origin,
        });
        bls12381::verify_normal_signature(&sig, &pk, msg)
    }

    #[view]
    /// ACE threshold-VRF hook. Alice derives bearer key material from the full
    /// blob id (`@<alice>/<suffix>`), and workers pass the Aptos account that
    /// signed the VRF request. Requiring a strict `@<account>/...` label prefix
    /// means only the owner can derive bearer keys for her namespace.
    public fun on_ace_vrf_request(label: vector<u8>, account: address, origin: String): bool {
        if (origin.bytes() != &EXPECTED_APP_ORIGIN) return false;
        let owner_prefix = create_full_blob_name(account, string::utf8(b""));
        bytes_strictly_starts_with(&label, owner_prefix.bytes())
    }

    /// Canonical blob_id constructor — `@<canonical-64-hex-owner>/<suffix>`.
    /// Matches the convention ACE examples use for
    /// `@<owner>/<path>`-style object names.
    public fun create_full_blob_name(owner_address: address, blob_name_suffix: String): String {
        let full_blob_name = string_utils::to_string_with_canonical_addresses(&owner_address);
        full_blob_name.append_utf8(b"/");
        full_blob_name.append(blob_name_suffix);
        full_blob_name
    }

    fun bytes_strictly_starts_with(bytes: &vector<u8>, prefix: &vector<u8>): bool {
        let prefix_len = prefix.length();
        let bytes_len = bytes.length();
        if (bytes_len <= prefix_len) return false;

        let i = 0;
        while (i < prefix_len) {
            if (*bytes.borrow(i) != *prefix.borrow(i)) return false;
            i = i + 1;
        };
        true
    }

    // ─────────────────── tests ───────────────────

    #[test_only] use aptos_framework::account;

    #[test]
    fun vrf_request_owner_blob_allowed() {
        let label = create_full_blob_name(@0xcafe, string::utf8(b"song.mp3"));
        assert!(
            on_ace_vrf_request(
                *label.bytes(),
                @0xcafe,
                string::utf8(b"https://example.com"),
            ),
            120,
        );
    }

    #[test]
    fun vrf_request_non_owner_rejected() {
        let label = create_full_blob_name(@0xcafe, string::utf8(b"song.mp3"));
        assert!(
            !on_ace_vrf_request(
                *label.bytes(),
                @0xdead,
                string::utf8(b"https://example.com"),
            ),
            121,
        );
    }

    #[test]
    fun vrf_request_wrong_origin_rejected() {
        let label = create_full_blob_name(@0xcafe, string::utf8(b"song.mp3"));
        assert!(
            !on_ace_vrf_request(
                *label.bytes(),
                @0xcafe,
                string::utf8(b"https://attacker.example"),
            ),
            122,
        );
    }

    #[test]
    fun vrf_request_requires_suffix_after_owner_prefix() {
        let label = create_full_blob_name(@0xcafe, string::utf8(b""));
        assert!(
            !on_ace_vrf_request(
                *label.bytes(),
                @0xcafe,
                string::utf8(b"https://example.com"),
            ),
            123,
        );
    }

    // Fixture generated by tools/gen-fixture.ts (also pasted in README):
    //   sk     = 0x0102…1f20
    //   owner  = @0xcafe   suffix = "song.mp3"
    //   origin = "https://example.com"   user_epk = 0xdeadbeefcafebabe
    #[test(admin = @admin)]
    fun happy_path_verifies(admin: &signer) {
        account::create_account_for_test(@admin);
        init(admin);
        let access_public_key = x"96a20bb9485ff6d8950955a629e8043a43775968ac133eb7b19c5f0389a2253676abdd6c86c7b68d38a1b7f6af8650e7";
        register(admin, string::utf8(b"song.mp3"), access_public_key);

        let label   = x"40303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030636166652f736f6e672e6d7033";
        let user_epk  = x"deadbeefcafebabe";
        let payload = x"1368747470733a2f2f6578616d706c652e636f6d60948bd4729d5f3755b455f52ae82d7a6ce5e8b363fdb831ee9a80e26f152b5225a2654ceddbc33e7375c35a0bac9125e215038ba9d9a7741297f45df575780253f0e6b9b93fe7a49e1ecf8893cf9dceb1f6477440ff6ea71fce776dffc9169ff7";
        assert!(on_ace_decryption_request_custom_flow(label, user_epk, payload), 100);
    }

    // Tamper with one byte of user_epk — sig should no longer verify.
    #[test(admin = @admin)]
    fun mismatched_user_epk_rejected(admin: &signer) {
        account::create_account_for_test(@admin);
        init(admin);
        let access_public_key = x"96a20bb9485ff6d8950955a629e8043a43775968ac133eb7b19c5f0389a2253676abdd6c86c7b68d38a1b7f6af8650e7";
        register(admin, string::utf8(b"song.mp3"), access_public_key);

        let label    = x"40303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030636166652f736f6e672e6d7033";
        let bad_pk   = x"deadbeefcafebabf";  // last byte flipped
        let payload  = x"1368747470733a2f2f6578616d706c652e636f6d60948bd4729d5f3755b455f52ae82d7a6ce5e8b363fdb831ee9a80e26f152b5225a2654ceddbc33e7375c35a0bac9125e215038ba9d9a7741297f45df575780253f0e6b9b93fe7a49e1ecf8893cf9dceb1f6477440ff6ea71fce776dffc9169ff7";
        assert!(!on_ace_decryption_request_custom_flow(label, bad_pk, payload), 101);
    }

    // Claimed origin doesn't match this dapp's `EXPECTED_APP_ORIGIN`.
    // The sig in the payload is even validly signed over the wrong
    // origin (a malicious wallet that ignored the application context)
    // — the contract still rejects on the `claimed_origin` check before
    // even getting to the sig verify.
    #[test(admin = @admin)]
    fun wrong_origin_rejected(admin: &signer) {
        account::create_account_for_test(@admin);
        init(admin);
        let access_public_key = x"96a20bb9485ff6d8950955a629e8043a43775968ac133eb7b19c5f0389a2253676abdd6c86c7b68d38a1b7f6af8650e7";
        register(admin, string::utf8(b"song.mp3"), access_public_key);

        let label   = x"40303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030636166652f736f6e672e6d7033";
        let user_epk  = x"deadbeefcafebabe";
        // payload claims (and self-consistently signs over) attacker.example.
        let payload = x"1868747470733a2f2f61747461636b65722e6578616d706c656085dc6c31b6f4889462a9464e99f1fdd9f88e103f4e459848aebf8f70a948853565f3f46b262e6bccc4993943a0dceb6a03a9cd2eee63b5d55a7d27179003e31a781a08a1afdcc0025e48f99d839d5487ccc02f91349205701c790d4768284a60";
        assert!(!on_ace_decryption_request_custom_flow(label, user_epk, payload), 103);
    }

    // Unregistered blob_id → hook returns false (no abort).
    #[test(admin = @admin)]
    fun unknown_blob_returns_false(admin: &signer) {
        account::create_account_for_test(@admin);
        init(admin);
        let label   = b"@deadbeef/never-registered";
        let user_epk  = x"deadbeefcafebabe";
        let payload = x"1368747470733a2f2f6578616d706c652e636f6d60948bd4729d5f3755b455f52ae82d7a6ce5e8b363fdb831ee9a80e26f152b5225a2654ceddbc33e7375c35a0bac9125e215038ba9d9a7741297f45df575780253f0e6b9b93fe7a49e1ecf8893cf9dceb1f6477440ff6ea71fce776dffc9169ff7";
        assert!(!on_ace_decryption_request_custom_flow(label, user_epk, payload), 102);
    }

    // Garbage access_public_key bytes → register aborts; nothing is stored.
    #[test(admin = @admin)]
    #[expected_failure(abort_code = 0x10003, location = Self)]
    fun register_rejects_garbage_access_public_key(admin: &signer) {
        account::create_account_for_test(@admin);
        init(admin);
        let garbage = x"00112233";
        register(admin, string::utf8(b"song.mp3"), garbage);
    }

    // Re-registering with a new access_public_key under the same suffix overwrites
    // (= revokes the old access_private_key). Sig from the old access_public_key should now reject.
    #[test(admin = @admin)]
    fun overwrite_revokes_previous_access_public_key(admin: &signer) {
        account::create_account_for_test(@admin);
        init(admin);

        let access_public_key_v1 = x"96a20bb9485ff6d8950955a629e8043a43775968ac133eb7b19c5f0389a2253676abdd6c86c7b68d38a1b7f6af8650e7";
        register(admin, string::utf8(b"song.mp3"), access_public_key_v1);

        let label   = x"40303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030636166652f736f6e672e6d7033";
        let user_epk  = x"deadbeefcafebabe";
        let payload = x"1368747470733a2f2f6578616d706c652e636f6d60948bd4729d5f3755b455f52ae82d7a6ce5e8b363fdb831ee9a80e26f152b5225a2654ceddbc33e7375c35a0bac9125e215038ba9d9a7741297f45df575780253f0e6b9b93fe7a49e1ecf8893cf9dceb1f6477440ff6ea71fce776dffc9169ff7";
        assert!(on_ace_decryption_request_custom_flow(label, user_epk, payload), 110);

        // Overwrite with a second well-formed access_public_key (any valid G1 pk that
        // differs from access_public_key_v1 works).
        let access_public_key_v2 = x"808864c91ae7a9998b3f5ee71f447840864e56d79838e4785ff5126c51480198df3d972e1e0348c6da80d396983e42d7";
        register(admin, string::utf8(b"song.mp3"), access_public_key_v2);

        assert!(!on_ace_decryption_request_custom_flow(label, user_epk, payload), 111);
    }
}
