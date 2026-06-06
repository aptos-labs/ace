// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Shelby pre-signed access: one BLS12-381 bearer pubkey per blob.
///
/// Owner uploads `enc_blob` for `blob_id = @<owner>/<suffix>` to Shelby,
/// derives a deterministic BLS keypair `(ask, apk)` from `(owner, blob_id)`
/// via ACE's threshold VRF, and registers `apk` on-chain here. The owner
/// shares `ask` out-of-band as a single-token access grant ("pre-signed
/// URL" semantics): anyone who holds `ask` can ask the ACE workers to
/// release a decryption-key share — provided they sign for this dapp's
/// origin.
///
/// Worker calls `on_ace_decryption_request_custom_flow(label, user_epk, payload)`
/// before releasing a share. Custom flow leaves the `payload` shape to
/// the contract, so this contract defines:
///
///   payload     = BCS({ claimed_origin, sig })
///   signed_msg  = BCS(SignableRequest { dst, label, user_epk, claimed_origin })
///   sig is a BLS sig over signed_msg under the registered `apk`.
///
/// Access is granted iff `claimed_origin == EXPECTED_APP_ORIGIN` AND
/// `sig` verifies. Binding `user_epk` stops an eavesdropper from replaying
/// a captured signature with their own ephemeral encryption key; binding
/// `claimed_origin` mirrors what the basic flow gets for free via
/// wallet-`fullMessage` extraction — a wallet/helper holding `ask` should
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
/// Overwrite-by-same-owner = revoke + reissue: registering a new `apk`
/// for the same blob invalidates the old `ask`.
module admin::presigned_access {
    use std::bcs;
    use std::error;
    use std::option;
    use std::signer;
    use std::string::{Self, String};
    use aptos_std::bcs_stream;
    use aptos_std::bls12381;
    use aptos_std::string_utils;
    use aptos_std::table::{Self, Table};

    /// Domain-separation tag for the BLS signed message. Bumping it
    /// invalidates every outstanding `ask` even if the registered `apk`
    /// is unchanged — useful for protocol-level breaking changes.
    const SIGNABLE_REQUEST_DST: vector<u8> = b"ACE_PRESIGNED_ACCESS_v2";

    /// The dapp origin that ACE requests must be signed for. Must match
    /// the `application` value that any wallet/helper holding `ask`
    /// attests to before signing. Cribbed by `tools/gen-fixture.ts` and
    /// by the TS-side reader scripts.
    const EXPECTED_APP_ORIGIN: vector<u8> = b"https://shelby.example";

    /// Module not initialized at `@admin` yet.
    const E_NOT_INITIALIZED: u64 = 1;
    /// Caller is not the module's deployer (initialization only).
    const E_NOT_ADMIN: u64 = 2;
    /// Supplied bytes are not a valid BLS12-381 G1 public key.
    const E_INVALID_APK: u64 = 3;

    /// What `ask` actually signs. BCS-encoded by the reader, then
    /// `bls12381::verify_normal_signature`'d by the hook. BCS for a
    /// struct = concat of its field encodings; each `vector<u8>` is
    /// ULEB128(len)||bytes.
    struct SignableRequest has copy, drop {
        dst: vector<u8>,
        label: vector<u8>,
        user_epk: vector<u8>,
        origin: vector<u8>,
    }

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
    /// ACE custom-flow hook. Returns true iff (a) the reader's claimed
    /// origin matches this dapp's `EXPECTED_APP_ORIGIN` and (b) `sig`
    /// is a valid BLS12-381 signature over
    /// `BCS(SignableRequest { dst, label, user_epk, claimed_origin })`
    /// under the registered `apk`. The signature suite is the IETF
    /// min-pubkey-size variant with DST
    /// `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` (matches Aptos's
    /// native `aptos_std::bls12381::verify_normal_signature`).
    public fun on_ace_decryption_request_custom_flow(
        label: vector<u8>,
        user_epk: vector<u8>,
        payload: vector<u8>,
    ): bool acquires Registry {
        if (!exists<Registry>(@admin)) return false;
        let registry = borrow_global<Registry>(@admin);
        if (!registry.entries.contains(label)) return false;
        let apk_bytes = *registry.entries.borrow(label);

        let stream = bcs_stream::new(payload);
        let claimed_origin = bcs_stream::deserialize_vector(&mut stream, |s| bcs_stream::deserialize_u8(s));
        let sig_bytes      = bcs_stream::deserialize_vector(&mut stream, |s| bcs_stream::deserialize_u8(s));
        if (bcs_stream::has_remaining(&mut stream)) return false;
        if (claimed_origin != EXPECTED_APP_ORIGIN) return false;

        let pk_opt = bls12381::public_key_from_bytes(apk_bytes);
        if (!option::is_some(&pk_opt)) return false; // unreachable: register() validates
        let pk = option::extract(&mut pk_opt);
        let sig = bls12381::signature_from_bytes(sig_bytes);
        let msg = bcs::to_bytes(&SignableRequest {
            dst: SIGNABLE_REQUEST_DST,
            label,
            user_epk,
            origin: claimed_origin,
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
    //   sk     = 0x0102…1f20
    //   owner  = @0xcafe   suffix = "song.mp3"
    //   origin = "https://shelby.example"   user_epk = 0xdeadbeefcafebabe
    #[test(admin = @admin)]
    fun happy_path_verifies(admin: &signer) acquires Registry {
        account::create_account_for_test(@admin);
        init(admin);
        let apk = x"96a20bb9485ff6d8950955a629e8043a43775968ac133eb7b19c5f0389a2253676abdd6c86c7b68d38a1b7f6af8650e7";
        register(admin, string::utf8(b"song.mp3"), apk);

        let label   = x"40303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030636166652f736f6e672e6d7033";
        let user_epk  = x"deadbeefcafebabe";
        let payload = x"1668747470733a2f2f7368656c62792e6578616d706c6560b886d3be1b43e6edc06146346e0a55291e27f2cbf3dcd24688252f314b201e7393b0f4d15ff62412549ed2b4fd0e2a9c134e605444970e17ac079d526c650c512a52898421b7930e6bc1b6eef065ced6301b8b183c2d48f85de3e34d662ff4c6";
        assert!(on_ace_decryption_request_custom_flow(label, user_epk, payload), 100);
    }

    // Tamper with one byte of user_epk — sig should no longer verify.
    #[test(admin = @admin)]
    fun mismatched_user_epk_rejected(admin: &signer) acquires Registry {
        account::create_account_for_test(@admin);
        init(admin);
        let apk = x"96a20bb9485ff6d8950955a629e8043a43775968ac133eb7b19c5f0389a2253676abdd6c86c7b68d38a1b7f6af8650e7";
        register(admin, string::utf8(b"song.mp3"), apk);

        let label    = x"40303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030636166652f736f6e672e6d7033";
        let bad_pk   = x"deadbeefcafebabf";  // last byte flipped
        let payload  = x"1668747470733a2f2f7368656c62792e6578616d706c6560b886d3be1b43e6edc06146346e0a55291e27f2cbf3dcd24688252f314b201e7393b0f4d15ff62412549ed2b4fd0e2a9c134e605444970e17ac079d526c650c512a52898421b7930e6bc1b6eef065ced6301b8b183c2d48f85de3e34d662ff4c6";
        assert!(!on_ace_decryption_request_custom_flow(label, bad_pk, payload), 101);
    }

    // Claimed origin doesn't match this dapp's `EXPECTED_APP_ORIGIN`.
    // The sig in the payload is even validly signed over the wrong
    // origin (a malicious wallet that ignored the application context)
    // — the contract still rejects on the `claimed_origin` check before
    // even getting to the sig verify.
    #[test(admin = @admin)]
    fun wrong_origin_rejected(admin: &signer) acquires Registry {
        account::create_account_for_test(@admin);
        init(admin);
        let apk = x"96a20bb9485ff6d8950955a629e8043a43775968ac133eb7b19c5f0389a2253676abdd6c86c7b68d38a1b7f6af8650e7";
        register(admin, string::utf8(b"song.mp3"), apk);

        let label   = x"40303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030636166652f736f6e672e6d7033";
        let user_epk  = x"deadbeefcafebabe";
        // payload claims (and self-consistently signs over) attacker.example.
        let payload = x"1868747470733a2f2f61747461636b65722e6578616d706c65608063bb21c4552acba704cce4841b2a67fe74871d41f79430fe5f35431d47b4748538d3129954827b70562b69d0d9730b0fac488ef08371db611c27bc9915b15aa72c2848a251d8d9d3efa0a0bc68d92597cc3e0ded8644bae3253d7f849995d3";
        assert!(!on_ace_decryption_request_custom_flow(label, user_epk, payload), 103);
    }

    // Unregistered blob_id → hook returns false (no abort).
    #[test(admin = @admin)]
    fun unknown_blob_returns_false(admin: &signer) acquires Registry {
        account::create_account_for_test(@admin);
        init(admin);
        let label   = b"@deadbeef/never-registered";
        let user_epk  = x"deadbeefcafebabe";
        let payload = x"1668747470733a2f2f7368656c62792e6578616d706c6560b886d3be1b43e6edc06146346e0a55291e27f2cbf3dcd24688252f314b201e7393b0f4d15ff62412549ed2b4fd0e2a9c134e605444970e17ac079d526c650c512a52898421b7930e6bc1b6eef065ced6301b8b183c2d48f85de3e34d662ff4c6";
        assert!(!on_ace_decryption_request_custom_flow(label, user_epk, payload), 102);
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

    // Re-registering with a new apk under the same suffix overwrites
    // (= revokes the old ask). Sig from the old apk should now reject.
    #[test(admin = @admin)]
    fun overwrite_revokes_previous_apk(admin: &signer) acquires Registry {
        account::create_account_for_test(@admin);
        init(admin);

        let apk_v1 = x"96a20bb9485ff6d8950955a629e8043a43775968ac133eb7b19c5f0389a2253676abdd6c86c7b68d38a1b7f6af8650e7";
        register(admin, string::utf8(b"song.mp3"), apk_v1);

        let label   = x"40303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030303030636166652f736f6e672e6d7033";
        let user_epk  = x"deadbeefcafebabe";
        let payload = x"1668747470733a2f2f7368656c62792e6578616d706c6560b886d3be1b43e6edc06146346e0a55291e27f2cbf3dcd24688252f314b201e7393b0f4d15ff62412549ed2b4fd0e2a9c134e605444970e17ac079d526c650c512a52898421b7930e6bc1b6eef065ced6301b8b183c2d48f85de3e34d662ff4c6";
        assert!(on_ace_decryption_request_custom_flow(label, user_epk, payload), 110);

        // Overwrite with a second well-formed apk (any valid G1 pk that
        // differs from apk_v1 works).
        let apk_v2 = x"808864c91ae7a9998b3f5ee71f447840864e56d79838e4785ff5126c51480198df3d972e1e0348c6da80d396983e42d7";
        register(admin, string::utf8(b"song.mp3"), apk_v2);

        assert!(!on_ace_decryption_request_custom_flow(label, user_epk, payload), 111);
    }
}
