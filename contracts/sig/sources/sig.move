// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Scheme-dispatching signature types for node-to-node ACE protocol messages.
module ace::sig {
    use aptos_std::bcs_stream;
    use aptos_std::bcs_stream::BCSStream;
    use ace::sig_ed25519;

    const E_UNSUPPORTED_SCHEME: u64 = 1;
    const E_TRAILING_BYTES: u64 = 2;
    const E_SCHEME_MISMATCH: u64 = 3;

    const SCHEME_ED25519: u8 = 0;

    enum PublicKey has copy, drop, store {
        Ed25519(sig_ed25519::PublicKey),
    }

    enum Signature has copy, drop, store {
        Ed25519(sig_ed25519::Signature),
    }

    public fun scheme_ed25519(): u8 {
        SCHEME_ED25519
    }

    public fun deserialize_public_key(stream: &mut BCSStream): PublicKey {
        let scheme = bcs_stream::deserialize_u8(stream);
        if (scheme == SCHEME_ED25519) {
            PublicKey::Ed25519(sig_ed25519::deserialize_public_key(stream))
        } else {
            abort E_UNSUPPORTED_SCHEME
        }
    }

    public fun public_key_from_bytes(data: vector<u8>): PublicKey {
        let stream = bcs_stream::new(data);
        let pk = deserialize_public_key(&mut stream);
        assert!(!bcs_stream::has_remaining(&mut stream), E_TRAILING_BYTES);
        pk
    }

    public fun public_key_scheme(pk: &PublicKey): u8 {
        match (pk) {
            PublicKey::Ed25519(_) => SCHEME_ED25519,
        }
    }

    public fun public_key_as_ed25519(pk: PublicKey): sig_ed25519::PublicKey {
        match (pk) {
            PublicKey::Ed25519(inner) => inner,
        }
    }

    public fun deserialize_signature(stream: &mut BCSStream): Signature {
        let scheme = bcs_stream::deserialize_u8(stream);
        if (scheme == SCHEME_ED25519) {
            Signature::Ed25519(sig_ed25519::deserialize_signature(stream))
        } else {
            abort E_UNSUPPORTED_SCHEME
        }
    }

    public fun signature_from_bytes(data: vector<u8>): Signature {
        let stream = bcs_stream::new(data);
        let signature = deserialize_signature(&mut stream);
        assert!(!bcs_stream::has_remaining(&mut stream), E_TRAILING_BYTES);
        signature
    }

    public fun signature_scheme(signature: &Signature): u8 {
        match (signature) {
            Signature::Ed25519(_) => SCHEME_ED25519,
        }
    }

    public fun signature_as_ed25519(signature: Signature): sig_ed25519::Signature {
        match (signature) {
            Signature::Ed25519(inner) => inner,
        }
    }

    public fun verify(signature: &Signature, public_key: &PublicKey, message: vector<u8>): bool {
        match (signature) {
            Signature::Ed25519(signature) => match (public_key) {
                PublicKey::Ed25519(public_key) => sig_ed25519::verify(signature, public_key, message),
            },
        }
    }

    public fun assert_same_scheme(signature: &Signature, public_key: &PublicKey) {
        assert!(signature_scheme(signature) == public_key_scheme(public_key), E_SCHEME_MISMATCH);
    }

    const GOLDEN_PUBLIC_KEY: vector<u8> = x"0020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
    const GOLDEN_SIGNATURE: vector<u8> =
        x"0040000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f";

    #[test]
    fun public_key_from_bytes_round_trips_scheme() {
        let pk = public_key_from_bytes(GOLDEN_PUBLIC_KEY);
        assert!(public_key_scheme(&pk) == SCHEME_ED25519, 1);
        let inner = public_key_as_ed25519(pk);
        assert!(sig_ed25519::public_key_bytes(&inner).length() == 32, 2);
    }

    #[test]
    fun signature_from_bytes_round_trips_scheme() {
        let signature = signature_from_bytes(GOLDEN_SIGNATURE);
        assert!(signature_scheme(&signature) == SCHEME_ED25519, 1);
        let inner = signature_as_ed25519(signature);
        assert!(sig_ed25519::signature_bytes(&inner).length() == 64, 2);
    }

    #[test]
    #[expected_failure(abort_code = E_UNSUPPORTED_SCHEME)]
    fun public_key_from_bytes_rejects_unknown_scheme() {
        let bad = GOLDEN_PUBLIC_KEY;
        bad[0] = 0xff;
        public_key_from_bytes(bad);
    }

    #[test]
    #[expected_failure(abort_code = E_TRAILING_BYTES)]
    fun public_key_from_bytes_rejects_trailing_bytes() {
        let bad = GOLDEN_PUBLIC_KEY;
        bad.push_back(0x00);
        public_key_from_bytes(bad);
    }
}
