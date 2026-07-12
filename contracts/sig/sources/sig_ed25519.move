// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Ed25519 messaging signatures for node-to-node ACE protocol messages.
module ace::sig_ed25519 {
    use aptos_std::bcs_stream;
    use aptos_std::bcs_stream::BCSStream;
    use aptos_std::ed25519;

    const E_INVALID_PUBLIC_KEY_LEN: u64 = 1;
    const E_INVALID_SIGNATURE_LEN: u64 = 2;

    const PUBLIC_KEY_BYTES: u64 = 32;
    const SIGNATURE_BYTES: u64 = 64;

    struct PublicKey has copy, drop, store {
        bytes: vector<u8>,
    }

    struct Signature has copy, drop, store {
        bytes: vector<u8>,
    }

    public fun public_key_from_bytes(bytes: vector<u8>): PublicKey {
        assert!(bytes.length() == PUBLIC_KEY_BYTES, E_INVALID_PUBLIC_KEY_LEN);
        PublicKey { bytes }
    }

    public fun signature_from_bytes(bytes: vector<u8>): Signature {
        assert!(bytes.length() == SIGNATURE_BYTES, E_INVALID_SIGNATURE_LEN);
        Signature { bytes }
    }

    public fun deserialize_public_key(stream: &mut BCSStream): PublicKey {
        let bytes = bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s));
        public_key_from_bytes(bytes)
    }

    public fun deserialize_signature(stream: &mut BCSStream): Signature {
        let bytes = bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s));
        signature_from_bytes(bytes)
    }

    public fun public_key_bytes(pk: &PublicKey): vector<u8> {
        pk.bytes
    }

    public fun signature_bytes(sig: &Signature): vector<u8> {
        sig.bytes
    }

    public fun verify(signature: &Signature, public_key: &PublicKey, message: vector<u8>): bool {
        let sig = ed25519::new_signature_from_bytes(signature.bytes);
        let pk = ed25519::new_unvalidated_public_key_from_bytes(public_key.bytes);
        ed25519::signature_verify_strict(&sig, &pk, message)
    }

    #[test]
    fun public_key_from_bytes_accepts_32_bytes() {
        let pk = public_key_from_bytes(x"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f");
        assert!(public_key_bytes(&pk).length() == PUBLIC_KEY_BYTES, 1);
    }

    #[test]
    #[expected_failure(abort_code = E_INVALID_PUBLIC_KEY_LEN)]
    fun public_key_from_bytes_rejects_wrong_len() {
        public_key_from_bytes(x"01");
    }

    #[test]
    fun signature_from_bytes_accepts_64_bytes() {
        let sig = signature_from_bytes(
            x"000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        );
        assert!(signature_bytes(&sig).length() == SIGNATURE_BYTES, 1);
    }

    #[test]
    #[expected_failure(abort_code = E_INVALID_SIGNATURE_LEN)]
    fun signature_from_bytes_rejects_wrong_len() {
        signature_from_bytes(x"01");
    }
}
