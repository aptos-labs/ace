// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// ElGamal+OTP over Ristretto255 — scheme 0 concrete types.
/// Mirrors ts-sdk/src/pke/elgamal_otp_ristretto255.ts.
/// BCS wire format is byte-identical with the TypeScript implementation.
///
/// This module contains the scheme-specific structs and serde.
/// The abstract outer layer lives in ace::pke.
module ace::pke_elgamal_otp_ristretto255 {
    use aptos_std::bcs_stream::{Self, BCSStream};
    use aptos_std::ristretto255::{Self, CompressedRistretto};

    // ── Error codes ──────────────────────────────────────────────────────────

    const EINVALID_ENC_KEY: u64 = 1;
    const EINVALID_CIPHERTEXT: u64 = 2;
    const ETRAILING_BYTES: u64 = 3;

    // ── Constants ────────────────────────────────────────────────────────────

    const RISTRETTO255_POINT_BYTES: u64 = 32;
    const MAC_BYTES: u64 = 32;

    // ── Types ────────────────────────────────────────────────────────────────

    /// Encryption key: (enc_base, public_point).
    /// Wire (no scheme prefix): [ULEB128(32)] [32B enc_base]
    ///                          [ULEB128(32)] [32B public_point]
    struct EncryptionKey has copy, drop, store {
        enc_base: CompressedRistretto,
        public_point: CompressedRistretto,
    }

    /// Ciphertext: (c0, c1, symmetric_ciph, mac).
    /// Wire (no scheme prefix): [ULEB128(32)] [32B c0]
    ///                          [ULEB128(32)] [32B c1]
    ///                          [ULEB128(len)] [len B symmetric_ciph]
    ///                          [ULEB128(32)] [32B mac]
    struct Ciphertext has copy, drop, store {
        c0: CompressedRistretto,
        c1: CompressedRistretto,
        symmetric_ciph: vector<u8>,
        mac: vector<u8>,
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    fun deserialize_bytes_field(stream: &mut BCSStream): vector<u8> {
        bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s))
    }

    fun deserialize_point(stream: &mut BCSStream, err: u64): CompressedRistretto {
        let bytes = deserialize_bytes_field(stream);
        assert!(bytes.length() == RISTRETTO255_POINT_BYTES, err);
        let opt = ristretto255::new_point_from_bytes(bytes);
        assert!(opt.is_some(), err);
        ristretto255::point_compress(&opt.destroy_some())
    }

    // ── EncryptionKey public API ──────────────────────────────────────────────

    /// Parse an `EncryptionKey` from a BCS stream (no leading scheme byte).
    public fun deserialize_enc_key(stream: &mut BCSStream): EncryptionKey {
        let enc_base = deserialize_point(stream, EINVALID_ENC_KEY);
        let public_point = deserialize_point(stream, EINVALID_ENC_KEY);
        EncryptionKey { enc_base, public_point }
    }

    /// Parse an `EncryptionKey` from standalone bytes (no leading scheme byte).
    public fun enc_key_from_bytes(data: vector<u8>): EncryptionKey {
        let stream = bcs_stream::new(data);
        let ek = deserialize_enc_key(&mut stream);
        assert!(!bcs_stream::has_remaining(&mut stream), ETRAILING_BYTES);
        ek
    }

    /// Destructure an `EncryptionKey` into `(enc_base, public_point)`.
    public fun unpack_enc_key(ek: EncryptionKey): (CompressedRistretto, CompressedRistretto) {
        let EncryptionKey { enc_base, public_point } = ek;
        (enc_base, public_point)
    }

    // ── Ciphertext public API ─────────────────────────────────────────────────

    /// Parse a `Ciphertext` from a BCS stream (no leading scheme byte).
    public fun deserialize_ciphertext(stream: &mut BCSStream): Ciphertext {
        let c0 = deserialize_point(stream, EINVALID_CIPHERTEXT);
        let c1 = deserialize_point(stream, EINVALID_CIPHERTEXT);
        let symmetric_ciph = deserialize_bytes_field(stream);
        let mac = deserialize_bytes_field(stream);
        assert!(mac.length() == MAC_BYTES, EINVALID_CIPHERTEXT);
        Ciphertext { c0, c1, symmetric_ciph, mac }
    }

    /// Parse a `Ciphertext` from standalone bytes (no leading scheme byte).
    public fun ciphertext_from_bytes(data: vector<u8>): Ciphertext {
        let stream = bcs_stream::new(data);
        let ct = deserialize_ciphertext(&mut stream);
        assert!(!bcs_stream::has_remaining(&mut stream), ETRAILING_BYTES);
        ct
    }

    /// Destructure a `Ciphertext` into `(c0, c1, symmetric_ciph, mac)`.
    public fun unpack_ciphertext(ct: Ciphertext): (CompressedRistretto, CompressedRistretto, vector<u8>, vector<u8>) {
        let Ciphertext { c0, c1, symmetric_ciph, mac } = ct;
        (c0, c1, symmetric_ciph, mac)
    }

    // ── Tests ─────────────────────────────────────────────────────────────────
    //
    // Inner golden bytes are the outer pke.test.ts goldens with the leading 0x00
    // scheme byte stripped.

    #[test]
    fun test_ciphertext_from_bytes_golden() {
        // 116 bytes — outer 117-byte GOLDEN_CIPHERTEXT_BYTES minus leading 0x00
        let inner = x"2014c7926d76823e4a63b1af4b5b3e95dae3c64d05cf977e9d2a15a0111f06d4622056c0e7f44b3421bd93e1f418768db5f034eae6b1cf1bc005e24cd1d04c5b821c10bd77c200e653658f9dd719653744eb9e20e36a274f7710a9c9448afbfe5857a0f2478ee0f21f4cd27cdadcbbc9b45e9090";
        let ct = ciphertext_from_bytes(inner);
        let (c0, c1, sym_ciph, mac) = unpack_ciphertext(ct);
        assert!(ristretto255::point_to_bytes(&c0).length() == 32, 1);
        assert!(ristretto255::point_to_bytes(&c1).length() == 32, 2);
        assert!(sym_ciph.length() == 16, 3); // "golden-plaintext" (16 bytes)
        assert!(mac.length() == 32, 4);
    }

    #[test]
    #[expected_failure]
    fun test_ciphertext_trailing_bytes_rejected() {
        let inner = x"2014c7926d76823e4a63b1af4b5b3e95dae3c64d05cf977e9d2a15a0111f06d4622056c0e7f44b3421bd93e1f418768db5f034eae6b1cf1bc005e24cd1d04c5b821c10bd77c200e653658f9dd719653744eb9e20e36a274f7710a9c9448afbfe5857a0f2478ee0f21f4cd27cdadcbbc9b45e9090";
        inner.push_back(0x00);
        ciphertext_from_bytes(inner);
    }

    #[test]
    fun test_enc_key_from_bytes_golden() {
        // 66 bytes — outer 67-byte GOLDEN_ENC_KEY_HEX minus leading 0x00
        let inner = x"20f84e5c1c19630f29093c84052819f02bc2158dbad8590e9121fa4c59d20e1741209e441d841f1c37c7104a3eb43f51447306c8cb2294cc6ac1be23f32f23c72b71";
        let ek = enc_key_from_bytes(inner);
        let (enc_base, public_point) = unpack_enc_key(ek);
        assert!(ristretto255::point_to_bytes(&enc_base).length() == 32, 1);
        assert!(ristretto255::point_to_bytes(&public_point).length() == 32, 2);
    }

    #[test]
    #[expected_failure]
    fun test_enc_key_trailing_bytes_rejected() {
        let inner = x"20f84e5c1c19630f29093c84052819f02bc2158dbad8590e9121fa4c59d20e1741209e441d841f1c37c7104a3eb43f51447306c8cb2294cc6ac1be23f32f23c72b71";
        inner.push_back(0x00);
        enc_key_from_bytes(inner);
    }
}
