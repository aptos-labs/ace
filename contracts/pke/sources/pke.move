// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// PKE abstract layer — scheme-dispatching enums for encryption keys and ciphertexts.
/// Mirrors ts-sdk/src/pke/index.ts.
///
/// Each enum currently has one variant (Simple ElGamal over Ristretto255 = scheme 0).
/// Adding a new scheme is an additive change: add a variant here and a sibling module.
/// Scheme-specific types and serde live in ace::pke_elgamal_otp_ristretto255.
module ace::pke {
    use aptos_std::bcs_stream::{Self, BCSStream};
    use ace::pke_elgamal_otp_ristretto255;

    // ── Error codes ──────────────────────────────────────────────────────────

    /// Unknown / unsupported PKE scheme byte.
    const EUNSUPPORTED_SCHEME: u64 = 1;
    /// Trailing bytes after deserialization.
    const ETRAILING_BYTES: u64 = 2;

    // ── Scheme constants ─────────────────────────────────────────────────────

    const SCHEME_ELGAMAL_OTP_RISTRETTO255: u8 = 0;

    // ── Outer enum types ─────────────────────────────────────────────────────

    /// Wire: [u8 scheme=0] [inner EncryptionKey bytes]
    enum EncryptionKey has copy, drop, store {
        ElGamalOtpRistretto255(pke_elgamal_otp_ristretto255::EncryptionKey),
    }

    /// Wire: [u8 scheme=0] [inner Ciphertext bytes]
    enum Ciphertext has copy, drop, store {
        ElGamalOtpRistretto255(pke_elgamal_otp_ristretto255::Ciphertext),
    }

    // ── Public scheme constants ───────────────────────────────────────────────

    public fun scheme_elgamal_otp_ristretto255(): u8 {
        SCHEME_ELGAMAL_OTP_RISTRETTO255
    }

    // ── EncryptionKey parse ───────────────────────────────────────────────────

    /// Parse an `EncryptionKey` from a BCS stream (reads the leading scheme byte).
    public fun deserialize_enc_key(stream: &mut BCSStream): EncryptionKey {
        let scheme = bcs_stream::deserialize_u8(stream);
        if (scheme == SCHEME_ELGAMAL_OTP_RISTRETTO255) {
            EncryptionKey::ElGamalOtpRistretto255(
                pke_elgamal_otp_ristretto255::deserialize_enc_key(stream)
            )
        } else {
            abort EUNSUPPORTED_SCHEME
        }
    }

    /// Parse an `EncryptionKey` from standalone bytes.
    public fun enc_key_from_bytes(data: vector<u8>): EncryptionKey {
        let stream = bcs_stream::new(data);
        let ek = deserialize_enc_key(&mut stream);
        assert!(!bcs_stream::has_remaining(&mut stream), ETRAILING_BYTES);
        ek
    }

    // ── EncryptionKey accessors ───────────────────────────────────────────────

    /// Return the scheme byte of an `EncryptionKey`.
    public fun get_enc_key_scheme(ek: &EncryptionKey): u8 {
        match (ek) {
            EncryptionKey::ElGamalOtpRistretto255(_) => SCHEME_ELGAMAL_OTP_RISTRETTO255,
        }
    }

    /// Downcast an `EncryptionKey` to its `ElGamalOtpRistretto255` inner type.
    /// Aborts with `EUNSUPPORTED_SCHEME` if the variant does not match (future-proof).
    public fun enc_key_as_elgamal_otp_ristretto255(ek: EncryptionKey): pke_elgamal_otp_ristretto255::EncryptionKey {
        match (ek) {
            EncryptionKey::ElGamalOtpRistretto255(inner) => inner,
        }
    }

    // ── Ciphertext parse ──────────────────────────────────────────────────────

    /// Parse a `Ciphertext` from a BCS stream (reads the leading scheme byte).
    public fun deserialize_ciphertext(stream: &mut BCSStream): Ciphertext {
        let scheme = bcs_stream::deserialize_u8(stream);
        if (scheme == SCHEME_ELGAMAL_OTP_RISTRETTO255) {
            Ciphertext::ElGamalOtpRistretto255(
                pke_elgamal_otp_ristretto255::deserialize_ciphertext(stream)
            )
        } else {
            abort EUNSUPPORTED_SCHEME
        }
    }

    /// Parse a `Ciphertext` from standalone bytes.
    public fun ciphertext_from_bytes(data: vector<u8>): Ciphertext {
        let stream = bcs_stream::new(data);
        let ct = deserialize_ciphertext(&mut stream);
        assert!(!bcs_stream::has_remaining(&mut stream), ETRAILING_BYTES);
        ct
    }

    // ── Ciphertext accessors ──────────────────────────────────────────────────

    /// Return the scheme byte of a `Ciphertext`.
    public fun get_ciphertext_scheme(ct: &Ciphertext): u8 {
        match (ct) {
            Ciphertext::ElGamalOtpRistretto255(_) => SCHEME_ELGAMAL_OTP_RISTRETTO255,
        }
    }

    /// Downcast a `Ciphertext` to its `ElGamalOtpRistretto255` inner type.
    public fun ciphertext_as_elgamal_otp_ristretto255(ct: Ciphertext): pke_elgamal_otp_ristretto255::Ciphertext {
        match (ct) {
            Ciphertext::ElGamalOtpRistretto255(inner) => inner,
        }
    }

    // ── Tests ─────────────────────────────────────────────────────────────────
    //
    // Golden bytes from ts-sdk/tests/pke.test.ts (outer format, including scheme byte).

    // Golden ciphertext: GOLDEN_CIPHERTEXT_BYTES (117 bytes, scheme=0x00).
    const GOLDEN_CIPHERTEXT: vector<u8> = x"002014c7926d76823e4a63b1af4b5b3e95dae3c64d05cf977e9d2a15a0111f06d4622056c0e7f44b3421bd93e1f418768db5f034eae6b1cf1bc005e24cd1d04c5b821c10bd77c200e653658f9dd719653744eb9e20e36a274f7710a9c9448afbfe5857a0f2478ee0f21f4cd27cdadcbbc9b45e9090";

    // Golden enc key: GOLDEN_ENC_KEY_HEX (67 bytes, scheme=0x00).
    const GOLDEN_ENC_KEY: vector<u8> = x"0020f84e5c1c19630f29093c84052819f02bc2158dbad8590e9121fa4c59d20e1741209e441d841f1c37c7104a3eb43f51447306c8cb2294cc6ac1be23f32f23c72b71";

    #[test]
    fun test_ciphertext_from_bytes_golden() {
        let ct = ciphertext_from_bytes(GOLDEN_CIPHERTEXT);
        assert!(get_ciphertext_scheme(&ct) == SCHEME_ELGAMAL_OTP_RISTRETTO255, 1);
        let (_, _, sym_ciph, mac) = pke_elgamal_otp_ristretto255::unpack_ciphertext(
            ciphertext_as_elgamal_otp_ristretto255(ct)
        );
        assert!(sym_ciph.length() == 16, 2); // "golden-plaintext" (16 bytes)
        assert!(mac.length() == 32, 3);
    }

    #[test]
    #[expected_failure]
    fun test_ciphertext_trailing_bytes_rejected() {
        let bad = GOLDEN_CIPHERTEXT;
        bad.push_back(0x00);
        ciphertext_from_bytes(bad);
    }

    #[test]
    #[expected_failure(abort_code = EUNSUPPORTED_SCHEME)]
    fun test_ciphertext_unknown_scheme_rejected() {
        // Replace scheme byte 0x00 with 0x01
        let bad = x"012014c7926d76823e4a63b1af4b5b3e95dae3c64d05cf977e9d2a15a0111f06d4622056c0e7f44b3421bd93e1f418768db5f034eae6b1cf1bc005e24cd1d04c5b821c10bd77c200e653658f9dd719653744eb9e20e36a274f7710a9c9448afbfe5857a0f2478ee0f21f4cd27cdadcbbc9b45e9090";
        ciphertext_from_bytes(bad);
    }

    #[test]
    fun test_enc_key_from_bytes_golden() {
        let ek = enc_key_from_bytes(GOLDEN_ENC_KEY);
        assert!(get_enc_key_scheme(&ek) == SCHEME_ELGAMAL_OTP_RISTRETTO255, 1);
        // Verify round-trip by checking the inner type is accessible
        let _ = enc_key_as_elgamal_otp_ristretto255(ek);
    }

    #[test]
    #[expected_failure]
    fun test_enc_key_trailing_bytes_rejected() {
        let bad = GOLDEN_ENC_KEY;
        bad.push_back(0x00);
        enc_key_from_bytes(bad);
    }

    #[test]
    #[expected_failure(abort_code = EUNSUPPORTED_SCHEME)]
    fun test_enc_key_unknown_scheme_rejected() {
        // Replace scheme byte 0x00 with 0x01
        let bad = x"0120f84e5c1c19630f29093c84052819f02bc2158dbad8590e9121fa4c59d20e1741209e441d841f1c37c7104a3eb43f51447306c8cb2294cc6ac1be23f32f23c72b71";
        enc_key_from_bytes(bad);
    }
}
