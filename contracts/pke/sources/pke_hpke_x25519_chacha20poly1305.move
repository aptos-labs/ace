// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// HPKE base mode, ciphersuite:
///   KEM:  DHKEM(X25519, HKDF-SHA256)   (KemId 0x0020)
///   KDF:  HKDF-SHA256                  (KdfId 0x0001)
///   AEAD: ChaCha20-Poly1305            (AeadId 0x0003)
///
/// Wire-compatible with `ts-sdk/src/pke/hpke_x25519_chacha20poly1305.ts` and
/// `worker-components/vss-common/src/pke_hpke_x25519_chacha20poly1305.rs`.
///
/// Move performs no HPKE math — encrypt/decrypt happen off-chain. This module only
/// provides typed BCS wrappers + length checks so on-chain code can pass the bytes
/// around without losing structure. Mirrors `ace::pke_elgamal_otp_ristretto255`.
module ace::pke_hpke_x25519_chacha20poly1305 {
    use aptos_std::bcs_stream::{Self, BCSStream};

    // ── Error codes ──────────────────────────────────────────────────────────

    const EINVALID_ENC_KEY: u64 = 1;
    const EINVALID_CIPHERTEXT: u64 = 2;
    const ETRAILING_BYTES: u64 = 3;

    // ── Constants ────────────────────────────────────────────────────────────

    const X25519_KEY_BYTES: u64 = 32;
    /// Poly1305 authentication tag length appended by the AEAD.
    const AEAD_TAG_BYTES: u64 = 16;

    // ── Types ────────────────────────────────────────────────────────────────

    /// Encryption key wraps a raw 32-byte X25519 public key.
    /// Wire (no scheme prefix): [ULEB128(32)] [32B pk]
    struct EncryptionKey has copy, drop, store {
        pk: vector<u8>,
    }

    /// Ciphertext: 32-byte encapsulated key + AEAD ciphertext (which already includes
    /// the trailing 16-byte Poly1305 tag).
    /// Wire (no scheme prefix): [ULEB128(32)] [32B enc] [ULEB128(len)] [len B aead_ct]
    struct Ciphertext has copy, drop, store {
        enc: vector<u8>,
        aead_ct: vector<u8>,
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    fun deserialize_bytes_field(stream: &mut BCSStream): vector<u8> {
        bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s))
    }

    // ── EncryptionKey public API ──────────────────────────────────────────────

    /// Parse an `EncryptionKey` from a BCS stream (no leading scheme byte).
    public fun deserialize_enc_key(stream: &mut BCSStream): EncryptionKey {
        let pk = deserialize_bytes_field(stream);
        assert!(pk.length() == X25519_KEY_BYTES, EINVALID_ENC_KEY);
        EncryptionKey { pk }
    }

    /// Parse an `EncryptionKey` from standalone bytes (no leading scheme byte).
    public fun enc_key_from_bytes(data: vector<u8>): EncryptionKey {
        let stream = bcs_stream::new(data);
        let ek = deserialize_enc_key(&mut stream);
        assert!(!bcs_stream::has_remaining(&mut stream), ETRAILING_BYTES);
        ek
    }

    /// Destructure an `EncryptionKey` into its raw 32-byte public key.
    public fun unpack_enc_key(ek: EncryptionKey): vector<u8> {
        let EncryptionKey { pk } = ek;
        pk
    }

    // ── Ciphertext public API ─────────────────────────────────────────────────

    /// Parse a `Ciphertext` from a BCS stream (no leading scheme byte).
    public fun deserialize_ciphertext(stream: &mut BCSStream): Ciphertext {
        let enc = deserialize_bytes_field(stream);
        assert!(enc.length() == X25519_KEY_BYTES, EINVALID_CIPHERTEXT);
        let aead_ct = deserialize_bytes_field(stream);
        assert!(aead_ct.length() >= AEAD_TAG_BYTES, EINVALID_CIPHERTEXT);
        Ciphertext { enc, aead_ct }
    }

    /// Parse a `Ciphertext` from standalone bytes (no leading scheme byte).
    public fun ciphertext_from_bytes(data: vector<u8>): Ciphertext {
        let stream = bcs_stream::new(data);
        let ct = deserialize_ciphertext(&mut stream);
        assert!(!bcs_stream::has_remaining(&mut stream), ETRAILING_BYTES);
        ct
    }

    /// Destructure a `Ciphertext` into `(enc, aead_ct)`.
    public fun unpack_ciphertext(ct: Ciphertext): (vector<u8>, vector<u8>) {
        let Ciphertext { enc, aead_ct } = ct;
        (enc, aead_ct)
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test_only]
    fun build_enc_key_bytes(pk_len: u64): vector<u8> {
        // ULEB128(pk_len) is one byte for pk_len < 128. We assume pk_len < 128 here (always 32).
        let out = vector[];
        out.push_back(pk_len as u8);
        let i = 0;
        while (i < pk_len) { out.push_back(i as u8); i = i + 1; };
        out
    }

    #[test_only]
    fun build_ciphertext_bytes(enc_len: u64, aead_ct_len: u64): vector<u8> {
        let out = vector[];
        out.push_back(enc_len as u8);
        let i = 0;
        while (i < enc_len) { out.push_back(i as u8); i = i + 1; };
        // aead_ct_len fits in 1 ULEB128 byte for our test sizes (< 128).
        out.push_back(aead_ct_len as u8);
        let j = 0;
        while (j < aead_ct_len) { out.push_back((j as u8) ^ 0xa5); j = j + 1; };
        out
    }

    #[test]
    fun test_enc_key_round_trip() {
        let bytes = build_enc_key_bytes(32);
        assert!(bytes.length() == 33, 100);
        let ek = enc_key_from_bytes(bytes);
        let pk = unpack_enc_key(ek);
        assert!(pk.length() == 32, 101);
    }

    #[test]
    #[expected_failure(abort_code = EINVALID_ENC_KEY)]
    fun test_enc_key_wrong_length_rejected() {
        let bytes = build_enc_key_bytes(31); // 31B pk → fails length check
        enc_key_from_bytes(bytes);
    }

    #[test]
    #[expected_failure(abort_code = ETRAILING_BYTES)]
    fun test_enc_key_trailing_bytes_rejected() {
        let bytes = build_enc_key_bytes(32);
        bytes.push_back(0xff);
        enc_key_from_bytes(bytes);
    }

    #[test]
    fun test_ciphertext_round_trip_minimum() {
        // Smallest legal: enc=32B, aead_ct=16B (just the tag, plaintext was empty).
        let bytes = build_ciphertext_bytes(32, 16);
        assert!(bytes.length() == 1 + 32 + 1 + 16, 200);
        let ct = ciphertext_from_bytes(bytes);
        let (enc, aead_ct) = unpack_ciphertext(ct);
        assert!(enc.length() == 32, 201);
        assert!(aead_ct.length() == 16, 202);
    }

    #[test]
    fun test_ciphertext_round_trip_with_payload() {
        // 64B aead_ct = 48B ciphertext + 16B tag (e.g. plaintext "hello hpke" + lots of padding).
        let bytes = build_ciphertext_bytes(32, 64);
        let ct = ciphertext_from_bytes(bytes);
        let (enc, aead_ct) = unpack_ciphertext(ct);
        assert!(enc.length() == 32, 300);
        assert!(aead_ct.length() == 64, 301);
    }

    #[test]
    #[expected_failure(abort_code = EINVALID_CIPHERTEXT)]
    fun test_ciphertext_short_aead_rejected() {
        // aead_ct too short to even contain the Poly1305 tag.
        let bytes = build_ciphertext_bytes(32, 15);
        ciphertext_from_bytes(bytes);
    }

    #[test]
    #[expected_failure(abort_code = EINVALID_CIPHERTEXT)]
    fun test_ciphertext_wrong_enc_length_rejected() {
        let bytes = build_ciphertext_bytes(31, 16);
        ciphertext_from_bytes(bytes);
    }

    #[test]
    #[expected_failure(abort_code = ETRAILING_BYTES)]
    fun test_ciphertext_trailing_bytes_rejected() {
        let bytes = build_ciphertext_bytes(32, 16);
        bytes.push_back(0x00);
        ciphertext_from_bytes(bytes);
    }
}
