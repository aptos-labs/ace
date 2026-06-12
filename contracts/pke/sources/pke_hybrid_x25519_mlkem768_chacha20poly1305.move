// Copyright (c) Aptos Labs
// SPDX-License-Identifier: Apache-2.0

/// Hybrid PKE wire wrappers:
///   inner: HPKE-X25519-HKDF-SHA256-ChaCha20Poly1305
///   outer: ML-KEM-768 shared secret -> HKDF-SHA256 -> ChaCha20-Poly1305
///
/// Move performs no cryptographic operations here. This module only decodes BCS
/// structs and checks lengths so worker config and VSS sessions can carry the
/// bytes on chain without losing structure.
module ace::pke_hybrid_x25519_mlkem768_chacha20poly1305 {
    use aptos_std::bcs_stream::{Self, BCSStream};
    use ace::pke_hpke_x25519_chacha20poly1305;

    // ── Error codes ──────────────────────────────────────────────────────────

    const EINVALID_ENC_KEY: u64 = 1;
    const EINVALID_CIPHERTEXT: u64 = 2;
    const ETRAILING_BYTES: u64 = 3;

    // ── Constants ────────────────────────────────────────────────────────────

    const MLKEM768_EK_BYTES: u64 = 1184;
    const MLKEM768_CT_BYTES: u64 = 1088;
    const AEAD_NONCE_BYTES: u64 = 12;
    const AEAD_TAG_BYTES: u64 = 16;

    // ── Types ────────────────────────────────────────────────────────────────

    /// Wire (no outer scheme prefix):
    ///   HpkeEncryptionKey || [ULEB128(1184)] [1184B ML-KEM ek]
    struct EncryptionKey has copy, drop, store {
        hpke_x25519: pke_hpke_x25519_chacha20poly1305::EncryptionKey,
        mlkem768_ek: vector<u8>,
    }

    /// Wire (no outer scheme prefix):
    ///   [ULEB128(1088)] [1088B ML-KEM ct]
    ///   [ULEB128(12)]   [12B nonce]
    ///   [ULEB128(len)]  [len B outer AEAD ct]
    struct Ciphertext has copy, drop, store {
        mlkem768_ct: vector<u8>,
        aead_nonce: vector<u8>,
        aead_ct: vector<u8>,
    }

    // ── Internal helpers ─────────────────────────────────────────────────────

    fun deserialize_bytes_field(stream: &mut BCSStream): vector<u8> {
        bcs_stream::deserialize_vector(stream, |s| bcs_stream::deserialize_u8(s))
    }

    // ── EncryptionKey public API ──────────────────────────────────────────────

    public fun deserialize_enc_key(stream: &mut BCSStream): EncryptionKey {
        let hpke_x25519 = pke_hpke_x25519_chacha20poly1305::deserialize_enc_key(stream);
        let mlkem768_ek = deserialize_bytes_field(stream);
        assert!(mlkem768_ek.length() == MLKEM768_EK_BYTES, EINVALID_ENC_KEY);
        EncryptionKey { hpke_x25519, mlkem768_ek }
    }

    public fun enc_key_from_bytes(data: vector<u8>): EncryptionKey {
        let stream = bcs_stream::new(data);
        let ek = deserialize_enc_key(&mut stream);
        assert!(!bcs_stream::has_remaining(&mut stream), ETRAILING_BYTES);
        ek
    }

    public fun unpack_enc_key(ek: EncryptionKey): (pke_hpke_x25519_chacha20poly1305::EncryptionKey, vector<u8>) {
        let EncryptionKey { hpke_x25519, mlkem768_ek } = ek;
        (hpke_x25519, mlkem768_ek)
    }

    // ── Ciphertext public API ─────────────────────────────────────────────────

    public fun deserialize_ciphertext(stream: &mut BCSStream): Ciphertext {
        let mlkem768_ct = deserialize_bytes_field(stream);
        assert!(mlkem768_ct.length() == MLKEM768_CT_BYTES, EINVALID_CIPHERTEXT);
        let aead_nonce = deserialize_bytes_field(stream);
        assert!(aead_nonce.length() == AEAD_NONCE_BYTES, EINVALID_CIPHERTEXT);
        let aead_ct = deserialize_bytes_field(stream);
        assert!(aead_ct.length() >= AEAD_TAG_BYTES, EINVALID_CIPHERTEXT);
        Ciphertext { mlkem768_ct, aead_nonce, aead_ct }
    }

    public fun ciphertext_from_bytes(data: vector<u8>): Ciphertext {
        let stream = bcs_stream::new(data);
        let ct = deserialize_ciphertext(&mut stream);
        assert!(!bcs_stream::has_remaining(&mut stream), ETRAILING_BYTES);
        ct
    }

    public fun unpack_ciphertext(ct: Ciphertext): (vector<u8>, vector<u8>, vector<u8>) {
        let Ciphertext { mlkem768_ct, aead_nonce, aead_ct } = ct;
        (mlkem768_ct, aead_nonce, aead_ct)
    }

    // ── Tests ─────────────────────────────────────────────────────────────────

    #[test_only]
    fun push_bytes(out: &mut vector<u8>, len: u64, seed: u8) {
        let i = 0;
        while (i < len) {
            out.push_back(seed ^ ((i % 251) as u8));
            i = i + 1;
        }
    }

    #[test_only]
    fun push_uleb_len(out: &mut vector<u8>, len: u64) {
        if (len < 128) {
            out.push_back(len as u8);
        } else if (len == MLKEM768_EK_BYTES) {
            out.push_back(0xa0);
            out.push_back(0x09);
        } else if (len == MLKEM768_CT_BYTES) {
            out.push_back(0xc0);
            out.push_back(0x08);
        } else {
            abort 999
        }
    }

    #[test_only]
    fun build_enc_key_bytes(mlkem_len: u64): vector<u8> {
        let out = vector[];
        // HPKE inner key: [ULEB128(32)] [32B pk]
        out.push_back(0x20);
        push_bytes(&mut out, 32, 0x11);
        push_uleb_len(&mut out, mlkem_len);
        push_bytes(&mut out, mlkem_len, 0x42);
        out
    }

    #[test_only]
    fun build_ciphertext_bytes(mlkem_ct_len: u64, nonce_len: u64, aead_ct_len: u64): vector<u8> {
        let out = vector[];
        push_uleb_len(&mut out, mlkem_ct_len);
        push_bytes(&mut out, mlkem_ct_len, 0x21);
        push_uleb_len(&mut out, nonce_len);
        push_bytes(&mut out, nonce_len, 0x31);
        push_uleb_len(&mut out, aead_ct_len);
        push_bytes(&mut out, aead_ct_len, 0x41);
        out
    }

    #[test]
    fun test_enc_key_round_trip() {
        let bytes = build_enc_key_bytes(MLKEM768_EK_BYTES);
        let ek = enc_key_from_bytes(bytes);
        let (_, mlkem768_ek) = unpack_enc_key(ek);
        assert!(mlkem768_ek.length() == MLKEM768_EK_BYTES, 100);
    }

    #[test]
    #[expected_failure(abort_code = EINVALID_ENC_KEY)]
    fun test_enc_key_wrong_mlkem_length_rejected() {
        let bytes = build_enc_key_bytes(32);
        enc_key_from_bytes(bytes);
    }

    #[test]
    #[expected_failure(abort_code = ETRAILING_BYTES)]
    fun test_enc_key_trailing_bytes_rejected() {
        let bytes = build_enc_key_bytes(MLKEM768_EK_BYTES);
        bytes.push_back(0xff);
        enc_key_from_bytes(bytes);
    }

    #[test]
    fun test_ciphertext_round_trip() {
        let bytes = build_ciphertext_bytes(MLKEM768_CT_BYTES, AEAD_NONCE_BYTES, AEAD_TAG_BYTES + 8);
        let ct = ciphertext_from_bytes(bytes);
        let (mlkem768_ct, nonce, aead_ct) = unpack_ciphertext(ct);
        assert!(mlkem768_ct.length() == MLKEM768_CT_BYTES, 200);
        assert!(nonce.length() == AEAD_NONCE_BYTES, 201);
        assert!(aead_ct.length() == AEAD_TAG_BYTES + 8, 202);
    }

    #[test]
    #[expected_failure(abort_code = EINVALID_CIPHERTEXT)]
    fun test_ciphertext_wrong_mlkem_length_rejected() {
        let bytes = build_ciphertext_bytes(32, AEAD_NONCE_BYTES, AEAD_TAG_BYTES);
        ciphertext_from_bytes(bytes);
    }

    #[test]
    #[expected_failure(abort_code = EINVALID_CIPHERTEXT)]
    fun test_ciphertext_wrong_nonce_length_rejected() {
        let bytes = build_ciphertext_bytes(MLKEM768_CT_BYTES, 11, AEAD_TAG_BYTES);
        ciphertext_from_bytes(bytes);
    }

    #[test]
    #[expected_failure(abort_code = EINVALID_CIPHERTEXT)]
    fun test_ciphertext_short_aead_rejected() {
        let bytes = build_ciphertext_bytes(MLKEM768_CT_BYTES, AEAD_NONCE_BYTES, AEAD_TAG_BYTES - 1);
        ciphertext_from_bytes(bytes);
    }
}
