# Public-Key Encryption (`pke::*`)

The PKE layer is used to encrypt **VSS share messages** (dealer → recipient) and **decryption-request bodies** (client ↔ worker). Three schemes exist in the codebase, selected by a 1-byte scheme tag:

| Scheme | Tag | Status | Defined |
|--------|-----|--------|---------|
| ElGamal-OTP-Ristretto255 | `0x00` | **test-only** (see below) | `ts-sdk/src/pke/elgamal_otp_ristretto255.ts`, `worker-components/vss-common/src/{pke.rs,crypto.rs}`, `contracts/pke/sources/pke_elgamal_otp_ristretto255.move` |
| HPKE-X25519-HKDF-SHA256-ChaCha20Poly1305 | `0x01` | **production, default** | `ts-sdk/src/pke/hpke_x25519_chacha20poly1305.ts`, `worker-components/vss-common/src/pke_hpke_x25519_chacha20poly1305.rs`, `contracts/pke/sources/pke_hpke_x25519_chacha20poly1305.move` |
| Hybrid-X25519-MLKEM768-HKDF-SHA256-ChaCha20Poly1305 | `0x02` | **prototype, unaudited** | `ts-sdk/src/pke/hybrid_x25519_mlkem768_chacha20poly1305.ts`, `worker-components/vss-common/src/pke_hybrid_x25519_mlkem768_chacha20poly1305.rs`, `contracts/pke/sources/pke_hybrid_x25519_mlkem768_chacha20poly1305.move` |

> **Audit scope.** Only **scheme `0x01`** is audited. Scheme `0x00` is **test-only** — a hand-rolled ElGamal-in-the-exponent + custom OTP/HMAC DEM construction that has no formal security proof and uses non-standard primitives (notably the 64-byte-block HMAC-SHA3-256 of [`symmetric.md`](./symmetric.md) §2). Scheme `0x02` is a post-quantum/hybrid prototype for on-chain share transport and is not production-audited. Production deployments must use scheme `0x01` unless a deployment explicitly opts into the prototype.

## 1. HPKE-X25519-HKDF-SHA256-ChaCha20Poly1305 (scheme `0x01`, default)

[RFC 9180](https://www.rfc-editor.org/rfc/rfc9180) HPKE in **base mode** (no PSK, no auth).

**Ciphersuite.**
```
KemId  = 0x0020   (DHKEM(X25519, HKDF-SHA256))
KdfId  = 0x0001   (HKDF-SHA256)
AeadId = 0x0003   (ChaCha20-Poly1305)
info   = b""       (empty)
aad    = b""       (empty by default; callers do NOT pass AAD)
```

**TS implementation** uses [`@hpke/core`](https://www.npmjs.com/package/@hpke/core) for browser+node WebCrypto-backed primitives (`ts-sdk/src/pke/hpke_x25519_chacha20poly1305.ts`). **Rust implementation** uses [`hpke`](https://docs.rs/hpke/latest/hpke/) crate (`worker-components/vss-common/src/pke_hpke_x25519_chacha20poly1305.rs:19-23`). **Move implementation** is decoder-only (`contracts/pke/sources/pke_hpke_x25519_chacha20poly1305.move`); no on-chain encrypt/decrypt is needed.

**Wire shapes.** Byte layouts for `EncryptionKey`, `DecryptionKey`, and `Ciphertext` (HPKE rows) live in [`../wire-formats.md`](../wire-formats.md) §1.1-§1.3.

**Security.** RFC 9180 base mode is IND-CCA2 under the X25519 GapDH assumption (or qDHI per the analysis in the HPKE RFC) and HKDF/ChaCha20-Poly1305 standard assumptions. ~128-bit security level.

**Caveats / audit notes.**
- AAD is hardcoded empty; callers cannot bind external context to a ciphertext via this layer. The application layer (Aptos full-message signature, Solana txn simulation) provides binding instead.
- Implementations across TS/Rust/Move use **independent** HPKE libraries — wire-compatibility is verified by the round-trip tests in `worker-components/vss-common/src/pke_hpke_x25519_chacha20poly1305.rs:166-307` and `contracts/pke/tests/`.

## 2. Hybrid-X25519-MLKEM768-HKDF-SHA256-ChaCha20Poly1305 (scheme `0x02`, prototype)

Nested hybrid PKE for harvest-now-decrypt-later protection of long-lived on-chain share ciphertexts. TS and Rust encrypt the plaintext first with scheme `0x01`, then encapsulate with ML-KEM-768, derive an outer ChaCha20-Poly1305 key via HKDF-SHA256, and encrypt the serialized inner HPKE ciphertext. Move is decoder-only.

**Sources / standards.**
- Inner encryption is HPKE base mode from [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180), using DHKEM(X25519, HKDF-SHA256) and ChaCha20-Poly1305.
- Outer encapsulation uses ML-KEM-768 from [NIST FIPS 203](https://csrc.nist.gov/pubs/fips/203/final).
- The outer KDF is HKDF-SHA256 from [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869); the outer AEAD is ChaCha20-Poly1305 from [RFC 8439](https://www.rfc-editor.org/rfc/rfc8439).

**Security model / intent.** This exact nested construction is not a standardized HPKE hybrid, HPKE-X-Wing, or a scheme with an ACE-specific production proof. Treat it as a prototype KEM-DEM composition in the public-key IND-CCA confidentiality setting: inner HPKE relies on the RFC 9180 HPKE security analysis; outer confidentiality relies on ML-KEM-768 IND-CCA KEM security, HKDF as a KDF, and ChaCha20-Poly1305 AEAD security. The intended harvest-now-decrypt-later property is that historical ciphertext confidentiality survives if the outer ML-KEM-768 layer remains secure against quantum adversaries; the nested inner HPKE layer is a classical fallback if the ML-KEM layer were later broken. The Rust ML-KEM implementation is the unaudited RustCrypto `ml-kem` crate; this scheme is not production-audited.

**Ciphertext size.** For a plaintext of `P` bytes, the inner HPKE ciphertext struct is `33 + uleb_len(P + 16) + P + 16` bytes, where `uleb_len(x)` is the byte length of the BCS ULEB128 length prefix for `x`. The outer AEAD plaintext is that inner struct, and the outer AEAD adds a 16-byte tag. Including the scheme byte, ML-KEM ciphertext, nonce, and BCS length prefixes, scheme `0x02` ciphertext size is:

```
1104 + uleb_len(outer_len) + outer_len
where outer_len = 49 + uleb_len(P + 16) + P + 16
```

Examples: `P=32` -> **1203 B**, `P=1024` -> **2197 B**, `P=65536` -> **66711 B**. See [`../wire-formats.md`](../wire-formats.md) §1.2 for the field-level byte layout.

**Current limitations.** Scheme `0x02` is not standardized HPKE-X-Wing and is not audited. It is suitable for VSS share-transport prototyping and performance evaluation, not default production use.
