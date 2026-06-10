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

**Security intent.** Historical ciphertext confidentiality should survive if either X25519 remains secure or ML-KEM-768 remains secure. The Rust ML-KEM implementation is the unaudited RustCrypto `ml-kem` crate; this scheme is not production-audited.

**Current limitations.** Scheme `0x02` is not standardized HPKE-X-Wing and is not audited. It is suitable for VSS share-transport prototyping and performance evaluation, not default production use.
