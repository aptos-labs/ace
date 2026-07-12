# Public-Key Encryption (`pke::*`)

The PKE layer is used for **client <-> worker request/response bodies**. It is
no longer the VSS share-delivery mechanism: off-chain VSS shares are sent over
the node-message gateway and authenticated with node-to-node signatures; see
[`sig.md`](./sig.md) and [`vss.md`](./vss.md).

Worker PKE encryption keys are still registered on chain in
`worker_config::PkeEncryptionKey` so SDK clients can encrypt worker requests.
Two schemes exist in the codebase, selected by a 1-byte scheme tag:

| Scheme | Tag | Status | Defined |
|--------|-----|--------|---------|
| ElGamal-OTP-Ristretto255 | `0x00` | **test-only** (see below) | `ts-sdk/src/pke/elgamal_otp_ristretto255.ts`, `worker-components/vss-common/src/{pke.rs,crypto.rs}`, `contracts/pke/sources/pke_elgamal_otp_ristretto255.move` |
| HPKE-X25519-HKDF-SHA256-ChaCha20Poly1305 | `0x01` | **production, default** | `ts-sdk/src/pke/hpke_x25519_chacha20poly1305.ts`, `worker-components/vss-common/src/pke_hpke_x25519_chacha20poly1305.rs`, `contracts/pke/sources/pke_hpke_x25519_chacha20poly1305.move` |

> **Audit scope.** Only **scheme `0x01`** is audited. Scheme `0x00` is **test-only** — a hand-rolled ElGamal-in-the-exponent + custom OTP/HMAC DEM construction that has no formal security proof and uses non-standard primitives. Production deployments must use scheme `0x01`.

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

**Wire shapes.** Byte layouts for `EncryptionKey`, `DecryptionKey`, and
`Ciphertext` (HPKE rows) live in [`../wire-formats.md`](../wire-formats.md)
§PKE.

**Security.** RFC 9180 base mode is IND-CCA2 under the X25519 GapDH assumption (or qDHI per the analysis in the HPKE RFC) and HKDF/ChaCha20-Poly1305 standard assumptions. ~128-bit security level.

**Caveats / audit notes.**
- AAD is hardcoded empty; callers cannot bind external context to a ciphertext via this layer. The application layer provides binding through signed Aptos request payloads and protocol transcripts.
- Implementations across TS/Rust/Move use **independent** HPKE libraries — wire-compatibility is verified by the round-trip tests in `worker-components/vss-common/src/pke_hpke_x25519_chacha20poly1305.rs:166-307` and `contracts/pke/tests/`.
