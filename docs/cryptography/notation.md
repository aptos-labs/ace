# Notation and conventions

- `Fr` — scalar field of BLS12-381, prime order `r ≈ 2²⁵²`.
- `G1`, `G2` — the two pairing-friendly subgroups of BLS12-381 (cofactor-cleared).
- `Gt` — target group, `Fp¹²` in BLS12-381.
- `Ristretto255` — prime-order group derived from Ed25519 (RFC 9496 candidate).
- `||` denotes byte concatenation. `LE64(x)` means 8-byte little-endian. `BCS(·)` is Aptos's Binary Canonical Serialization (`Vec<u8>` ⇒ `ULEB128(len) || bytes`).
- All hash-to-curve uses RFC 9380 (`hash_to_curve`) with the per-suite DST listed in the scheme that uses it.
- Random sampling uses each platform's CSPRNG (`OsRng` in Rust, `crypto.getRandomValues` / Web Crypto in TS). See [`identifiers.md`](./identifiers.md) for the per-component RNG table.

Group/scheme tags used throughout:

- `group::SCHEME_BLS12381G1 = 0x00`
- `group::SCHEME_BLS12381G2 = 0x01`

Defined in `contracts/group/sources/group.move` and mirrored in `worker-components/vss-common/src/session.rs`. Per-scheme element sizes and hash-to-curve suites are tabulated in [`identifiers.md`](./identifiers.md).
