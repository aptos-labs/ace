# ACE Cryptographic Specification

This folder is the canonical cryptographic reference for ACE — exact constructions, parameters, domain-separation tags, security assumptions, and (where applicable) formal theorems and proof sketches.

For the higher-level protocol (DKG / DKR / decryption-request flow), see [`../protocols.md`](../protocols.md). For the on-the-wire byte layouts, see [`../wire-formats.md`](../wire-formats.md). For terms used without definition, see [`../glossary.md`](../glossary.md). For the trust model the constructions plug into, see [`../trust-model.md`](../trust-model.md).

> All byte-counts assume the wire/BCS encoding shipped today. ULEB128 length prefixes for `Vec<u8>` fields are noted explicitly. Citations are `path:line` against the repository at the doc-PR commit.

## Files

**Conventions.**
- [`notation.md`](./notation.md) — Fields, groups, byte/BCS conventions, hash-to-curve, RNG.

**Public-key primitives.**
- [`pke.md`](./pke.md) — Public-key encryption schemes used inside ACE for share messages and decryption-request bodies.
- [`t-ibe.md`](./t-ibe.md) — Threshold Identity-Based Encryption (the user-facing layer).

**Secret-sharing stack.**
- [`vss.md`](./vss.md) — Synchronous VSS protocol, Feldman PCS, share derivation, **Theorem 1** (sharing-phase one-wayness).
- [`dkg.md`](./dkg.md) — Distributed Key Generation as a composition of `n` parallel VSS sessions.
- [`dkr.md`](./dkr.md) — Distributed Key Resharing (proactive secret sharing variant): resharing-dealer challenge, old → new committee transition, corruption model.

**Building blocks.**
- [`sigma-dlog-eq.md`](./sigma-dlog-eq.md) — Sigma protocol proving equal discrete log in two bases; used by the DKR resharing-dealer challenge.
- [`symmetric.md`](./symmetric.md) — Custom SHA3-256 KDF and HMAC-like construction shared by TS, Rust, and Move.
- [`identifiers.md`](./identifiers.md) — Curve/group identifier cheat sheet, byte sizes, RNG sources.

**Boundary.**
- [`out-of-scope.md`](./out-of-scope.md) — Cryptographic items intentionally not in the current codebase (future work).
- [`references.md`](./references.md) — Standards and academic references cited across the folder.

## Suggested reading order for auditors

1. [`notation.md`](./notation.md) and [`identifiers.md`](./identifiers.md) — pin the symbols and curve choices.
2. [`pke.md`](./pke.md) and [`symmetric.md`](./symmetric.md) — the lowest-level primitives.
3. [`vss.md`](./vss.md) — the secret-sharing core, including **Theorem 1**.
4. [`dkg.md`](./dkg.md) and [`dkr.md`](./dkr.md) — protocol composition on top of VSS.
5. [`sigma-dlog-eq.md`](./sigma-dlog-eq.md) — the NIZK used by DKR.
6. [`t-ibe.md`](./t-ibe.md) — the application layer that consumes the DKG output.
7. [`out-of-scope.md`](./out-of-scope.md), [`references.md`](./references.md) — known boundaries and citations.

> Historical note: this folder replaces the former monolithic `docs/crypto-spec.md`. That file is now a thin index/redirect; new content should be added under the appropriate per-scheme file here.
