# ACE Cryptographic Specification — moved

This file has been split into per-scheme documents under [`cryptography/`](./cryptography/). See [`cryptography/README.md`](./cryptography/README.md) for the index and reading order.

## Redirect map

| Old section | New location |
|---|---|
| §1 Notation and conventions | [`cryptography/notation.md`](./cryptography/notation.md) |
| §2 Public-Key Encryption | [`cryptography/pke.md`](./cryptography/pke.md) |
| §3 Threshold IBE | [`cryptography/t-ibe.md`](./cryptography/t-ibe.md) |
| §4 VSS — origin, implementation choices, modified security argument | [`cryptography/vss.md`](./cryptography/vss.md) |
| §4.0.1 DKR origin and modifications | [`cryptography/dkr.md`](./cryptography/dkr.md) |
| §4.3 Resharing-dealer challenge | [`cryptography/dkr.md`](./cryptography/dkr.md) §2 |
| §4.4 DKG/DKR composition | [`cryptography/dkg.md`](./cryptography/dkg.md), [`cryptography/dkr.md`](./cryptography/dkr.md) |
| §5 Sigma-DLog-Eq | [`cryptography/sigma-dlog-eq.md`](./cryptography/sigma-dlog-eq.md) |
| §6 Symmetric primitives (KDF, HMAC) | [`cryptography/symmetric.md`](./cryptography/symmetric.md) |
| §7 RNG · §8 Curve cheat sheet | [`cryptography/identifiers.md`](./cryptography/identifiers.md) |
| §9 Out of scope | [`cryptography/out-of-scope.md`](./cryptography/out-of-scope.md) |
| §10 References | [`cryptography/references.md`](./cryptography/references.md) |

This stub exists so that external references to `docs/crypto-spec.md` still resolve to a meaningful landing page. New content should be added under the appropriate file in [`cryptography/`](./cryptography/).
