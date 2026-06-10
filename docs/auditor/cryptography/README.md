# ACE Cryptographic Specification

This folder is the canonical cryptographic reference for ACE — exact constructions, parameters, domain-separation tags, security assumptions, and (where applicable) formal theorems and proof sketches.

For the higher-level protocol (DKG / DKR / decryption-request flow), see [`../protocols.md`](../protocols.md). For the on-the-wire byte layouts, see [`../wire-formats.md`](../wire-formats.md). For terms used without definition, see [`../glossary.md`](../glossary.md). For the trust model the constructions plug into, see [`../trust-model.md`](../trust-model.md).

> All byte-counts assume the wire/BCS encoding shipped today. ULEB128 length prefixes for `Vec<u8>` fields are noted explicitly. Citations are `path:line` against the repository at the doc-PR commit.

## Files

- [`pke.md`](./pke.md) — Public-key encryption schemes used inside ACE for share messages and decryption-request bodies.
- [`t-ibe.md`](./t-ibe.md) — Threshold Identity-Based Encryption (the user-facing layer).
- [`vss.md`](./vss.md) — Synchronous VSS protocol, Pedersen PCS, degree check, and sigma public-key binding.
- [`dkg.md`](./dkg.md) — Distributed Key Generation as a composition of $n$ parallel VSS sessions.
- [`dkr.md`](./dkr.md) — Distributed Key Resharing (proactive secret sharing variant): resharing-dealer challenge, old → new committee transition, corruption model.
- [`symmetric.md`](./symmetric.md) — Custom SHA3-256 KDF and HMAC-like construction shared by TS, Rust, and Move.

The notation, group/curve cheat sheet, out-of-scope items, and references are kept in this index file as the sections below.

## Suggested reading order for auditors

1. **Notation** and **Identifiers** (sections below) — pin the symbols and curve choices.
2. [`pke.md`](./pke.md) and [`symmetric.md`](./symmetric.md) — the lowest-level primitives.
3. [`vss.md`](./vss.md) — the secret-sharing core, including Pedersen commitments and public-key binding proofs.
4. [`dkg.md`](./dkg.md) and [`dkr.md`](./dkr.md) — protocol composition on top of VSS.
5. [`t-ibe.md`](./t-ibe.md) — the application layer that consumes the DKG output.
6. **Out of scope** and **References** (sections below) — known boundaries and citations.

> Historical note: this folder replaces the former monolithic `docs/crypto-spec.md`, which has been removed.

---

## Notation and conventions

- $\mathbb{F}_r$ — scalar field of BLS12-381, prime order $r \approx 2^{252}$.
- $\mathbb{G}_1$, $\mathbb{G}_2$ — the two pairing-friendly subgroups of BLS12-381 (cofactor-cleared).
- $\mathbb{G}_t$ — target group, $\mathbb{F}_{p^{12}}$ in BLS12-381.
- $e(\cdot, \cdot)\colon \mathbb{G}_1 \times \mathbb{G}_2 \to \mathbb{G}_t$ — the BLS12-381 optimal Ate pairing.
- $\mathsf{Ristretto255}$ — prime-order group derived from Ed25519 (RFC 9496 candidate).
- $g$ — generic notation for a group element used as a base point in a particular construction (the session's `public_base_element` for VSS; the master public key's basePoint for t-IBE; etc.). Specific base points are subscripted: $g_{\text{old}}$, $g_{\text{new}}$, $g_1 \in \mathbb{G}_1$, $g_2 \in \mathbb{G}_2$.
- Group operations are usually written **multiplicatively** in this folder: $g^x$ for scalar exponentiation, $g^x \cdot g^y$ for the group operation. VSS/PCS docs use additive notation such as $xG+rH$ because the Move implementation exposes `scale_element`, `element_add`, and MSM. The two notations are mathematically equivalent.
- $\|$ denotes byte concatenation. $\mathsf{LE64}(x)$ means 8-byte little-endian. $\mathsf{BCS}(\cdot)$ is Aptos's Binary Canonical Serialization: `Vec<u8>` is encoded as $\mathsf{ULEB128}(\mathsf{len}) \mathbin{\|} \mathsf{bytes}$.
- $x \in_R S$ means $x$ is sampled uniformly at random from the set $S$.
- All hash-to-curve uses RFC 9380 ($\mathsf{hashToCurve}$) with the per-suite DST listed in the scheme that uses it.

Group/scheme tags used throughout:

- `group::SCHEME_BLS12381G1 = 0x00`
- `group::SCHEME_BLS12381G2 = 0x01`

Defined in `contracts/group/sources/group.move` and mirrored in `worker-components/vss-common/src/session.rs`.

---

## Identifiers

### Curve / group cheat sheet

| Curve / Group | Field | Element size (compressed) | Hash-to-curve suite |
|---------------|-------|--------------------------:|---------------------|
| BLS12-381 G1 | Fp (381b) | **48 B** | `BLS12381G1_XMD:SHA-256_SSWU_RO_` |
| BLS12-381 G2 | Fp² | **96 B** | `BLS12381G2_XMD:SHA-256_SSWU_RO_` |
| BLS12-381 Fr | scalar (252b) | 32 B (LE) | n/a |
| BLS12-381 Gt | Fp¹² | 576 B (custom canonicalization, see [`t-ibe.md`](./t-ibe.md) §2) | n/a |
| Ristretto255 | derived from Ed25519 (252b) | 32 B | n/a (rejection-sampled) |
| X25519 (Curve25519 Mont) | Fp (255b) | 32 B (raw clamp) | n/a |
| Ed25519 (verifying key) | Fp | 32 B | n/a — used only for ProofOfPermission |

### Random number generation

| Component | RNG | Usage |
|-----------|-----|-------|
| TS SDK | WebCrypto `crypto.getRandomValues` (browser) / Node `crypto.randomBytes` | All ephemerals ($r$ in PKE/IBE encrypt, ephemeral encryption keys) |
| Rust workers | `rand::rngs::OsRng` (`/dev/urandom` on Linux, `getrandom` syscall) | VSS dealer optional `secret_override`, HPKE keygen |
| Move (on-chain) | `aptos_framework::randomness` API | DKG basepoint sampling (e.g. `epoch_change::touch` uses `randomness::generate(...)` for new G2 base points) |

**Audit notes.**
- VSS dealer polynomial randomness is **derived from the dealer's PKE decryption key**, not freshly sampled. This includes both the secret-bearing polynomial and the Pedersen blinding polynomial. This is intentional and security-equivalent provided the PKE dk is itself uniformly random; the operator-CLI generates the dk via `WebCrypto` at onboarding and stores it in the provider-specific secret manager (Cloud Run Secret, etc.).
- Aptos's on-chain `randomness::generate` is itself a threshold protocol. Trust assumption: the Aptos validator quorum is honest. This is part of the "contract is truth" trust premise — see [`../trust-model.md`](../trust-model.md).

---

## Out of scope (not yet implemented)

The following were called out in earlier discussions and are **not** in the current codebase. Auditors should not flag their absence; they're tracked as future work.

- **Production post-quantum PKE.** Scheme `0x02` is a TS/Rust PQ-hybrid prototype with Move-side decoding, but no audited production PQ-hybrid or PQ-only PKE is currently shipped. (Future: HPKE-X-Wing or another standardized hybrid; tracked separately.)
- **256-bit security level PKE.** Both PKE schemes are ~128-bit. (Future: HPKE-X448-HKDF-SHA512-ChaCha20Poly1305 or similar.)
- **t-IBE share proof.** The `IdentityDecryptionKeyShare` wire format reserves a 1-byte "proof" flag for a future per-share Schnorr proof; today it is always `0x00` (no proof). The verification check in [`t-ibe.md`](./t-ibe.md) §1 uses on-chain `share_pks` instead, which is sufficient for honest-majority assumptions but not for accountability under accusatory failure.
- **Move-side HPKE / shortsig-aead encrypt-decrypt.** Move only decodes these formats; the on-chain side never holds a private key for either, so no on-chain encrypt or decrypt is needed.
- **DKG bias-avoidance round (GJKR'99 commit-then-open).** Not implemented. The current DKG admits a small amount of bias on the master public key distribution under a rushing adversary; see [`dkg.md`](./dkg.md) §2. Acceptable under standard threshold-decryption / threshold-signing applications, where the master key is consumed only as a public group element and bias on a few bits of MSK is not exploitable.
- **Formal adaptive-security arguments.** VSS, DKG, and DKR are documented for static corruption. Adaptive corruption and adaptive-decryption security are out of scope.

---

## References

**Standards.**
- RFC 2104 — HMAC: Keyed-Hashing for Message Authentication.
- RFC 5869 — HKDF: HMAC-based Extract-and-Expand Key Derivation Function.
- RFC 7748 — Elliptic Curves for Security (Curve25519, Curve448).
- RFC 8032 — Edwards-Curve Digital Signature Algorithm (EdDSA / Ed25519).
- RFC 8439 — ChaCha20 and Poly1305 for IETF Protocols.
- RFC 9180 — Hybrid Public Key Encryption (HPKE).
- RFC 9380 — Hashing to Elliptic Curves.
- RFC 9496 — The Ristretto255 and Decaf448 Groups.
- FIPS 202 — SHA-3 Standard (Keccak).
- IRTF CFRG draft — `draft-irtf-cfrg-bls-signature` (BLS Signatures, "minimal-signature-size" / "minimal-pubkey-size" variants).

**Academic.**
- Boneh, Franklin. "Identity-Based Encryption from the Weil Pairing." CRYPTO 2001. <https://crypto.stanford.edu/~dabo/papers/bfibe.pdf>
- Boneh, Lynn, Shacham. "Short Signatures from the Weil Pairing." ASIACRYPT 2001.
- Fujisaki, Okamoto. "Secure Integration of Asymmetric and Symmetric Encryption Schemes." CRYPTO 1999.
- Shamir. "How to Share a Secret." Commun. ACM 22(11), 1979.
- Pedersen. "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing." CRYPTO 1991.
- Schnorr. "Efficient Signature Generation by Smart Cards." J. Cryptology 4(3), 1991.
- Chaum, Pedersen. "Wallet Databases with Observers." CRYPTO 1992.
- Camenisch, Stadler. "Proof Systems for General Statements about Discrete Logarithms." ETH technical report 260, 1997.
- Herzberg, Jakobsson, Jarecki, Krawczyk, Yung. "Proactive Secret Sharing or: How to Cope with Perpetual Leakage." CRYPTO 1995.
- Gennaro, Jarecki, Krawczyk, Rabin. "Secure Distributed Key Generation for Discrete-Log Based Cryptosystems." EUROCRYPT 1999.
- Desmedt, Jajodia. "Redistributing Secret Shares to New Access Structures and Its Applications." ISSE-TR-97-01, 1997.
- Das, Xiang, Tomescu, Spiegelman, Pinkas, Ren. "Verifiable Secret Sharing Simplified." IACR ePrint 2023/1196. <https://eprint.iacr.org/2023/1196>
- Goldwasser, Micali. "Probabilistic Encryption." J. Comput. Syst. Sci. 28(2), 1984 — the IND-CPA simulation/hybrid technique.

**Other.**
- Tomescu, Alin. "How to reshare a secret." 2024. <https://alinush.github.io/2024/04/26/How-to-reshare-a-secret.html>
