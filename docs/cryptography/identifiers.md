# Group/curve identifiers and RNG sources

## 1. Curve / group cheat sheet

| Curve / Group | Field | Element size (compressed) | Hash-to-curve suite |
|---------------|-------|--------------------------:|---------------------|
| BLS12-381 G1 | Fp (381b) | **48 B** | `BLS12381G1_XMD:SHA-256_SSWU_RO_` |
| BLS12-381 G2 | Fp² | **96 B** | `BLS12381G2_XMD:SHA-256_SSWU_RO_` |
| BLS12-381 Fr | scalar (252b) | 32 B (LE) | n/a |
| BLS12-381 Gt | Fp¹² | 576 B (custom canonicalization, see [`t-ibe.md`](./t-ibe.md) §2) | n/a |
| Ristretto255 | derived from Ed25519 (252b) | 32 B | n/a (rejection-sampled) |
| X25519 (Curve25519 Mont) | Fp (255b) | 32 B (raw clamp) | n/a |
| Ed25519 (verifying key) | Fp | 32 B | n/a — used only for ProofOfPermission |

`group::SCHEME_BLS12381G1 = 0x00`, `group::SCHEME_BLS12381G2 = 0x01`. Defined in `contracts/group/sources/group.move` and mirrored in `worker-components/vss-common/src/session.rs`.

## 2. Random number generation

| Component | RNG | Usage |
|-----------|-----|-------|
| TS SDK | WebCrypto `crypto.getRandomValues` (browser) / Node `crypto.randomBytes` | All ephemerals (`r` in PKE/IBE encrypt, ephemeral encryption keys) |
| Rust workers | `rand::rngs::OsRng` (`/dev/urandom` on Linux, `getrandom` syscall) | VSS dealer optional `secret_override`, HPKE keygen, Sigma-DLog-Eq proof randomness |
| Move (on-chain) | `aptos_framework::randomness` API | DKG basepoint sampling (e.g. `epoch_change::touch` uses `randomness::generate(...)` for new G2 base points) |

**Audit notes.**
- VSS dealer randomness is **derived from the dealer's PKE decryption key** (see [`vss.md`](./vss.md) §3), not freshly sampled. This is intentional and security-equivalent provided the PKE dk is itself uniformly random; the operator-CLI generates the dk via `WebCrypto` at onboarding and stores it in the provider-specific secret manager (Cloud Run Secret, etc.).
- Aptos's on-chain `randomness::generate` is itself a threshold protocol. Trust assumption: the Aptos validator quorum is honest. This is part of the "contract is truth" trust premise — see [`../trust-model.md`](../trust-model.md).
