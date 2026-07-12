# ACE Cryptographic Specification

This folder is the cryptographic reference for ACE's current codebase: exact constructions, parameters, domain-separation tags, and security assumptions.

For higher-level protocol state machines, see [`../protocols.md`](../protocols.md). For byte layouts, see [`../wire-formats.md`](../wire-formats.md). For terms, see [`../glossary.md`](../glossary.md). For the trust model, see [`../trust-model.md`](../trust-model.md).

## Files

- [`pke.md`](./pke.md) — Public-key encryption for worker request/response encryption.
- [`sig.md`](./sig.md) — Ed25519 node-message signatures for off-chain worker-to-worker protocol messages.
- [`vss.md`](./vss.md) — Verifiable Secret Sharing with Pedersen polynomial commitments.
- [`dkg.md`](./dkg.md) — Distributed Key Generation as a composition of parallel VSS sessions.
- [`dkr.md`](./dkr.md) — Distributed Key Resharing for committee transitions.
- [`t-ibe.md`](./t-ibe.md) — Threshold Boneh-Franklin IBE and IDK-share verification.
- [`symmetric.md`](./symmetric.md) — Custom symmetric helpers still used by legacy/test-only PKE code.

## Notation

- $\mathbb{F}_r$ — scalar field of BLS12-381.
- $\mathbb{G}_1$, $\mathbb{G}_2$ — BLS12-381 pairing groups.
- $e(\cdot,\cdot)$ — BLS12-381 optimal Ate pairing.
- $G,H$ — Pedersen commitment generators for a PCS context.
- $p(x), r(x)$ — secret and blinding polynomials in VSS.
- $\mathsf{BCS}(\cdot)$ — Aptos Binary Canonical Serialization.

Group/scheme tags used throughout:

- `group::SCHEME_BLS12381G1 = 0x00`
- `group::SCHEME_BLS12381G2 = 0x01`

## Randomness

- TS SDK uses WebCrypto or Node crypto for client-side ephemeral keys.
- Rust workers use `rand::rngs::OsRng` where fresh randomness is needed.
- Aptos on-chain randomness samples DKG PCS contexts where the Move protocol requests it.
- VSS dealer polynomial state and holder shares are persisted off-chain by the VSS store path; current protocol code no longer publishes encrypted share payloads on-chain as the durable source of private shares.

## Out of Scope

- Post-quantum PKE or signatures.
- Permissionless operator admission, staking, rewards, or slashing.
- Formal adaptive-security proofs for VSS/DKG/DKR.
