# ACE Specification Documents

Audit-oriented technical specifications. These docs are versioned with the code; changes to the protocol or wire formats must update the relevant doc in the same PR.

| Document | Audience | Covers |
|----------|----------|--------|
| [`glossary.md`](./glossary.md) | All readers | Shared definitions of identifiers, roles, cryptographic objects, sub-protocol acronyms, parameters. **Hit an undefined term in any doc? Look here first.** |
| [`crypto-spec.md`](./crypto-spec.md) | Cryptographic auditor | Primitives (PKE, t-IBE, sigma-dlog-eq, KDF, HMAC), parameters, DSTs, security assumptions |
| [`trust-model.md`](./trust-model.md) | Protocol auditor / security reviewer | Actors, threat model, what each adversary class can/cannot do, non-goals |
| [`protocols.md`](./protocols.md) | Protocol auditor / implementer | On-chain state machines (VSS, DKG, DKR, voting, epoch_change, network), end-to-end decryption-request flow |
| [`wire-formats.md`](./wire-formats.md) | Auditor + cross-implementation reviewer | Byte-level BCS layouts for every type that crosses a chain or network boundary |

**Reading order for a fresh auditor:** trust-model → crypto-spec → protocols → wire-formats. Each doc cross-references the others where relevant.

**Source of truth.** When a doc and the code disagree, the code is authoritative; please file an issue. Citations in the docs are `path:line` against this commit.

## Out of scope (for the docs)

- App-developer tutorials → see top-level [`README.md`](../README.md) and [`examples/`](../examples/).
- Operator runbooks → see [`README.md`](../README.md) "Operator Guide" section and `operator-cli/`.
- API references → see `ts-sdk/src/` JSDoc comments and `cargo doc` for the worker crates.
