# ACE Specification Documents

Audit-oriented technical specifications. These docs are versioned with the code; changes to protocol state machines, cryptographic constructions, or wire formats must update the relevant doc in the same PR.

| Document | Audience | Covers |
|----------|----------|--------|
| [`glossary.md`](./glossary.md) | All readers | Shared identifiers, roles, cryptographic objects, and protocol acronyms |
| [`cryptography/`](./cryptography/) | Cryptographic auditor | PKE, signatures, VSS, DKG, DKR, symmetric helpers, and related assumptions |
| [`trust-model.md`](./trust-model.md) | Protocol auditor / security reviewer | Actors, threat model, trust boundaries, and non-goals |
| [`protocols.md`](./protocols.md) | Protocol auditor / implementer | VSS, DKG, DKR, epoch change, network state, and threshold VRF request flow |
| [`wire-formats.md`](./wire-formats.md) | Auditor + cross-implementation reviewer | BCS layouts for the active worker request and share formats |

Reading order for a fresh auditor: trust-model -> cryptography -> protocols -> wire-formats.

When a doc and the code disagree, the code is authoritative; please file an issue.

## Out of Scope

- App-developer tutorials -> see [`../developers/app-developer-guide/`](../developers/app-developer-guide/).
- Operator runbooks -> see [`../../README.md`](../../README.md) "Operator Guide" section and `cli/`.
- API references -> see `ts-sdk/src/` JSDoc comments and `cargo doc` for the worker crates.
