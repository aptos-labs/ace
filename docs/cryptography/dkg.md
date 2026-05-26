# Distributed Key Generation (DKG)

DKG composes `n` parallel VSS sessions ([`vss.md`](./vss.md)), one per committee member acting as dealer, into a single joint key. The output is the **master public key** `master_pk = g^{MSK}` plus a Shamir share `s_i` of `MSK` held by each member.

## 1. Construction

Every committee member runs one VSS as dealer with a freshly sampled uniform secret `a_0^{(dealer)} ←$ Fr`. The on-chain orchestrator (`contracts/dkg/sources/dkg.move`) snapshots a **qualifying set** `Q` the first `touch()` at which `|Q| ≥ threshold` VSSs have reached the qualifying state (`dkg.move:135-140`). Once `Q` is frozen:

- The joint master secret is `MSK = Σ_{i ∈ Q} a_0^{(i)}` (sum over qualifying dealers' constant terms).
- The master public key is `master_pk = Σ_{i ∈ Q} v_0^{(i)} = g^{MSK}` (sum of Feldman first commitments).
- Each recipient `j ∈ [n]` holds `s_j = Σ_{i ∈ Q} g_i(j+1)` — a Shamir share of `MSK` at evaluation point `j+1`.
- `share_pk_j = Σ_{i ∈ Q} share_pks_i[j] = g^{s_j}` is published on-chain, computed in `dkg.move::touch` (`AGGREGATE_SHARE_PKS` state).

See [`../protocols.md`](../protocols.md) for the on-chain state machine, error paths, and timeouts.

## 2. Security (forthcoming Theorem 2)

A full DKG secrecy theorem composing [`vss.md`](./vss.md) Theorem 1 across `Q` is **not yet written down here**. The high-level shape will be:

- *Composition*: each per-VSS simulator is fed a target `g^{a_0^{(i)}}` derived from the DKG-level simulator's `master_pk` plus the corrupted dealers' publicly observable contributions. Honest dealers' `g^{a_0^{(i)}}` are coordinated so they sum to `master_pk` minus the corrupted contributions.
- *Bias rider*: `master_pk`'s distribution is NOT uniformly random across all of `G`; an adversary controlling up to `t` dealers can, by selectively completing or stalling its own VSSs, bias the `Q` snapshot. The achievable bias is bounded by `≤ 2^t` candidate `master_pk` values, i.e., ≤ `t` bits of entropy loss. Current ACE DKG does NOT include the GJKR'99-style commit-then-open round that would close this bias.

This is a known, bounded attack surface. Theorem 2 will state the bound explicitly when written.

**Reference.** Gennaro, Jarecki, Krawczyk, Rabin. "Secure Distributed Key Generation for Discrete-Log Based Cryptosystems." Eurocrypt 1999 — the classical bias-avoidance construction we are NOT applying.
