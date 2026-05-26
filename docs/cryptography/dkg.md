# Distributed Key Generation (DKG)

DKG composes $n$ parallel VSS sessions ([`vss.md`](./vss.md)), one per committee member acting as dealer, into a single joint key. The output is the **master public key** $\mathsf{master\_pk} = g^{\mathsf{MSK}}$ plus a Shamir share $s_i$ of $\mathsf{MSK}$ held by each member.

## 1. Construction

Every committee member runs one VSS as dealer with a freshly sampled uniform secret $a_0^{(\mathrm{dealer})} \in_R \mathbb{F}_r$. The on-chain orchestrator (`contracts/dkg/sources/dkg.move`) snapshots a **qualifying set** $Q$ at the first `touch()` for which $|Q| \geq \mathsf{threshold}$ VSSs have reached the qualifying state (`dkg.move:135-140`). Once $Q$ is frozen:

- The joint master secret is $\mathsf{MSK} = \sum_{i \in Q} a_0^{(i)}$ (sum over qualifying dealers' constant terms).
- The master public key is $\mathsf{master\_pk} = \prod_{i \in Q} v_0^{(i)} = g^{\mathsf{MSK}}$ (product of Feldman first commitments).
- Each recipient $j \in [n]$ holds $s_j = \sum_{i \in Q} g_i(j+1)$ — a Shamir share of $\mathsf{MSK}$ at evaluation point $j + 1$.
- $\mathsf{share\_pk}_j = \prod_{i \in Q} \mathsf{share\_pks}_i[j] = g^{s_j}$ is published on-chain, computed in `dkg.move::touch` (`AGGREGATE_SHARE_PKS` state).

See [`../protocols.md`](../protocols.md) for the on-chain state machine, error paths, and timeouts.

## 2. Security (forthcoming Theorem 2)

A full DKG secrecy theorem composing [`vss.md`](./vss.md) Theorem 1 across $Q$ is **not yet written down here**. The high-level shape will be:

- *Composition.* Each per-VSS simulator is fed a target $g^{a_0^{(i)}}$ derived from the DKG-level simulator's $\mathsf{master\_pk}$ plus the corrupted dealers' publicly observable contributions. Honest dealers' $g^{a_0^{(i)}}$ values are coordinated so they multiply to $\mathsf{master\_pk}$ divided by the corrupted contributions.
- *Bias rider.* $\mathsf{master\_pk}$'s distribution is NOT uniformly random across $\mathbb{G}$; an adversary controlling up to $t$ dealers can, by selectively completing or stalling its own VSSs, bias the $Q$ snapshot. The achievable bias is bounded by $\leq 2^t$ candidate $\mathsf{master\_pk}$ values, i.e., $\leq t$ bits of entropy loss. Current ACE DKG does NOT include the GJKR'99-style commit-then-open round that would close this bias.

This is a known, bounded attack surface. Theorem 2 will state the bound explicitly when written.

**Reference.** Gennaro, Jarecki, Krawczyk, Rabin. "Secure Distributed Key Generation for Discrete-Log Based Cryptosystems." Eurocrypt 1999 — the classical bias-avoidance construction we are NOT applying.
