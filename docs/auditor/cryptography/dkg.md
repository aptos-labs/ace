# Distributed Key Generation (DKG)

DKG composes \(n\) parallel VSS sessions, one per committee member acting as dealer, into a single joint key. Each VSS now uses Pedersen commitments and publishes public key shares via DC1 sigma proofs or revealed openings; see [`vss.md`](./vss.md).

This document uses additive notation. \(B\) is the DKG public base element and \(\mathsf{MSK}\) is the scalar master secret.

## 1. Construction

Each worker \(k\) starts one VSS with a degree-\((t-1)\) sharing polynomial:

\[
p_k(X) = a_{k,0} + a_{k,1}X + \cdots + a_{k,t-1}X^{t-1}.
\]

ACE derives dealer coefficients from the dealer's PKE decryption key, with optional override only for resharing. For fresh DKG, \(a_{k,0}\) is uniform if the PKE secret key is uniform.

The DKG contract waits until at least \(t\) VSS sessions complete and freezes that contributing set \(Q\). Once \(Q\) is fixed:

\[
\mathsf{MSK} = \sum_{k\in Q} a_{k,0},
\qquad
\mathsf{masterPk} = \sum_{k\in Q} a_{k,0}B.
\]

The contract computes \(\mathsf{masterPk}\) by summing `vss::result_pk()` from the contributing VSS sessions. It computes each holder's public share key by summing the corresponding VSS share public keys:

\[
s_j = \sum_{k\in Q} p_k(j+1),
\qquad
P_j = s_jB = \sum_{k\in Q} p_k(j+1)B.
\]

The scalar share \(s_j\) is reconstructed off chain by holder \(j\), who decrypts its private opening from every contributing VSS and sums the \(p_k(j+1)\) values. The blinding values \(r_k(j+1)\) are used only to verify openings; they do not enter the DKG share.

See [`../protocols.md`](../protocols.md) for the on-chain state machine, timeouts, and touch-driven aggregation.

## 2. Security Properties

The DKG properties are inherited from the per-VSS properties plus linear composition over the contributing set \(Q\). These statements assume static corruption with at most \(t-1\) corrupted committee members. Adaptive corruption is out of scope.

**Correctness.** Every successful VSS contributes a well-defined degree-\((t-1)\) polynomial \(p_k\) and public keys \(p_k(i)B\) for \(i=0,\ldots,n\). Summing those polynomials over \(Q\) gives a degree-\((t-1)\) joint polynomial:

\[
F(X)=\sum_{k\in Q}p_k(X),
\qquad
F(0)=\mathsf{MSK},
\qquad
F(j+1)=s_j.
\]

The published \(\mathsf{masterPk}\) and share public keys are exactly \(F(0)B\) and \(F(j+1)B\).

**Completeness and termination.** If at least \(t\) dealers complete their VSS sessions, the DKG can enter aggregation. Honest VSS sessions complete under synchrony and L1 liveness; the DKG's own aggregation work is deterministic and split across `touch()` calls.

**Secrecy.** Fewer than \(t\) corrupted holders learn fewer than \(t\) evaluations of the joint Shamir polynomial \(F\). Pedersen commitments hide the VSS commitment vectors; PKE hides honest holders' openings; the public values \(\mathsf{masterPk}\) and \(P_j\) reveal only group encodings, so scalar secrecy additionally relies on DLog in the DKG base group.

**Public-key soundness.** The master public key and every share public key are sums of VSS public keys that were individually checked on chain, either from revealed Pedersen openings or from sigma linear-DLog proofs. A successful DKG therefore cannot publish a share public key inconsistent with the scalar share reconstructed from the same VSS messages, except by breaking the underlying VSS checks.

**Bounded bias on \(\mathsf{masterPk}\).** The protocol still freezes \(Q\) after observing completed VSS sessions, without a prior commit-then-open round. A rushing adversary controlling \(k\leq t-1\) dealers can decide which of its own completed sessions enter \(Q\), giving it a small choice over the final public key. The standard mitigation is a GJKR-style bias-avoidance round; ACE does not implement it.

## 3. References

- Shamir. "How to Share a Secret." Commun. ACM 22(11), 1979.
- Pedersen. "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing." CRYPTO 1991.
- Gennaro, Jarecki, Krawczyk, Rabin. "Secure Distributed Key Generation for Discrete-Log Based Cryptosystems." EUROCRYPT 1999.
- Das, Xiang, Tomescu, Spiegelman, Pinkas, Ren. "Verifiable Secret Sharing Simplified." IACR ePrint 2023/1196.
