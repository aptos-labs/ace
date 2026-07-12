# Distributed Key Generation (DKG)

DKG composes \(n\) parallel VSS sessions, one per committee member acting as dealer, into a single joint secret. Each VSS uses Pedersen commitments and off-chain share delivery; see [`vss.md`](./vss.md).

This document uses additive notation. \((G,H)\) is the DKG PCS context and \(\mathsf{MSK}\) is the scalar master secret.

## 1. Construction

Each worker \(k\) starts one VSS with a degree-\((t-1)\) sharing polynomial:

\[
p_k(X) = a_{k,0} + a_{k,1}X + \cdots + a_{k,t-1}X^{t-1}.
\]

Each dealer also samples a blinding polynomial:

\[
r_k(X) = b_{k,0} + b_{k,1}X + \cdots + b_{k,t-1}X^{t-1}.
\]

ACE samples fresh dealer coefficients with OS randomness and persists them in
the VSS store before submitting DC0. DKR uses overrides only for the constant
terms that must carry forward the previous share opening.

The DKG contract waits until at least \(t\) VSS sessions complete and freezes that contributing set \(Q\). Once \(Q\) is fixed:

\[
\mathsf{MSK} = \sum_{k\in Q} a_{k,0},
\qquad
\mathsf{R}_0 = \sum_{k\in Q} b_{k,0}.
\]

The contract aggregates both the contributing VSS Pedersen commitment points
and public keys:

\[
C_i = \sum_{k\in Q} \left(p_k(i)G + r_k(i)H\right)
    = F(i)G + R(i)H
\qquad \text{for } i=0,\ldots,n,
\]

where:

\[
F(X)=\sum_{k\in Q}p_k(X),
\qquad
R(X)=\sum_{k\in Q}r_k(X).
\]

`commitment_points[0]` is \(C_0=\mathsf{MSK}G+\mathsf{R}_0H\). For holder
\(j\), `commitment_points[j+1]` is the aggregate share commitment.

In parallel:

\[
P_i = F(i)G = \sum_{k\in Q} p_k(i)G.
\]

`public_keys[0]` is the IBE master public key and `public_keys[j+1]` is the
public key for holder \(j\)'s aggregate scalar share.

The holder reconstructs both private shares off chain by summing its openings
from every contributing VSS:

\[
s_j = F(j+1)=\sum_{k\in Q}p_k(j+1),
\qquad
\rho_j = R(j+1)=\sum_{k\in Q}r_k(j+1).
\]

The pair \((s_j,\rho_j)\) is persisted in the VSS store. The scalar \(s_j\)
is consumed by application protocols; \(\rho_j\) is needed to prove consistency
with the aggregate Pedersen share commitment.

See [`../protocols.md`](../protocols.md) for the on-chain state machine, timeouts, and touch-driven aggregation.

## 2. Security Properties

The DKG properties are inherited from the per-VSS properties plus linear composition over the contributing set \(Q\). These statements assume static corruption with at most \(t-1\) corrupted committee members. Adaptive corruption is out of scope.

**Correctness.** Every successful VSS contributes well-defined degree-\((t-1)\) polynomials \(p_k,r_k\). Summing those polynomials over \(Q\) gives degree-\((t-1)\) joint polynomials:

\[
F(X)=\sum_{k\in Q}p_k(X),
\qquad
F(0)=\mathsf{MSK},
\qquad
F(j+1)=s_j,
\]

and similarly \(R(X)=\sum_{k\in Q}r_k(X)\). The published commitment points
are exactly:

\[
C_i=F(i)G+R(i)H.
\]

**Completeness and termination.** If at least \(t\) dealers complete their VSS sessions, the DKG can enter aggregation. Honest VSS sessions complete under synchrony and L1 liveness; the DKG's own aggregation work is deterministic and split across `touch()` calls.

**Secrecy.** Fewer than \(t\) corrupted holders learn fewer than \(t\) evaluations of the joint Shamir polynomial \(F\). Published scalar-derived public keys expose no scalar under the BLS12-381 discrete-log assumption. Off-chain shares must remain confidential in storage and transport.

**Commitment soundness.** The root commitment and every share commitment are sums of VSS commitment points that were accepted by the VSS state machines. A successful DKG therefore cannot publish an aggregate commitment inconsistent with the VSS commitment vectors, except by breaking the underlying VSS checks.

**Bounded bias on the generated secret.** The protocol still freezes \(Q\) after observing completed VSS sessions, without a prior commit-then-open round. A rushing adversary controlling \(k\leq t-1\) dealers can decide which of its own completed sessions enter \(Q\), giving it a small choice over the final secret commitment. The standard mitigation is a GJKR-style bias-avoidance round; ACE does not implement it.

## 3. References

- Shamir. "How to Share a Secret." Commun. ACM 22(11), 1979.
- Pedersen. "Non-Interactive and Information-Theoretic Secure Verifiable Secret Sharing." CRYPTO 1991.
- Gennaro, Jarecki, Krawczyk, Rabin. "Secure Distributed Key Generation for Discrete-Log Based Cryptosystems." EUROCRYPT 1999.
- Das, Xiang, Tomescu, Spiegelman, Pinkas, Ren. "Verifiable Secret Sharing Simplified." IACR ePrint 2023/1196.
