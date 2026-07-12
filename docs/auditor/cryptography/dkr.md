# Distributed Key Resharing (DKR)

DKR transfers an existing master secret from an old committee \((C_{\text{old}},t)\) to a new committee \((C_{\text{new}},t')\) without reconstructing the secret. It composes one resharing VSS per old-committee member, then combines the successful reshares with Lagrange coefficients at zero.

This document uses additive notation. \((G,H)\) is the PCS context carried forward from the parent DKG/DKR session.

## 1. Construction

Let the old committee's sharing polynomial be \(f\), with old share:

\[
s_j = f(j+1)
\]

for old holder \(j\). Let the old blinding polynomial be \(\rho(X)\), so the
old holder also has blinding share:

\[
\rho_j = \rho(j+1).
\]

The parent session has already published the old share commitment:

\[
C_j = s_jG+\rho_jH.
\]

Each old holder \(j\) starts a new VSS to the new committee with a fresh degree-\((t'-1)\) polynomial \(g_j\) satisfying:

\[
g_j(0)=s_j.
\]

It also uses a fresh degree-\((t'-1)\) blinding polynomial \(h_j\) satisfying:

\[
h_j(0)=\rho_j.
\]

Once at least \(t\) old holders' VSS sessions complete, the DKR freezes the contributing set \(Q\subseteq C_{\text{old}}\) and computes Lagrange-at-zero coefficients over the old evaluation points:

\[
\lambda_j =
\prod_{k\in Q,\,k\neq j}
\frac{0-(k+1)}{(j+1)-(k+1)}
\pmod r.
\]

Each new holder \(i\) receives the combined share:

\[
S_i = \sum_{j\in Q}\lambda_j g_j(i+1).
\]

and the combined blinding share:

\[
R_i = \sum_{j\in Q}\lambda_j h_j(i+1).
\]

Equivalently, the new committee holds the degree-\((t'-1)\) polynomial:

\[
F(X)=\sum_{j\in Q}\lambda_j g_j(X).
\]

The new blinding polynomial is:

\[
R(X)=\sum_{j\in Q}\lambda_j h_j(X).
\]

Because \(g_j(0)=s_j=f(j+1)\), Lagrange interpolation gives:

\[
F(0)=\sum_{j\in Q}\lambda_j s_j=f(0)=\mathsf{MSK}.
\]

The root Pedersen commitment remains unchanged because the same Lagrange
combination is applied to both secret and blinding openings:

\[
F(0)G+R(0)H
= \sum_{j\in Q}\lambda_j(s_jG+\rho_jH)
= \mathsf{MSK}G+\rho(0)H.
\]

The new share commitments are computed on chain as the same Lagrange combination
of each contributing VSS's commitment points:

\[
S_iG+R_iH
= \sum_{j\in Q}\lambda_j \left(g_j(i+1)G+h_j(i+1)H\right).
\]

DKR applies the same Lagrange combination to child-VSS public keys:

\[
P_i = S_iG = \sum_{j\in Q}\lambda_j g_j(i+1)G.
\]

It publishes the unchanged master public key at position zero and the new
committee's per-holder public keys at positions `1..n`.

## 2. Resharing-Dealer Binding

The legacy design tried to bind a reshare by checking a first commitment point
directly against an old scalar-derived public point. With Pedersen commitments
this direct equality is no longer meaningful, because:

\[
V_0 = g_j(0)G + h_j(0)H
\]

is hiding and should equal the old share commitment only when both the secret
and blinding openings are carried forward.

ACE now binds the dealer with the VSS DC0 consistency proof. The child VSS stores
`previous_commitment = (G,H,C_j)`. In the current same-context DKR case, the
dealer proves knowledge of the constant opening such that:

\[
g_j(0)G+h_j(0)H = C_j,
\qquad
g_j(0)G+h_j(0)H = V_0.
\]

More precisely, the previous commitment carries `(old_g, old_h, old_c)` and the
new session carries `(new_g, new_h, new_c)`. The sigma proof shows knowledge of
\((s,\rho,r_{\text{new}})\) with:

\[
sG_{\text{old}}+\rho H_{\text{old}}=C_{\text{old}},
\qquad
sG_{\text{new}}+r_{\text{new}}H_{\text{new}}=C_{\text{new}}.
\]

In current DKR, the old and new PCS contexts are the same original DKG context,
and the dealer sets \(r_{\text{new}}=\rho\) for the constant term. This keeps
the root commitment stable across reshares.

## 3. Security Properties

These statements assume static corruption with \(b_{\text{old}}\leq t-1\) old nodes and \(b_{\text{new}}\leq t'-1\) new nodes. Adaptive corruption is out of scope.

**Correctness.** Each successful resharing VSS contributes polynomials \(g_j,h_j\) whose constant opening matches the old share commitment, enforced by the DC0 consistency proof. The Lagrange combination over any \(Q\) of size at least \(t\) therefore has constant term \(\mathsf{MSK}\), and the new share commitments match the scalar/blinding shares reconstructed from the VSS messages.

**Liveness.** Under synchrony and L1 liveness, honest old dealers complete their VSS sessions. Once \(t\) such sessions are complete, the rest of DKR is deterministic on-chain work split across `touch()` calls.

**Privacy.** DKR does not reveal the master secret. New holders learn only their new scalar/blinding shares; corrupted old holders already knew their old shares. Pedersen commitments hide resharing commitment vectors. Off-chain shares must remain confidential in storage and transport.

**Resharing soundness.** A malicious old dealer cannot successfully reshare a fresh scalar in place of its old share. To complete DC0 it must prove that the new VSS constant opens the old Pedersen share commitment inherited from the parent session.

**Committee overlap.** If a physical node belongs to both old and new committees, one corruption counts against both budgets. Full overlap with no change in corrupted set gives no proactive benefit; the protection comes from changing which physical nodes are corrupted across epochs.

## 4. References

- Tomescu, Alin. "How to reshare a secret." 2024.
- Herzberg, Jakobsson, Jarecki, Krawczyk, Yung. "Proactive Secret Sharing or: How to Cope with Perpetual Leakage." CRYPTO 1995.
- Desmedt, Jajodia. "Redistributing Secret Shares to New Access Structures and Its Applications." ISSE-TR-97-01, 1997.
- Das, Xiang, Tomescu, Spiegelman, Pinkas, Ren. "Verifiable Secret Sharing Simplified." IACR ePrint 2023/1196.
