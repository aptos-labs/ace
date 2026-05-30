# Distributed Key Resharing (DKR)

DKR transfers an existing master secret from an old committee \((C_{\text{old}},t)\) to a new committee \((C_{\text{new}},t')\) without reconstructing the secret. It composes one resharing VSS per old-committee member, then combines the successful reshares with Lagrange coefficients at zero.

This document uses additive notation. \(B\) is the base element carried forward from the parent DKG/DKR session.

## 1. Construction

Let the old committee's sharing polynomial be \(f\), with old share:

\[
s_j = f(j+1)
\]

for old holder \(j\). The parent session has already published the old share public key:

\[
P_j = s_jB.
\]

Each old holder \(j\) starts a new VSS to the new committee with a fresh degree-\((t'-1)\) polynomial \(g_j\) satisfying:

\[
g_j(0)=s_j.
\]

Once at least \(t\) old holders' VSS sessions complete, the DKR freezes the contributing set \(H\subseteq C_{\text{old}}\) and computes Lagrange-at-zero coefficients over the old evaluation points:

\[
\lambda_j =
\prod_{k\in H,\,k\neq j}
\frac{0-(k+1)}{(j+1)-(k+1)}
\pmod r.
\]

Each new holder \(i\) receives the combined share:

\[
S_i = \sum_{j\in H}\lambda_j g_j(i+1).
\]

Equivalently, the new committee holds the degree-\((t'-1)\) polynomial:

\[
F(X)=\sum_{j\in H}\lambda_j g_j(X).
\]

Because \(g_j(0)=s_j=f(j+1)\), Lagrange interpolation gives:

\[
F(0)=\sum_{j\in H}\lambda_j s_j=f(0)=\mathsf{MSK}.
\]

The master public key is unchanged. The new share public keys are computed on chain as the same Lagrange combination of each contributing VSS's public keys:

\[
S_iB = \sum_{j\in H}\lambda_j\,g_j(i+1)B.
\]

## 2. Resharing-Dealer Binding

The old Feldman-era design tried to bind a reshare by checking a first commitment point directly against \(P_j\). With Pedersen commitments this direct equality is no longer meaningful, because:

\[
V_0 = g_j(0)G + r_j(0)H
\]

is hiding and should not equal \(g_j(0)B\).

ACE now binds the dealer with the VSS DC0 consistency proof. The child VSS stores `previous_public_key = P_j`; the dealer proves knowledge of \((g_j(0), r_j(0))\) such that:

\[
g_j(0)B = P_j,
\qquad
g_j(0)G + r_j(0)H = V_0.
\]

This is a sigma linear-DLog proof verified by `vss::on_dealer_contribution_0`. It proves the same scalar opens both the old share public key and the Pedersen commitment at position 0, while keeping the Pedersen blinding \(r_j(0)\) private.

## 3. Security Properties

These statements assume static corruption with \(b_{\text{old}}\leq t-1\) old nodes and \(b_{\text{new}}\leq t'-1\) new nodes. Adaptive corruption is out of scope.

**Correctness.** Each successful resharing VSS contributes a polynomial \(g_j\) with \(g_j(0)=s_j\), enforced by the DC0 consistency proof. The Lagrange combination over any \(H\) of size at least \(t\) therefore has constant term \(\mathsf{MSK}\), and the new share public keys match the scalar shares reconstructed from the VSS messages.

**Liveness.** Under synchrony and L1 liveness, honest old dealers complete their VSS sessions. Once \(t\) such sessions are complete, the rest of DKR is deterministic on-chain work split across `touch()` calls.

**Privacy.** DKR does not reveal the master secret. New holders learn only their new scalar shares; corrupted old holders already knew their old scalar shares. Pedersen commitments hide resharing commitment vectors, PKE hides honest recipients' openings, and public key shares reveal only group encodings under the DLog assumption.

**Resharing soundness.** A malicious old dealer cannot successfully reshare a fresh scalar in place of its old share. To complete DC0 it must prove \(g_j(0)B=P_j\), and \(P_j\) was inherited from the parent session's verified share public key list.

**Committee overlap.** If a physical node belongs to both old and new committees, one corruption counts against both budgets. Full overlap with no change in corrupted set gives no proactive benefit; the protection comes from changing which physical nodes are corrupted across epochs.

## 4. References

- Tomescu, Alin. "How to reshare a secret." 2024.
- Herzberg, Jakobsson, Jarecki, Krawczyk, Yung. "Proactive Secret Sharing or: How to Cope with Perpetual Leakage." CRYPTO 1995.
- Desmedt, Jajodia. "Redistributing Secret Shares to New Access Structures and Its Applications." ISSE-TR-97-01, 1997.
- Das, Xiang, Tomescu, Spiegelman, Pinkas, Ren. "Verifiable Secret Sharing Simplified." IACR ePrint 2023/1196.
