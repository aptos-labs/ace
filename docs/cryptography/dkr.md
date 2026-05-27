# Distributed Key Resharing (DKR)

DKR is a [proactive-secret-sharing](https://link.springer.com/chapter/10.1007/3-540-44750-4_27)-style **resharing** protocol that hands a master secret $s$ from an old committee $(C_{\text{old}}, t)$ to a new committee $(C_{\text{new}}, t')$ without $s$ ever existing in cleartext. The protocol consumes [`vss.md`](./vss.md) as a building block with the resharing-dealer challenge enabled (§2 below).

Notation: $g_{\text{old}}$ is the base point of the old committee's session, $g_{\text{new}}$ of the new. We write group operations multiplicatively, consistent with [`vss.md`](./vss.md).

## 1. Construction

Each old node $j$ runs a fresh VSS as dealer of degree $t'-1$, with $g_j(0) := s_j$ (their own old share, where $s_j = f(j+1)$ is the share of the underlying polynomial $f$), recipients = $C_{\text{new}}$. The resharing-dealer challenge (§2 below) forces $g_j(0) = s_j$. Once $\geq t$ such VSS reach the success state, the contributing set $H \subseteq C_{\text{old}}$ is frozen on-chain, and each new node $i \in C_{\text{new}}$ derives its new share via Lagrange-at-zero over the contributing old indices:

$$S_i := \sum_{j \in H} \lambda_j \cdot z_{j,i}, \qquad z_{j,i} = g_j(i+1), \qquad \lambda_j = \prod_{k \in H,\, k \neq j} \frac{0 - (k+1)}{(j+1) - (k+1)} \pmod r$$

The combined polynomial $F(x) := \sum_{j \in H} \lambda_j \cdot g_j(x)$ has degree $t' - 1$ and satisfies $F(0) = \sum_{j} \lambda_j s_j = f(0) = s$ (since the $\lambda_j$ Lagrange-interpolate $f$ at zero over $H$).

**References.**

- *Sourav Das, Zhuolun Xiang, Alin Tomescu, Alexander Spiegelman, Benny Pinkas, Ling Ren.* "Verifiable Secret Sharing Simplified." IACR ePrint 2023/1196 — provides the underlying VSS (Algorithm 1) used inside each per-old-dealer reshare.
- *Alin Tomescu*, ["How to reshare a secret"](https://alinush.github.io/2024/04/26/How-to-reshare-a-secret.html), 2024 — pedagogical overview of the exact construction ACE implements (Lagrange-at-zero combination of fresh VSS per old node).
- *Herzberg, Jakobsson, Jarecki, Krawczyk, Yung.* **"Proactive Secret Sharing or: How to Cope with Perpetual Leakage."** CRYPTO '95 — original PSS paper.
- *Desmedt, Jajodia.* **"Redistributing Secret Shares to New Access Structures and Its Applications."** Tech report ISSE-TR-97-01, 1997 — share-redistribution variant for distinct old/new committees.

## 2. Resharing-dealer challenge

A VSS session created as part of DKR carries a *resharing challenge*: the parent committee's pre-published share-PK $P_j = g_\text{old}^{s_j}$ is used as the binding target. The new VSS session is configured with base point $g_\text{old}$, and the on-chain handler verifies that the dealer's first Feldman commitment $v_0$ equals $P_j$ (a direct group equality). Combined with the Feldman polynomial-verification check during normal-or-dispute share opening, this forces the dealer's polynomial $g_j(\cdot)$ to satisfy $g_j(0) = s_j$ regardless of dealer behavior — a different secret would either fail this $v_0$ equality up front or fail Feldman verification during reveal.

## 3. Modifications relative to classical PSS / the blog construction

1. **Resharing-dealer binding.** A standard PSS dealer can quietly substitute their own fresh secret for $s_j$. ACE prevents this by requiring the dealer's first Feldman commitment $v_0 = g_\text{old}^{a_0}$ to equal the pre-published $P_j = g_\text{old}^{s_j}$ — verified on chain by a single group-equality check. Combined with Feldman verification of the polynomial during normal-or-dispute share opening, this forces $g_j(0) = s_j$ regardless of dealer behavior. This is the reason ACE's PCS is Feldman and not the paper's Pedersen instantiation — see [`vss.md`](./vss.md) §1.1 item 1: a hiding $v_0$ would obstruct this group equality.

2. **Agreement on contributing set $H$ = chain.** Naïvely, the new committee would need a Byzantine agreement protocol among themselves to agree on which $t$ VSS sessions to combine. ACE delegates this to the L1: the on-chain orchestrator deterministically reads each VSS's completion flag and freezes the contributing set the first time $|\{j : \mathsf{vss}_j\ \text{done}\}| \geq t$. Every observer reads the same $H$ from on-chain state. **New-node honesty does not provide agreement; the chain does.** Same pattern as VSS §1.1 item 3 in [`vss.md`](./vss.md).

3. **Lagrange coefficients computed on-chain.** Move computes $\{\lambda_j : j \in H\}$ once per session; new nodes don't compute their own. Saves cross-committee replay and ensures every party uses the same $\lambda_j$.

4. **No within-epoch share refresh.** Classical PSS refreshes shares periodically within an epoch to handle a mobile adversary. ACE refreshes only at epoch boundaries (`epoch_duration_micros` $\geq 30\text{s}$); within an epoch, shares are static.

## 4. Corruption model

Across the resharing transition window, the standard PSS analysis tolerates:

- $b_{\text{old}} < t$ corrupted nodes in the old committee, **and**
- $b_{\text{new}} < t'$ corrupted nodes in the new committee.

This is the **dual** of the user-friendly liveness phrasing (which says: at least $t$ honest in the old committee and at least $t'$ honest in the new). Note the inequality direction: secrecy needs $b_{\text{old}} \leq t - 1$, liveness needs $n - b_{\text{old}} \geq t$ (and analogously for new). The two coincide only when the corrupted and the offline-but-honest sets coincide (i.e., a malicious node acts by going silent).

**Effect of committee overlap.** ACE's typical deployment has heavy overlap: an epoch transition often rotates one or two nodes. With overlap:

- A node in the overlap that is corrupted contributes to **both** $b_{\text{old}}$ and $b_{\text{new}}$.
- The *abstract* secrecy bound is unchanged: still $b_\text{old} < t$ and $b_\text{new} < t'$.
- The *number of distinct physical nodes an adversary must corrupt* to reach both budgets is smaller. With overlap of size $k$, corrupting up to $\min(t - 1, t' - 1)$ overlap-nodes counts double — a $(t-1)$-bounded attacker on the old side automatically gets $t - 1$ corruptions on the new side too if every corruption is an overlap node.
- In the limit ($C_{\text{old}} = C_{\text{new}}$, full overlap, $t = t'$), the resharing protocol's secrecy collapses to the static secrecy of the underlying VSS in that committee: if you don't change the committee, fresh polynomial coefficients alone do not protect against an attacker who already corrupts $\geq t$ of those nodes.

This is the expected behavior for any PSS — the proactive benefit comes from changing the corrupted set, not from the polynomial refresh. The overlap level is a *deployment policy* choice: small overlap maximizes proactive benefit at the cost of operational continuity; large overlap maximizes continuity at the cost of attacker-cost reduction.

## 5. Liveness

DKR completes when:

- $\geq t$ honest-and-online old dealers submit a valid first-round message (whose $v_0$ passes the resharing-challenge group equality); the chain advances the contribution flags.
- For each of those VSS sessions, $\geq t'$ honest-and-online new ackers ACK within the 10-second window (or the dealer reveals the missing shares in the second round).

Heavy overlap also helps liveness: a single honest-and-online physical node serves both as old dealer and as new acker.

## 6. Audit notes

- $g_{\text{old}}^{s_j}$ is read from the previous session's on-chain share-PK list; auditors should confirm the read path cannot be poisoned by a malicious admin upgrading the predecessor module.
- A chain liveness halt during DKR stalls the epoch transition arbitrarily long — *liveness* concern, not *safety*.
- Heavy overlap is a deployment policy; the protocol does not enforce or reject it. A deployment that rotates $\geq 1$ node per epoch but is otherwise stable inherits the analysis above.
