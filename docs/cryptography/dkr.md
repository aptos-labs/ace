# Distributed Key Resharing (DKR)

DKR is a proactive-secret-sharing-style **resharing** protocol that hands a master secret $s$ from an old committee $(C_{\text{old}}, t)$ to a new committee $(C_{\text{new}}, t')$ without $s$ ever existing in cleartext. The protocol consumes [`vss.md`](./vss.md) as a building block, with the resharing-dealer challenge (§1.2 below) enabled. The exact construction ACE implements is described in Alin Tomescu's blog post ["How to reshare a secret"](https://alinush.github.io/2024/04/26/How-to-reshare-a-secret.html); academic provenance is in the references at the end of §1.

Notation: $g_{\text{old}}$ is the base point of the old committee's session, $g_{\text{new}}$ of the new. Group operations are written multiplicatively, consistent with [`vss.md`](./vss.md).

## 1. Construction

### 1.1 Resharing via Lagrange-at-zero

Each old node $j$ runs a fresh VSS as dealer of degree $t'-1$, with $g_j(0) := s_j$ (their own old share, where $s_j = f(j+1)$ is the share of the underlying polynomial $f$), recipients = $C_{\text{new}}$. The resharing-dealer challenge (§1.2) forces $g_j(0) = s_j$. Once $\geq t$ such VSS reach the success state, the contributing set $H \subseteq C_{\text{old}}$ is frozen on chain, and each new node $i \in C_{\text{new}}$ derives its new share via Lagrange-at-zero over the contributing old indices:

$$S_i := \sum_{j \in H} \lambda_j \cdot z_{j,i}, \qquad z_{j,i} = g_j(i+1), \qquad \lambda_j = \prod_{k \in H,\, k \neq j} \frac{0 - (k+1)}{(j+1) - (k+1)} \pmod r$$

The combined polynomial $F(x) := \sum_{j \in H} \lambda_j \cdot g_j(x)$ has degree $t' - 1$ and satisfies $F(0) = \sum_{j} \lambda_j s_j = f(0) = s$ (since the $\lambda_j$ Lagrange-interpolate $f$ at zero over $H$).

### 1.2 Resharing-dealer challenge

A VSS session created as part of DKR carries a *resharing challenge*: the parent committee's pre-published share-PK $P_j = g_\text{old}^{s_j}$ is used as the binding target. The new VSS session is configured with base point $g_\text{old}$, and the dealer's first Feldman commitment $v_0$ is required to equal $P_j$ (a direct group equality, verified on chain). Combined with the Feldman polynomial-verification check during normal-or-dispute share opening, this forces the dealer's polynomial $g_j(\cdot)$ to satisfy $g_j(0) = s_j$ regardless of dealer behavior — a different secret would either fail the $v_0$ equality up front or fail Feldman verification during reveal.

### 1.3 Modifications relative to classical PSS

1. **Resharing-dealer binding.** As above (§1.2). A standard PSS dealer can quietly substitute their own fresh secret for $s_j$; ACE prevents this by the $v_0 = P_j$ check. This is the reason ACE's PCS is Feldman and not the paper's Pedersen instantiation — see [`vss.md`](./vss.md) §1.1 item 1: a hiding $v_0$ would obstruct this group equality.

2. **Agreement on contributing set $H$ via the chain.** Naïvely, the new committee would need a Byzantine agreement protocol among themselves to agree on which $t$ VSS sessions to combine. ACE delegates this to the L1: every observer reads the same $H$ from on-chain state (frozen the first time $|\{j : \mathsf{vss}_j \text{ done}\}| \geq t$). **New-node honesty does not provide agreement; the chain does.** Same pattern as VSS §1.1 item 3 in [`vss.md`](./vss.md).

3. **Lagrange coefficients computed on chain.** $\{\lambda_j : j \in H\}$ is computed once per session and all parties use the same coefficients. Saves cross-committee replay and avoids divergent local Lagrange computations.

4. **No within-epoch share refresh.** Classical PSS refreshes shares periodically within an epoch to handle a mobile adversary. ACE refreshes only at epoch boundaries (`epoch_duration_micros` $\geq 30\text{s}$); within an epoch, shares are static.

**References.**

- *Sourav Das, Zhuolun Xiang, Alin Tomescu, Alexander Spiegelman, Benny Pinkas, Ling Ren.* "Verifiable Secret Sharing Simplified." IACR ePrint 2023/1196 — provides the underlying VSS (Algorithm 1) used inside each per-old-dealer reshare.
- *Alin Tomescu*, ["How to reshare a secret"](https://alinush.github.io/2024/04/26/How-to-reshare-a-secret.html), 2024 — pedagogical overview of the exact construction ACE implements (Lagrange-at-zero combination of fresh VSS per old node).
- *Herzberg, Jakobsson, Jarecki, Krawczyk, Yung.* **"Proactive Secret Sharing or: How to Cope with Perpetual Leakage."** CRYPTO '95 — original PSS paper.
- *Desmedt, Jajodia.* **"Redistributing Secret Shares to New Access Structures and Its Applications."** Tech report ISSE-TR-97-01, 1997 — share-redistribution variant for distinct old/new committees.

## 2. Security properties

DKR is the cross-committee (Desmedt-Jajodia) variant of the proactive refresh primitive defined in Cachin, Kursawe, Lysyanskaya, Strobl '02 (CKLS) — see references at the end of §1. We adopt CKLS's [§5.1 Definition 3](https://eprint.iacr.org/2002/134) property list directly, adapted to ACE's synchronous + L1-broadcast setting with Feldman PCS, plus one ACE-specific addition (resharing-dealer soundness, item 4).

Each property assumes static corruption with the PSS budget: $b_\text{old} \leq t - 1$ in the old committee and $b_\text{new} \leq t' - 1$ in the new.

**1. Liveness (= termination).** All honest new-committee nodes complete the refresh within $O(\Delta)$ under synchrony + L1 liveness. — Per-VSS termination for each contributing old dealer; on-chain $H$-freezing and Lagrange-coefficient computation add only finite deterministic computation.

**2. Correctness.** After at least $t'$ honest new-committee nodes complete the refresh, they hold a verifiable Shamir sharing of $s_0 = $ parent MSK — any $t'$ of them reconstruct $s_0$, and this is the same $s_0$ the parent committee was sharing. — Immediate from §1.1: $F(x) = \sum_{j \in H} \lambda_j g_j(x)$ has degree $t'-1$, $F(0) = \sum_j \lambda_j s_j = f(0) = s_0$, and each new node $i$'s share is $F(i+1)$. Per-VSS completeness gives $|H| \geq t$ honest old dealers contributing.

**3. Privacy.** Over any polynomial number of consecutive DKR executions, the adversary's view is computationally independent of $s_0$. (CKLS prove this unconditionally using Pedersen-AVSS; ACE's Feldman swap reduces the claim to DLog hardness — see [`vss.md`](./vss.md) §2.) In a single snapshot this collapses to: the adversary's view of one DKR transcript is computationally simulatable from $(\mathsf{masterPk}, \{s_j : j \in J_\text{old}\}, \{S_i : i \in J_\text{new}\})$ — what the parent committee already published plus the corrupted parties' own old and new shares.

*Sketch.* Compose per-VSS simulators ([`vss.md`](./vss.md) §2) across each old dealer's reshare-VSS. For each honest old dealer $j$, the per-VSS simulator gets $P_j = g_\text{old}^{s_j}$ (publicly known from the parent committee) as the target $v_0$, and the corrupted new-committee shares $\{g_j(i+1) : i \in J_\text{new}\}$ as constraints. The DKR-level simulator coordinates: each honest old dealer's share-to-corrupted-new is a Lagrange-determined function of $\{S_i : i \in J_\text{new}\}$ and the corrupted old dealers' contributions. The conditional distribution of honest contributions in the real protocol matches the simulator's by the same affine-subspace argument as in DKG ([`dkg.md`](./dkg.md) §2 item 4). Forward security across multiple consecutive refreshes follows because each refresh re-randomises the polynomial subject to fixed $s_0$, and the per-epoch corruption budget caps what the adversary learns in each epoch.

**4. Resharing-dealer soundness (ACE-specific).** A malicious old dealer cannot reshare a value other than its own old share $s_j$. — Forced by the on-chain $v_0 \stackrel{?}{=} P_j$ equality check described in §1.2. CKLS does not need this property because their refresh is intra-committee (the same physical server reshares its own share), but ACE's cross-committee transition means the new committee cannot directly check old shares, so the binding has to be made on-chain against the parent's pre-published $P_j$.

**Effect of committee overlap.** ACE's typical deployment has heavy overlap: an epoch transition often rotates only one or two nodes. The implications:

- A node in the overlap that is corrupted contributes to **both** $b_\text{old}$ and $b_\text{new}$, so a single physical corruption counts twice against the budget.
- The *abstract* secrecy bound is unchanged: $b_\text{old} < t$ and $b_\text{new} < t'$.
- The *number of distinct physical nodes an adversary must corrupt* to saturate both budgets is smaller. With overlap of size $k$, corrupting up to $\min(t-1, t'-1)$ overlap-nodes gives the attacker $t-1$ corruptions on both sides for free.
- In the limit ($C_\text{old} = C_\text{new}$, full overlap, $t = t'$), DKR's secrecy collapses to the *static* secrecy of the underlying VSS in that committee — refreshing the polynomial alone doesn't protect against an attacker who already corrupts $\geq t$ of those same nodes.

This is the expected behavior for any PSS — the proactive benefit comes from *changing the corrupted set*, not from the polynomial refresh. The overlap level is a deployment-policy choice: small overlap maximizes proactive benefit at the cost of operational continuity; large overlap maximizes continuity at the cost of attacker-cost reduction.

### Adaptive corruption: not proved

Same caveat as DKG ([`dkg.md`](./dkg.md) §2 "Adaptive corruption"): if the adversary may adaptively choose which nodes to corrupt during the protocol (rather than committing to $J_\text{old}, J_\text{new}$ upfront), the per-VSS secrecy reduction breaks because the simulator's dummy ciphertexts to honest holders become distinguishable once those holders are corrupted. The mitigation paths (non-committing encryption, programmable-RO plus erasures, alternative share-channel) are not implemented in ACE; the operational threat of mid-DKR node compromise is judged strictly stronger than static corruption, hence out of scope.

**Audit notes.**

- $g_\text{old}^{s_j}$ is read from the previous session's on-chain share-PK list; auditors should confirm the read path cannot be poisoned by a malicious admin upgrading the predecessor module.
- A chain liveness halt during DKR stalls the epoch transition arbitrarily long — a *liveness* concern, not a *safety* concern.
- Heavy overlap is a deployment policy; the protocol does not enforce or reject it. A deployment that rotates $\geq 1$ node per epoch but is otherwise stable inherits the analysis above.
