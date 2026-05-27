# Distributed Key Generation (DKG)

DKG composes $n$ parallel VSS sessions ([`vss.md`](./vss.md)), one per committee member acting as dealer, into a single joint key. The output is the **master public key** $\mathsf{masterPk} = g^{\mathsf{MSK}}$ plus a Shamir share $s_i$ of $\mathsf{MSK}$ held by each member.

## 1. Construction

Every committee member runs one VSS as dealer with a freshly sampled uniform secret $a_0^{(\mathrm{dealer})} \in_R \mathbb{F}_r$. The protocol fixes a **qualifying set** $Q$ via a Byzantine-agreement step on "which VSSs have qualified": the first agreement point at which $|Q| \geq \mathsf{threshold}$ qualified VSSs are observed, $Q$ is frozen as that set. No prior commitment binds dealers to participate before observing others' contributions.

Once $Q$ is fixed:

- The joint master secret is $\mathsf{MSK} = \sum_{i \in Q} a_0^{(i)}$ (sum over qualifying dealers' constant terms).
- The master public key is $\mathsf{masterPk} = \prod_{i \in Q} v_0^{(i)} = g^{\mathsf{MSK}}$ (product of Feldman first commitments).
- Each recipient $j \in [n]$ holds $s_j = \sum_{i \in Q} g_i(j+1)$ — a Shamir share of $\mathsf{MSK}$ at evaluation point $j + 1$.
- The per-recipient public share key $\mathsf{sharePk}_j = \prod_{i \in Q} \mathsf{sharePks}_i[j] = g^{s_j}$ is also publicly derivable from the Feldman commitments.

See [`../protocols.md`](../protocols.md) for the on-chain state machine, error paths, and timeouts.

## 2. Security properties

ACE DKG inherits the standard Pedersen-DKG family security properties. Each follows from the corresponding per-VSS property (see [`vss.md`](./vss.md) §2) composed by the linear summation that defines $\mathsf{masterPk}$ and $s_j$.

Unless stated otherwise, properties below assume **static corruption**: $\mathcal{A}$ commits to a corruption set $J$ with $|J| \leq t$ before the protocol starts.

1. **Correctness.** All honest parties output the same $\mathsf{masterPk}$ and contributing set $Q$. There exists a unique degree- $t$ polynomial $F$ with $F(0) = \mathsf{MSK} = \log_g \mathsf{masterPk}$, and each honest node $j$'s share $s_j = F(j+1)$.

   *Sketch.* By §1, all honest parties read the same $Q$ and the same $\mathsf{masterPk} = \prod_{i \in Q} v_0^{(i)}$. Per-VSS binding (Feldman + DLog) pins each $i \in Q$ to a unique degree-$t$ polynomial $g_i$; $F := \sum_i g_i$ has degree $t$ with $F(0) = \log_g \mathsf{masterPk}$ and $F(j+1) = s_j$.

2. **Completeness.** Up to $t$ malicious dealers cannot prevent honest parties from outputting a consistent $(\mathsf{masterPk}, s_j)$.

   *Sketch.* Per-VSS completeness gives each honest dealer $O(\Delta)$ termination regardless of malicious recipients. With $\geq n - t \geq t + 1$ honest dealers contributing, $|Q|$ reaches threshold from honest VSSs alone.

3. **Termination.** All honest parties terminate within $O(\Delta)$.

   *Sketch.* Per-VSS termination plus §1's composition step (deterministic on already-public data) gives the same $O(\Delta)$ bound.

4. **Secrecy.** $\mathcal{A}$'s view is computationally simulatable from $(\mathsf{masterPk}, \{s_j : j \in J\})$. Reduces to DLog + PKE IND-CPA with multiplicative loss factor at most $n^2$.

   *Sketch.* Compose per-VSS simulators across $Q$. The DKG-level simulator receives $\mathsf{masterPk}$ and corrupted shares, then coordinates honest dealers' targets: pick $|Q \cap \text{honest}| - 1$ values of $g^{a_0^{(i)}}$ uniformly in $\mathbb{G}$ and force the last so the product equals $\mathsf{masterPk}$ divided by the (publicly-observable) corrupted contributions; similarly distribute each corrupted recipient's target share $s_j$ by sampling $|Q \cap \text{honest}| - 1$ honest contributions uniformly in $\mathbb{F}_r$ and forcing the last. Feed those targets to the per-VSS simulators. The conditional distribution matches the real protocol's (uniform subject to product / sum constraint), so composition is sound. Concrete bound:

   $$\mathsf{Adv}_{\text{DKG-Sec}}(\mathcal{A}) \leq n \cdot \mathsf{Adv}_{\text{DLog}} + n^2 \cdot \mathsf{Adv}_{\text{IND-CPA}}.$$

5. **Bounded bias on $\mathsf{masterPk}$.** $\mathsf{masterPk}$'s distribution is **NOT** uniform over $\mathbb{G}$: an adversary controlling $k \leq t$ dealers can restrict the protocol output to one of $\leq 2^k \leq 2^t$ candidate values of its choosing — **at most $t$ bits of entropy loss on $\log_g \mathsf{masterPk}$**.

   *Sketch.* §1 fixes $Q$ in a single agreement step with no prior commitment; for each of its $k$ controlled dealers, $\mathcal{A}$ can adaptively decide whether that VSS qualifies in time to enter $Q$, after observing honest dealers' $v_0$ values. This yields $2^k$ attainable subsets of $\mathcal{A}$'s VSSs in $Q$, each giving a different product $\mathsf{masterPk}$; $\mathcal{A}$ picks the most favourable.

   For ACE's typical $t \in \{2, 3\}$ this is $\leq 3$ bits of entropy loss on $\sim 256$-bit $\log_g \mathsf{masterPk}$ — not exploitable for $t$-IBE / threshold signing. The standard mitigation (GJKR'99 commit-then-open) reduces it to $0$ at the cost of an extra round.

### Adaptive corruption: not proved

If $\mathcal{A}$ may **adaptively** choose which nodes to corrupt during the protocol (rather than committing to $J$ upfront), the secrecy reduction (item 4) **breaks**. The concrete failure mode:

- The per-VSS simulator ([`vss.md`](./vss.md) §2) encrypts dummy `0` under honest holders' PKE keys to hide the real shares $y_i$.
- If $\mathcal{A}$ later corrupts a previously-honest holder $i$ and learns its $\mathsf{dk}_i$, it decrypts the dummy ciphertext and observes `0` instead of the share value $y_i$ that the real protocol would have produced. The simulation is trivially distinguishable; the reduction's advantage collapses to $\approx 1$.

Fixing this requires non-committing encryption, programmable-RO plus selective-erasure assumptions, or a fundamentally different share-channel construction — none of which ACE implements. We deem this acceptable because the operational threat (compromising an operator-run node *during* the $O(\Delta)$ sharing window of a fresh DKG/DKR) is strictly stronger than the static-corruption model already covered, and ACE's deployment doesn't see realistic mid-DKG compromise.

**References.** Pedersen'91 (original DKG, bias attack later identified); Gennaro–Jarecki–Krawczyk–Rabin '99 (commit-then-open mitigation; first adaptive-secure DKG techniques); Gennaro et al. '07 (analysis of biased Pedersen-DKG under threshold applications); Canetti et al. '99 "Adaptive Security for Threshold Cryptosystems" (canonical NCE-based adaptive fix).
