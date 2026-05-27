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

Each property below follows from the corresponding per-VSS property ([`vss.md`](./vss.md) §2) composed by the linear summation that defines $\mathsf{masterPk}$ and $s_j$. Properties 1–4 assume **static corruption** (adversary commits to the corruption set $J$ with $|J| \leq t$ before the protocol starts); property 5 is a structural bias gap; adaptive corruption is treated separately at the end.

**1. Correctness.** All honest parties output the same $\mathsf{masterPk}$ and contributing set $Q$, and the shares interpolate to $\log_g \mathsf{masterPk}$ via a unique degree-$t$ polynomial $F$ with $F(0) = \mathsf{MSK}$ and $F(j+1) = s_j$.

*Sketch.* By §1, all honest parties read the same $Q$ from the broadcast channel, hence agree on $\mathsf{masterPk}$. Per-VSS binding pins each dealer's polynomial $g_i$ uniquely; the sum $F = \sum_{i \in Q} g_i$ inherits degree $t$ and the desired evaluations.

**2. Completeness.** Up to $t$ malicious dealers cannot prevent honest parties from producing a consistent output.

*Sketch.* Per-VSS completeness gives each honest dealer's session $O(\Delta)$ termination. With $\geq n - t \geq t + 1$ honest dealers, $|Q|$ reaches the threshold from honest VSSs alone.

**3. Termination.** All honest parties terminate within $O(\Delta)$.

*Sketch.* Per-VSS termination plus the deterministic composition step in §1.

**4. Secrecy.** The adversary's view is computationally simulatable from $(\mathsf{masterPk}, \{s_j : j \in J\})$. Reduces to DLog and PKE IND-CPA.

*Sketch.* The DKG-level simulator takes $\mathsf{masterPk}$ and corrupted shares as input, then assigns each honest dealer a target $g^{a_0^{(i)}}$ so that the product over $Q$ equals $\mathsf{masterPk}$; it similarly assigns target evaluations to corrupted recipients. Each per-VSS simulator (see [`vss.md`](./vss.md) §2) is invoked with its assigned target. The composition is sound because, in the real protocol, the joint distribution of honest dealers' contributions conditional on $(\mathsf{masterPk}, \{s_j\}_{j \in J})$ is uniform over the affine subspace the simulator samples from. Loss factor at most $n^2$ times the per-VSS advantage.

**5. Bounded bias on $\mathsf{masterPk}$.** $\mathsf{masterPk}$'s distribution is **not** uniform over $\mathbb{G}$: a rushing adversary controlling $k \leq t$ dealers can restrict the output to one of $\leq 2^k$ candidate values of its choosing — **at most $t$ bits of entropy loss**.

*Sketch.* §1 fixes $Q$ in a single agreement step with no prior commitment binding dealers. For each controlled dealer, the adversary can adaptively decide — after observing honest dealers' $v_0$ values — whether to push that VSS to qualify in time to enter $Q$. This yields $2^k$ attainable values of $\mathsf{masterPk}$, from which the adversary picks the most favourable. The standard mitigation (GJKR'99 commit-then-open) eliminates the bias at the cost of an extra round; ACE does not implement it. For typical $t \in \{2, 3\}$ deployments, $\leq 3$ bits of entropy loss is not exploitable on $\sim 256$-bit DLog-hard $\log_g \mathsf{masterPk}$.

### Adaptive corruption: not proved

If the adversary may **adaptively** choose which nodes to corrupt during the protocol (rather than committing to $J$ upfront), the secrecy reduction in item 4 breaks. Concretely: the per-VSS simulator encrypts dummy `0` to honest holders; if the adversary later corrupts such a holder $i$ and learns $\mathsf{dk}_i$, decrypting that ciphertext yields `0` instead of the share value $y_i$ that the real protocol would have produced, and the simulation is trivially distinguished.

Fixing this requires non-committing encryption, programmable-RO plus selective-erasure assumptions, or a different share-channel construction — none of which ACE implements. We deem this acceptable because the operational threat (compromising an operator-run node *during* the $O(\Delta)$ sharing window of a fresh DKG/DKR) is strictly stronger than the static-corruption model already covered.

**References.** Pedersen'91 (original DKG, bias attack later identified); Gennaro–Jarecki–Krawczyk–Rabin '99 (commit-then-open mitigation; first adaptive-secure DKG techniques); Gennaro et al. '07 (analysis of biased Pedersen-DKG under threshold applications); Canetti et al. '99 (canonical non-committing-encryption-based adaptive fix).
