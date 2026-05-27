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

**1. Correctness.** All honest parties output the same $\mathsf{masterPk}$ and contributing set $Q$, and the shares interpolate to $\log_g \mathsf{masterPk}$ via a unique polynomial $F$ of degree $t$ with $F(0) = \mathsf{MSK}$ and $F(j+1) = s_j$. — Immediate from §1: $Q$ is broadcast, $\mathsf{masterPk}$ and $s_j$ are deterministic linear functions of public Feldman commitments, and per-VSS binding pins each $g_i$ uniquely.

**2. Completeness.** Up to $t$ malicious dealers cannot prevent honest parties from producing a consistent output. — Per-VSS completeness gives each honest dealer's session $O(\Delta)$ termination; with $\geq t+1$ honest dealers, $|Q|$ reaches threshold from honest VSSs alone.

**3. Termination.** All honest parties terminate within $O(\Delta)$. — Per-VSS termination plus the deterministic composition in §1.

**4. Secrecy.** The adversary's view is computationally simulatable from $(\mathsf{masterPk}, \{s_j : j \in J\})$. Reduces to DLog and PKE IND-CPA.

*Sketch.* The DKG-level simulator $\mathcal{S}$ must produce $\mathcal{A}$'s real-protocol view — chain transcript (Feldman commitments $v_k^{(i)}$ and ciphertexts), honest holders' ACKs, and the decryptable shares $\mathcal{A}$ extracts from ciphertexts addressed to corrupted holders. Two consistency constraints come from $\mathcal{S}$'s input:

- **(C1)** $\prod_{i \in Q} v_0^{(i)} = \mathsf{masterPk}$.
- **(C2)** For each $j \in J$, $\sum_{i \in Q} g_i(j+1) = s_j$.

$\mathcal{S}$ proceeds as follows. *(Notation: $J$ = corrupted parties, $H$ = honest dealers in $Q$, so $|H| = |Q| - |Q \cap J|$.)*

- **Reading off corrupted dealers.** For each $i \in Q \cap J$, $\mathcal{A}$ acts as dealer and publishes $(v_0^{(i)}, \dots, v_{t-1}^{(i)})$ on chain plus encrypted shares to every holder. $\mathcal{S}$ holds $\mathsf{dk}_j$ for honest $j \in [n] \setminus J$, decrypts those ciphertexts, and Lagrange-interpolates two of them to recover $g_i$ in full as a scalar polynomial. This lets $\mathcal{S}$ compute the corrupted dealers' contributions to both $\mathsf{masterPk}$ (in the exponent) and $s_j$ (in the scalar field).
- **Sampling $|H| - 1$ honest dealers freely.** Pick any $|H| - 1$ of the honest dealers and sample each one's polynomial $g_i \in_R \mathbb{F}_r[x]_{\deg \leq t-1}$ uniformly, just as the real protocol does. Compute their $v_k^{(i)}$ honestly.
- **Forcing the last honest dealer via Lagrange-in-exponent.** Call this dealer $i^\star$. Both constraints (C1) and (C2) now fully pin $i^\star$'s contributions:
  - From (C1): $v_0^{(i^\star)} = \mathsf{masterPk} / \prod_{i \in Q \setminus \{i^\star\}} v_0^{(i)}$ (computable group element; $\mathcal{S}$ does not know its discrete log).
  - From (C2), for each $j \in J$: $g_{i^\star}(j+1) = s_j - \sum_{i \in Q \setminus \{i^\star\}} g_i(j+1)$ (computable scalar).
  
  These are $1 + |J| \leq t$ fixed evaluations of a polynomial of degree $t-1$ — one group-side ($v_0^{(i^\star)}$ at $x=0$) and $|J|$ scalar-side ($g_{i^\star}(j+1)$ for $j \in J$). The remaining commitment coefficients $v_1^{(i^\star)}, \dots, v_{t-1}^{(i^\star)}$ are then determined by **Lagrange interpolation in the exponent** (see [`vss.md`](./vss.md) §2): $\mathcal{S}$ never learns $a_k^{(i^\star)}$ as scalars, but it can publish each $v_k^{(i^\star)}$ as a deterministic group expression in the fixed-point group elements above. For honest holders' shares $g_{i^\star}(j+1)$ ($j \notin J$), $\mathcal{S}$ doesn't need a scalar — only the ciphertext to those holders.
- **Encrypting honest-holder ciphertexts as dummies.** For any $(i, j)$ with $j \notin J$, the ciphertext $c_{i,j}$ on chain is $\mathsf{Enc}(\mathsf{ek}_j, 0)$. $\mathcal{A}$ doesn't hold $\mathsf{dk}_j$ and cannot decrypt.
- **Signing honest ACKs.** $\mathcal{S}$ holds $\mathsf{sk}_j$ for $j \notin J$ and signs the ACK message on $\mathcal{A}$'s behalf, matching what an honest holder would produce.

**Why it matches the real distribution.** Conditional on $(\mathsf{masterPk}, \{s_j\}_{j \in J}, \text{corrupted dealers' contributions})$, the real protocol's honest dealer polynomials are uniform over the affine subspace defined by (C1) and (C2). That subspace has dimension $|H| - 1$ in the coefficient space, with $|H| - 1$ free choices and one forced. $\mathcal{S}$ samples from exactly the same subspace by the construction above. The simulated and real views are then identical except for honest-holder ciphertexts (real share vs. dummy $0$), which $\mathcal{A}$ cannot tell apart by PKE IND-CPA — a hybrid over $\leq n$ honest holders, each VSS-level hybrid via [`vss.md`](./vss.md) §2's per-VSS argument, gives total advantage $\leq n^2 \cdot \mathsf{Adv}_{\text{IND-CPA}} + n \cdot \mathsf{Adv}_{\text{DLog}}$.

**5. Bounded bias on $\mathsf{masterPk}$.** $\mathsf{masterPk}$'s distribution is **not** uniform over $\mathbb{G}$: a rushing adversary controlling $k \leq t$ dealers can restrict the output to one of $\leq 2^k$ candidate values of its choosing — **at most $t$ bits of entropy loss**.

*Sketch.* §1 fixes $Q$ in a single agreement step with no prior commitment binding dealers. For each controlled dealer, the adversary can adaptively decide — after observing honest dealers' $v_0$ values — whether to push that VSS to qualify in time to enter $Q$. This yields $2^k$ attainable values of $\mathsf{masterPk}$, from which the adversary picks the most favourable. The standard mitigation (GJKR'99 commit-then-open) eliminates the bias at the cost of an extra round; ACE does not implement it. For typical $t \in \{2, 3\}$ deployments, $\leq 3$ bits of entropy loss is not exploitable on $\sim 256$-bit DLog-hard $\log_g \mathsf{masterPk}$.

### Adaptive corruption: not proved

If the adversary may **adaptively** choose which nodes to corrupt during the protocol (rather than committing to $J$ upfront), the secrecy reduction in item 4 breaks. Concretely: the per-VSS simulator encrypts dummy `0` to honest holders; if the adversary later corrupts such a holder $i$ and learns $\mathsf{dk}_i$, decrypting that ciphertext yields `0` instead of the share value $y_i$ that the real protocol would have produced, and the simulation is trivially distinguished.

Fixing this requires non-committing encryption, programmable-RO plus selective-erasure assumptions, or a different share-channel construction — none of which ACE implements. We deem this acceptable because the operational threat (compromising an operator-run node *during* the $O(\Delta)$ sharing window of a fresh DKG/DKR) is strictly stronger than the static-corruption model already covered.

**References.** Pedersen'91 (original DKG, bias attack later identified); Gennaro–Jarecki–Krawczyk–Rabin '99 (commit-then-open mitigation; first adaptive-secure DKG techniques); Gennaro et al. '07 (analysis of biased Pedersen-DKG under threshold applications); Canetti et al. '99 (canonical non-committing-encryption-based adaptive fix).
