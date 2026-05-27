# Verifiable Secret Sharing (VSS)

ACE uses a Feldman-style polynomial commitment scheme (PCS) over an abstract `group::Element` (BLS12-381 $\mathbb{G}_1$ or $\mathbb{G}_2$). The core building block is a single dealer-driven VSS session; [`dkg.md`](./dkg.md) composes $n$ VSS sessions in parallel, [`dkr.md`](./dkr.md) composes them with a resharing-dealer challenge.

Throughout this file we write the group multiplicatively: $g$ denotes the session base point (`public_base_element` on chain), $g^x$ denotes scalar exponentiation, and $\mathbb{F}_r$ is the scalar field of BLS12-381.

## 1. Construction

ACE's VSS is the **synchronous VSS** of Algorithm 1, §5 in:

> Sourav Das, Zhuolun Xiang, Alin Tomescu, Alexander Spiegelman, Benny Pinkas, Ling Ren. **"Verifiable Secret Sharing Simplified."** IACR ePrint 2023/1196. <https://eprint.iacr.org/2023/1196>

The paper presents a publicly-verifiable, complete, $t$-resilient VSS for $n \geq 2t + 1$ synchronous nodes assuming a polynomial commitment scheme `PC`, signatures, and a Byzantine broadcast channel. ACE preserves the protocol skeleton — single-round dealer share-out, ACK collection, second-round reveal of unacked shares — and inherits the paper's correctness, completeness, and termination properties. Secrecy needs a fresh argument tailored to ACE's PCS choice; see §2 below.

### 1.1 Implementation choices

Where the paper's protocol uses abstract primitives, ACE pins concrete ones. Auditors should re-check the security argument against each:

1. **Polynomial commitment scheme = Feldman.** The paper's `PC` is generic; its formal hiding requirement (§4.2 of the paper) is satisfied by the Pedersen-style PCS in their Appendix A.2 ($v_k = g^{a_k} h^{r_k}$). ACE pins `PC` to **Feldman commitments over BLS12-381 $\mathbb{G}_1$ or $\mathbb{G}_2$**: given a polynomial $f(x) = a_0 + a_1 x + \cdots + a_{t-1} x^{t-1}$ over $\mathbb{F}_r$, the dealer publishes

    $$v_k = g^{a_k} \in \mathbb{G}, \qquad k = 0, 1, \dots, t-1,$$

    where $g$ is the session's `public_base_element` (no $h$-blinding). Verifying a share $y_i = f(i+1)$ against the commitment amounts to checking $g^{y_i} = \prod_{k=0}^{t-1} v_k^{(i+1)^k}$ (a multi-scalar multiplication on-chain; implemented in `worker-components/vss-common/src/vss_types.rs::feldman_verify` and `contracts/vss/sources/vss.move::touch`). Consequence: `PC.Open` is trivial — the share $y_i$ *is* the witness — and the paper's `PC.BatchOpen` collapses to "publish the missing scalar shares directly".

    **Security argument: computational reduction, not hiding-based simulation.** Feldman is *not* a hiding commitment — $v_0 = g^s$ publicly determines $g^s$. So paper's information-theoretic Lemma 1 (App. C) does NOT carry over: paper's simulator uses the Pedersen blinding factor $r(\cdot)$ to "rebind" the commitment to any candidate secret, which has no Feldman analogue. ACE instead settles for a weaker, computational, reduction-style argument summarized in §2. The argument's game samples $s \in_R \mathbb{F}_r$ uniformly; auditors should verify that every VSS call site supplies a uniformly random secret (item 7 documents the two ACE derivations, both uniform).

    **Why Feldman, not Pedersen.** VSS ensures every node has a private key share. In ACE, we additionally want the public key shares to be publicly available, to facilitate two other ACE pieces:

    - In t-IBE decryption ([`t-ibe.md`](./t-ibe.md) §1), a client wants to verify a decryption key share $\sigma_i$ against the matching public key share $P_i$.
    - In the key resharing protocol, the $j$-th node in the old committee re-shares its key share $s_j$ using VSS, and the protocol needs $P_j$ to quickly detect and reject faulty dealers trying to share a different secret.

    With Feldman PCS, all of this is easy:

    - If the polynomial commitment is $(v_0, \dots, v_{t-1})$, the public key share for the node at evaluation point $x$ is simply $\prod_{k=0}^{t-1} v_k^{x^k}$.
    - The t-IBE decryption-key-share verification is a single pairing equation $e(\sigma_i,g)=e(Q_\text{id},P_i)$.
    - For key resharing, if the old key share $s_j$ has the public commitment $P_j = g^{s_j}$ and the new VSS session uses the same base point $g$ with polynomial commitment $(v_0, \dots, v_{t-1})$, then anyone can confirm secret consistency by checking $v_0 = g^{s_j}$ on chain.

    The paper's Pedersen variant can still be made to support all this, but the constructions are a lot more complicated.

2. **Private authenticated channel = PKE.** The paper assumes private authenticated channels between dealer and each node. ACE realizes this by **PKE-encrypting each share to the recipient's registered `pke_enc_key`**, with the resulting ciphertext riding the public broadcast channel. Confidentiality reduces to PKE security ([`pke.md`](./pke.md)). The auth side is provided by the chain layer: the share ciphertext is bound to the dealer's account by virtue of the `on_dealer_contribution_0` signed transaction.

3. **Byzantine broadcast channel = the L1 chain.** Total ordering, immutability, and authentication of the transcript come from the Aptos L1 (Aptos's BFT consensus replaces the abstract `BB` channel). Trust assumption shifts from "broadcast channel exists" to "Aptos validator quorum is honest". Documented in [`../trust-model.md`](../trust-model.md) §5.

4. **Signed `ACK` = on-chain transaction.** The paper has nodes send $\langle \mathsf{ACK}, \sigma_i \rangle$ over the broadcast channel, where $\sigma_i = \mathsf{sign}(\mathsf{sk}_i, v)$. ACE has them call `on_share_holder_ack(session_addr)` on-chain; the Aptos transaction signature *is* $\sigma_i$, and the chain naturally rejects $(t)$ ACKs from any node that already ACKed. The authenticated-tally property the paper needs is provided by the L1.

5. **Selective reveal of missing shares.** The paper's second round does $(s, \pi) := \mathsf{PC.BatchOpen}(p, I, w)$ and broadcasts $(v, I, \sigma, s, \pi)$. ACE's equivalent reveals only the scalar shares of non-ackers as a vector of optional scalars (one slot per holder; `None` if they acked, `Some(y_j)` otherwise). Because the Feldman share $y_j$ is its own witness (item 1 — no separate opening proof $\pi$ is needed), the second-round message carries the scalar share alone; the verifier (an on-chain incremental computation) re-runs the Feldman MSM check $g^{y_j} = \prod_k v_k^{(j+1)^k}$ on each revealed share.

6. **Resharing-dealer challenge.** ACE adds an *optional* challenge: a pre-published target $P = g_\text{old}^{s_j}$ from the parent DKG/DKR, against which the on-chain handler checks $v_0 \stackrel{?}{=} P$. This pins the dealer's polynomial constant term $a_0$ to the previously-known share $s_j$. Used by Distributed Key Resharing (see [`dkr.md`](./dkr.md)) to prevent a dealer from substituting a fresh secret. **This is outside the paper's scope.**

## 2. Modified security argument

Replacing Pedersen with Feldman (§1.1 item 1) breaks the paper's secrecy proof: paper's Lemma 1 uses the Pedersen blinding $r(\cdot)$ to absorb arbitrary secret choices into the commitment in a perfect-indistinguishability simulation, and Feldman has no $r(\cdot)$ to absorb anything. Information-theoretic secrecy is therefore no longer achievable for ACE's VSS.

In its place we get a weaker, **computational, one-wayness** guarantee, which reduces to the hardness of the discrete-logarithm problem.
